// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type ControlPlane interface {
	RegisterDevice(context.Context, controlplane.RegisterDeviceRequest) (controlplane.RegisterDeviceResponse, error)
	GetConfig(context.Context, controlplane.ConfigRequest) (model.Config, error)
	AckConfig(context.Context, controlplane.ConfigAckRequest) (controlplane.ConfigAckResponse, error)
}

type SignedControlPlane interface {
	GetSigningKeys(context.Context, string) (controlplane.SigningKeysResponse, error)
	GetSignedConfig(context.Context, controlplane.SignedConfigRequest) (signedconfig.Config, error)
	AckSignedConfig(context.Context, controlplane.SignedConfigAckRequest) (controlplane.SignedConfigAckResponse, error)
}

type InviteControlPlane interface {
	ExchangeJoinToken(context.Context, controlplane.JoinTokenExchangeRequest) (controlplane.JoinTokenExchangeResponse, error)
	GetEnrollmentSignedConfig(context.Context, string, controlplane.SignedConfigRequest) (signedconfig.Config, error)
	AckEnrollmentSignedConfig(context.Context, string, controlplane.SignedConfigAckRequest) (controlplane.SignedConfigAckResponse, error)
}

type DeviceSessionControlPlane interface {
	MintDeviceSession(context.Context, credential.Record, controlplane.DeviceSessionRequest) (controlplane.DeviceSessionResponse, error)
}

type ConfigContract string

const (
	ConfigContractAuto   ConfigContract = "auto"
	ConfigContractSigned ConfigContract = "signed"
	ConfigContractLegacy ConfigContract = "legacy"
)

func ParseConfigContract(value string) (ConfigContract, error) {
	contract := ConfigContract(strings.ToLower(strings.TrimSpace(value)))
	switch contract {
	case ConfigContractAuto, ConfigContractSigned, ConfigContractLegacy:
		return contract, nil
	default:
		return "", fault.New(fault.CodeInvalidInput, "parse config contract", nil)
	}
}

type KeyGenerator func() (privateKey string, publicKey string, err error)

type Joiner struct {
	controlPlane  ControlPlane
	store         *state.Store
	credentials   credential.Store
	runtime       runtime.Interface
	now           func() time.Time
	generateKey   KeyGenerator
	generateNonce func() (string, error)
	contract      ConfigContract
}

type JoinRequest struct {
	Server     string
	DeviceID   string
	DeviceName string
	Platform   string
	Hostname   string
	NetworkID  string
	NodeID     string
	JoinToken  string
}

type JoinResult struct {
	DeviceID      string `json:"device_id"`
	NetworkID     string `json:"network_id"`
	Revision      string `json:"revision"`
	AlreadyJoined bool   `json:"already_joined"`
}

func NewJoiner(controlPlane ControlPlane, store *state.Store, tunnelRuntime runtime.Interface) *Joiner {
	return &Joiner{
		controlPlane:  controlPlane,
		store:         store,
		runtime:       tunnelRuntime,
		now:           time.Now,
		generateKey:   generateWireGuardKeyPair,
		generateNonce: generateUUIDv4,
		contract:      ConfigContractLegacy,
	}
}

func (j *Joiner) WithCredentialStore(store credential.Store) *Joiner {
	j.credentials = store
	return j
}

func (j *Joiner) WithConfigContract(contract ConfigContract) *Joiner {
	j.contract = contract
	return j
}

func (j *Joiner) WithClock(now func() time.Time) *Joiner {
	j.now = now
	return j
}

func (j *Joiner) WithKeyGenerator(generator KeyGenerator) *Joiner {
	j.generateKey = generator
	return j
}

func (j *Joiner) Join(ctx context.Context, request JoinRequest) (JoinResult, error) {
	request.Server = strings.TrimRight(strings.TrimSpace(request.Server), "/")
	request.DeviceID = strings.TrimSpace(request.DeviceID)
	if request.Server == "" || request.DeviceID == "" {
		return JoinResult{}, fault.New(fault.CodeInvalidInput, "join overlay", nil)
	}

	if lastKnown, err := j.store.LoadLastKnown(); err == nil {
		if lastKnown.Server == request.Server && lastKnown.DeviceID == request.DeviceID && lastKnown.Phase == state.PhaseAcknowledged {
			if requestedNetwork := strings.TrimSpace(request.NetworkID); requestedNetwork != "" && requestedNetwork != lastKnown.NetworkID {
				return JoinResult{}, fault.New(fault.CodeStateConflict, "join existing device", nil)
			}
			if requestedNode := strings.TrimSpace(request.NodeID); requestedNode != "" && requestedNode != lastKnown.NodeID {
				return JoinResult{}, fault.New(fault.CodeStateConflict, "join existing device", nil)
			}
			lastContract := ConfigContract(lastKnown.ConfigContract)
			if lastContract == "" {
				lastContract = ConfigContractLegacy
			}
			if lastContract == ConfigContractSigned && j.contract == ConfigContractLegacy {
				return JoinResult{}, fault.New(fault.CodeConfigDowngradeBlocked, "join signed device with legacy config", nil)
			}
			if lastContract == ConfigContractSigned || j.contract == ConfigContractLegacy {
				if lastContract == ConfigContractSigned {
					if err := j.store.ClearEnrollmentSecret(); err != nil {
						return JoinResult{}, err
					}
				}
				return j.recoverLastKnown(ctx, lastKnown)
			}
			if err := j.seedMigrationCheckpoint(lastKnown); err != nil {
				return JoinResult{}, err
			}
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return JoinResult{}, err
	}

	checkpoint, err := j.loadOrCreateCheckpoint(request)
	if err != nil {
		return JoinResult{}, err
	}
	if checkpoint.InviteEnrollment && j.credentials == nil {
		return JoinResult{}, fault.New(fault.CodeCredentialStorage, "use protected device credential storage", nil)
	}
	if checkpoint.ConfigContract == string(ConfigContractSigned) && j.contract == ConfigContractLegacy {
		return JoinResult{}, fault.New(fault.CodeConfigDowngradeBlocked, "resume signed config with legacy contract", nil)
	}
	if checkpoint.ConfigContract == string(ConfigContractLegacy) && j.contract == ConfigContractSigned && phaseAtLeast(checkpoint.Phase, state.PhaseConfigFetched) {
		return JoinResult{}, fault.New(fault.CodeStateConflict, "resume legacy config with signed contract", nil)
	}

	if !phaseAtLeast(checkpoint.Phase, state.PhaseDeviceRegistered) {
		if checkpoint.InviteEnrollment {
			enrollment, err := j.loadOrRenewEnrollment(ctx, &checkpoint, request.JoinToken)
			if err != nil {
				return JoinResult{}, err
			}
			if checkpoint.NetworkID != "" && checkpoint.NetworkID != enrollment.NetworkID {
				return JoinResult{}, fault.New(fault.CodeStateConflict, "validate invite network", nil)
			}
			checkpoint.NetworkID = enrollment.NetworkID
			checkpoint.ConfigContract = string(ConfigContractSigned)
			checkpoint.EnrollmentExpiresAt = enrollment.ExpiresAt
		} else {
			response, err := j.controlPlane.RegisterDevice(ctx, controlplane.RegisterDeviceRequest{
				DeviceID:           checkpoint.DeviceID,
				Name:               checkpoint.DeviceName,
				Platform:           checkpoint.Platform,
				Hostname:           checkpoint.Hostname,
				NetworkID:          checkpoint.NetworkID,
				WireGuardPublicKey: checkpoint.WireGuardPublicKey,
			})
			if err != nil {
				return JoinResult{}, err
			}
			if response.Device.ID == "" || response.Device.ID != checkpoint.DeviceID || response.Device.NetworkID == "" || response.Network.ID != response.Device.NetworkID {
				return JoinResult{}, fault.New(fault.CodeInvalidResponse, "register overlay device", nil)
			}
			checkpoint.NetworkID = response.Device.NetworkID
		}
		checkpoint.Phase = state.PhaseDeviceRegistered
		checkpoint.LastErrorCode = ""
		checkpoint.UpdatedAt = j.now().UTC()
		if err := j.store.SaveCheckpoint(checkpoint); err != nil {
			return JoinResult{}, err
		}
	}

	if !phaseAtLeast(checkpoint.Phase, state.PhaseConfigFetched) {
		fetched, err := j.fetchRuntimeConfig(ctx, &checkpoint, request.JoinToken)
		if err != nil {
			return JoinResult{}, err
		}
		config := fetched.Config
		if err := config.Validate(); err != nil {
			return JoinResult{}, err
		}
		if config.Device.ID != checkpoint.DeviceID || config.Device.NetworkID != checkpoint.NetworkID || config.Network.ID != checkpoint.NetworkID {
			return JoinResult{}, fault.New(fault.CodeInvalidConfig, "validate config ownership", nil)
		}
		checkpoint.Config = &config
		checkpoint.ConfigContract = string(fetched.Contract)
		checkpoint.SignedConfigID = fetched.SignedConfigID
		checkpoint.SignedGeneration = fetched.SignedGeneration
		checkpoint.Phase = state.PhaseConfigFetched
		checkpoint.LastErrorCode = ""
		checkpoint.UpdatedAt = j.now().UTC()
		if err := j.store.SaveCheckpoint(checkpoint); err != nil {
			return JoinResult{}, err
		}
	}

	if checkpoint.Config == nil {
		return JoinResult{}, fault.New(fault.CodeStateIO, "resume join", nil)
	}
	if !phaseAtLeast(checkpoint.Phase, state.PhaseRuntimeApplied) {
		applyResult, err := j.runtime.Apply(ctx, runtime.ApplyRequest{
			Config:              *checkpoint.Config,
			WireGuardPrivateKey: checkpoint.WireGuardPrivateKey,
		})
		if err == nil && (applyResult.Revision != checkpoint.Config.Revision || applyResult.CoreID != model.CoreIDXray || !model.SupportedAdapterID(applyResult.AdapterID)) {
			err = fault.New(fault.CodeRuntimeApplyFailed, "validate runtime apply result", nil)
		}
		if err != nil {
			code := runtimeApplyErrorCode(err)
			checkpoint.LastErrorCode = code
			checkpoint.UpdatedAt = j.now().UTC()
			_ = j.store.SaveCheckpoint(checkpoint)
			return JoinResult{}, fault.New(code, "apply runtime profile", err)
		}
		checkpoint.Phase = state.PhaseRuntimeApplied
		checkpoint.LastErrorCode = ""
		checkpoint.UpdatedAt = j.now().UTC()
		if err := j.store.SaveCheckpoint(checkpoint); err != nil {
			return JoinResult{}, err
		}
	}

	if !phaseAtLeast(checkpoint.Phase, state.PhaseAcknowledged) {
		if checkpoint.InviteEnrollment {
			enrollment, err := j.loadOrRenewEnrollment(ctx, &checkpoint, request.JoinToken)
			if err != nil {
				return JoinResult{}, err
			}
			inviteControlPlane, ok := j.controlPlane.(InviteControlPlane)
			if !ok {
				return JoinResult{}, fault.New(fault.CodeEnrollmentUnavailable, "ack enrollment signed config", nil)
			}
			ack, err := inviteControlPlane.AckEnrollmentSignedConfig(ctx, enrollment.EnrollmentToken, controlplane.SignedConfigAckRequest{
				Generation: checkpoint.SignedGeneration, ConfigID: checkpoint.SignedConfigID,
				DeviceID: checkpoint.DeviceID, AppliedAt: j.now().UTC(),
			})
			if err != nil {
				return JoinResult{}, j.handleEnrollmentError(err)
			}
			if !ack.Acked || ack.Ack.DeviceID != checkpoint.DeviceID || ack.Ack.ConfigID != checkpoint.SignedConfigID || ack.Ack.Generation != checkpoint.SignedGeneration {
				return JoinResult{}, fault.New(fault.CodeInvalidResponse, "acknowledge enrollment signed config", nil)
			}
			if exactSessionScope(enrollment.Scope) && j.credentials != nil {
				record, loadErr := j.credentials.Load(ctx)
				if loadErr != nil {
					return JoinResult{}, loadErr
				}
				record.SigningKeys = enrollment.SigningKeys
				if saveErr := j.credentials.Save(ctx, record); saveErr != nil {
					return JoinResult{}, fault.New(fault.CodeCredentialStorage, "commit verified signing keys", saveErr)
				}
			}
		} else if checkpoint.ConfigContract == string(ConfigContractSigned) {
			signedControlPlane, ok := j.controlPlane.(SignedControlPlane)
			if !ok {
				return JoinResult{}, fault.New(fault.CodeSignedConfigUnavailable, "ack signed config", nil)
			}
			ack, err := signedControlPlane.AckSignedConfig(ctx, controlplane.SignedConfigAckRequest{
				Generation: checkpoint.SignedGeneration,
				ConfigID:   checkpoint.SignedConfigID,
				DeviceID:   checkpoint.DeviceID,
				AppliedAt:  j.now().UTC(),
			})
			if err != nil {
				return JoinResult{}, err
			}
			if !ack.Acked || ack.Ack.DeviceID != checkpoint.DeviceID || ack.Ack.ConfigID != checkpoint.SignedConfigID || ack.Ack.Generation != checkpoint.SignedGeneration {
				return JoinResult{}, fault.New(fault.CodeInvalidResponse, "acknowledge signed config", nil)
			}
		} else {
			ack, err := j.controlPlane.AckConfig(ctx, controlplane.ConfigAckRequest{
				DeviceID: checkpoint.DeviceID, NetworkID: checkpoint.NetworkID,
				Revision: checkpoint.Config.Revision, Digest: checkpoint.Config.Digest, AppliedAt: j.now().UTC(),
			})
			if err != nil {
				return JoinResult{}, err
			}
			if !ack.Acked || ack.DeviceID != checkpoint.DeviceID || ack.NetworkID != checkpoint.NetworkID || ack.Revision != checkpoint.Config.Revision {
				return JoinResult{}, fault.New(fault.CodeInvalidResponse, "acknowledge legacy config", nil)
			}
		}
		checkpoint.Phase = state.PhaseAcknowledged
		checkpoint.UpdatedAt = j.now().UTC()
		if err := j.store.SaveCheckpoint(checkpoint); err != nil {
			return JoinResult{}, err
		}
	}

	lastKnown := state.LastKnown{
		Server:              checkpoint.Server,
		DeviceID:            checkpoint.DeviceID,
		NetworkID:           checkpoint.NetworkID,
		NodeID:              checkpoint.NodeID,
		WireGuardPrivateKey: checkpoint.WireGuardPrivateKey,
		WireGuardPublicKey:  checkpoint.WireGuardPublicKey,
		Phase:               state.PhaseAcknowledged,
		Config:              *checkpoint.Config,
		ConfigContract:      checkpoint.ConfigContract,
		SignedConfigID:      checkpoint.SignedConfigID,
		SignedGeneration:    checkpoint.SignedGeneration,
		UpdatedAt:           j.now().UTC(),
	}
	if err := j.store.SaveLastKnown(lastKnown); err != nil {
		return JoinResult{}, err
	}
	if err := j.store.ClearCheckpoint(); err != nil {
		return JoinResult{}, err
	}
	if checkpoint.InviteEnrollment {
		if err := j.store.ClearEnrollmentSecret(); err != nil {
			return JoinResult{}, err
		}
	}
	return JoinResult{
		DeviceID:  lastKnown.DeviceID,
		NetworkID: lastKnown.NetworkID,
		Revision:  lastKnown.Config.Revision,
	}, nil
}

type fetchedRuntimeConfig struct {
	Config           model.Config
	Contract         ConfigContract
	SignedConfigID   string
	SignedGeneration uint64
}

func (j *Joiner) fetchRuntimeConfig(ctx context.Context, checkpoint *state.Checkpoint, joinToken string) (fetchedRuntimeConfig, error) {
	if checkpoint.InviteEnrollment {
		return j.fetchEnrollmentSignedConfig(ctx, checkpoint, joinToken)
	}
	locked, err := j.store.IsSignedLocked(checkpoint.Server, checkpoint.DeviceID, checkpoint.NetworkID)
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	switch j.contract {
	case ConfigContractLegacy:
		if locked {
			return fetchedRuntimeConfig{}, fault.New(fault.CodeConfigDowngradeBlocked, "fetch legacy config after signed lock", nil)
		}
		return j.fetchLegacyConfig(ctx, *checkpoint)
	case ConfigContractSigned:
		return j.fetchSignedConfig(ctx, *checkpoint)
	case ConfigContractAuto:
		fetched, signedErr := j.fetchSignedConfig(ctx, *checkpoint)
		if signedErr == nil {
			return fetched, nil
		}
		if fault.Code(signedErr) != fault.CodeSignedConfigUnavailable {
			return fetchedRuntimeConfig{}, signedErr
		}
		if locked {
			return fetchedRuntimeConfig{}, fault.New(fault.CodeConfigDowngradeBlocked, "signed config capability unavailable after lock", nil)
		}
		return j.fetchLegacyConfig(ctx, *checkpoint)
	default:
		return fetchedRuntimeConfig{}, fault.New(fault.CodeInvalidInput, "select config contract", nil)
	}
}

func (j *Joiner) exchangeEnrollment(ctx context.Context, checkpoint state.Checkpoint, joinToken string) (state.EnrollmentSecret, error) {
	if strings.TrimSpace(joinToken) == "" {
		return state.EnrollmentSecret{}, fault.New(fault.CodeEnrollmentUnavailable, "renew enrollment with a new invite", nil)
	}
	inviteControlPlane, ok := j.controlPlane.(InviteControlPlane)
	if !ok {
		return state.EnrollmentSecret{}, fault.New(fault.CodeEnrollmentUnavailable, "exchange join invite", nil)
	}
	response, err := inviteControlPlane.ExchangeJoinToken(ctx, controlplane.JoinTokenExchangeRequest{
		JoinToken: joinToken, DeviceID: checkpoint.DeviceID, Name: checkpoint.DeviceName,
		Platform: checkpoint.Platform, Hostname: checkpoint.Hostname,
		WireGuardPublicKey: checkpoint.WireGuardPublicKey, Now: j.now().UTC(),
	})
	if err != nil {
		return state.EnrollmentSecret{}, err
	}
	record := credential.Record{
		SchemaVersion: credential.SchemaVersion, Controller: checkpoint.Server, DeviceID: checkpoint.DeviceID,
		NetworkID: response.Network.ID, Platform: checkpoint.Platform, WireGuardPublicKey: checkpoint.WireGuardPublicKey,
		CredentialID: response.DeviceCredential.CredentialID, Credential: response.DeviceCredential.Credential,
		IssuedAt: response.DeviceCredential.IssuedAt, ExpiresAt: response.DeviceCredential.ExpiresAt,
		Scope:       append([]string(nil), response.DeviceCredential.Scope...),
		SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), response.SigningKeys...)},
	}
	if err := j.credentials.Save(ctx, record); err != nil {
		return state.EnrollmentSecret{}, fault.New(fault.CodeCredentialStorage, "persist device credential before enrollment", err)
	}
	enrollment := state.EnrollmentSecret{
		Controller: checkpoint.Server, DeviceID: checkpoint.DeviceID, NetworkID: response.Network.ID,
		Platform: checkpoint.Platform, WireGuardPublicKey: checkpoint.WireGuardPublicKey,
		EnrollmentToken: response.EnrollmentToken, ExpiresAt: response.ExpiresAt, Scope: append([]string(nil), response.Scope...),
		Device: response.Device, Network: response.Network,
		SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), response.SigningKeys...)}, CreatedAt: j.now().UTC(),
	}
	if err := j.store.SaveEnrollmentSecret(enrollment); err != nil {
		return state.EnrollmentSecret{}, err
	}
	return enrollment, nil
}

func (j *Joiner) mintEnrollment(ctx context.Context, checkpoint state.Checkpoint, record credential.Record) (state.EnrollmentSecret, error) {
	if record.Controller != checkpoint.Server || record.DeviceID != checkpoint.DeviceID || record.WireGuardPublicKey != checkpoint.WireGuardPublicKey || checkpoint.NetworkID != "" && record.NetworkID != checkpoint.NetworkID {
		return state.EnrollmentSecret{}, fault.New(fault.CodeStateConflict, "validate device credential binding", nil)
	}
	deviceControlPlane, ok := j.controlPlane.(DeviceSessionControlPlane)
	if !ok {
		return state.EnrollmentSecret{}, fault.New(fault.CodeEnrollmentUnavailable, "mint device enrollment session", nil)
	}
	nonce, err := j.generateNonce()
	if err != nil {
		return state.EnrollmentSecret{}, fault.New(fault.CodeDeviceSessionInvalid, "generate device session nonce", err)
	}
	response, err := deviceControlPlane.MintDeviceSession(ctx, record, controlplane.DeviceSessionRequest{ClientNonce: nonce, Now: j.now().UTC()})
	if err != nil {
		return state.EnrollmentSecret{}, err
	}
	enrollment := state.EnrollmentSecret{
		Controller: checkpoint.Server, DeviceID: checkpoint.DeviceID, NetworkID: record.NetworkID,
		Platform: checkpoint.Platform, WireGuardPublicKey: checkpoint.WireGuardPublicKey,
		EnrollmentToken: response.EnrollmentToken, ExpiresAt: response.ExpiresAt, Scope: append([]string(nil), response.Scope...),
		Device:  model.Device{ID: record.DeviceID, NetworkID: record.NetworkID, Platform: record.Platform, WireGuardPublicKey: record.WireGuardPublicKey},
		Network: model.Network{ID: record.NetworkID}, SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), response.SigningKeys...)}, CreatedAt: j.now().UTC(),
	}
	if err := j.store.SaveEnrollmentSecret(enrollment); err != nil {
		return state.EnrollmentSecret{}, err
	}
	return enrollment, nil
}

func (j *Joiner) loadOrRenewEnrollment(ctx context.Context, checkpoint *state.Checkpoint, joinToken string) (state.EnrollmentSecret, error) {
	enrollment, err := j.store.LoadEnrollmentSecret(checkpoint.Server, checkpoint.DeviceID, checkpoint.WireGuardPublicKey)
	if err == nil {
		if enrollment.ExpiresAt.After(j.now().UTC()) && (checkpoint.NetworkID == "" || enrollment.NetworkID == checkpoint.NetworkID) {
			return enrollment, nil
		}
		_ = j.store.ClearEnrollmentSecret()
	}
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return state.EnrollmentSecret{}, err
	}
	if j.credentials != nil {
		record, credentialErr := j.credentials.Load(ctx)
		if credentialErr == nil {
			if record.Expired(j.now()) {
				_ = j.credentials.Delete(ctx)
			} else {
				enrollment, mintErr := j.mintEnrollment(ctx, *checkpoint, record)
				if mintErr != nil {
					return state.EnrollmentSecret{}, mintErr
				}
				checkpoint.NetworkID = enrollment.NetworkID
				checkpoint.ConfigContract = string(ConfigContractSigned)
				checkpoint.EnrollmentExpiresAt = enrollment.ExpiresAt
				checkpoint.UpdatedAt = j.now().UTC()
				if err := j.store.SaveCheckpoint(*checkpoint); err != nil {
					return state.EnrollmentSecret{}, err
				}
				return enrollment, nil
			}
		} else if !errors.Is(credentialErr, credential.ErrNotFound) {
			return state.EnrollmentSecret{}, credentialErr
		}
	}
	if strings.TrimSpace(joinToken) == "" {
		return state.EnrollmentSecret{}, fault.New(fault.CodeEnrollmentExpired, "enrollment expired; a new invite is required", nil)
	}
	enrollment, err = j.exchangeEnrollment(ctx, *checkpoint, joinToken)
	if err != nil {
		return state.EnrollmentSecret{}, err
	}
	if checkpoint.NetworkID != "" && enrollment.NetworkID != checkpoint.NetworkID {
		_ = j.store.ClearEnrollmentSecret()
		return state.EnrollmentSecret{}, fault.New(fault.CodeStateConflict, "validate renewed enrollment network", nil)
	}
	checkpoint.NetworkID = enrollment.NetworkID
	checkpoint.ConfigContract = string(ConfigContractSigned)
	checkpoint.EnrollmentExpiresAt = enrollment.ExpiresAt
	checkpoint.UpdatedAt = j.now().UTC()
	if err := j.store.SaveCheckpoint(*checkpoint); err != nil {
		return state.EnrollmentSecret{}, err
	}
	return enrollment, nil
}

func (j *Joiner) fetchEnrollmentSignedConfig(ctx context.Context, checkpoint *state.Checkpoint, joinToken string) (fetchedRuntimeConfig, error) {
	enrollment, err := j.loadOrRenewEnrollment(ctx, checkpoint, joinToken)
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	inviteControlPlane, ok := j.controlPlane.(InviteControlPlane)
	if !ok {
		return fetchedRuntimeConfig{}, fault.New(fault.CodeEnrollmentUnavailable, "use enrollment signed config", nil)
	}
	config, err := inviteControlPlane.GetEnrollmentSignedConfig(ctx, enrollment.EnrollmentToken, controlplane.SignedConfigRequest{
		DeviceID: checkpoint.DeviceID, NetworkID: checkpoint.NetworkID, NodeID: checkpoint.NodeID,
	})
	if err != nil {
		return fetchedRuntimeConfig{}, j.handleEnrollmentError(err)
	}
	verificationKeys := enrollment.SigningKeys
	if exactSessionScope(enrollment.Scope) && j.credentials != nil {
		record, loadErr := j.credentials.Load(ctx)
		if loadErr != nil {
			return fetchedRuntimeConfig{}, loadErr
		}
		verificationKeys = record.SigningKeys
	}
	if err := signedconfig.Verify(config, verificationKeys, j.now()); err != nil {
		return fetchedRuntimeConfig{}, err
	}
	if config.DeviceID != checkpoint.DeviceID || config.NetworkID != checkpoint.NetworkID {
		return fetchedRuntimeConfig{}, fault.New(fault.CodeInvalidSignedConfig, "validate enrollment signed config ownership", nil)
	}
	compiled, err := signedconfig.Compile(config)
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	if err := j.store.AcceptSignedConfig(checkpoint.Server, checkpoint.DeviceID, checkpoint.NetworkID, config.ConfigID, compiled.Digest, config.Generation, j.now()); err != nil {
		return fetchedRuntimeConfig{}, err
	}
	return fetchedRuntimeConfig{Config: compiled, Contract: ConfigContractSigned, SignedConfigID: config.ConfigID, SignedGeneration: config.Generation}, nil
}

func (j *Joiner) handleEnrollmentError(err error) error {
	if fault.Code(err) == fault.CodeEnrollmentExpired {
		_ = j.store.ClearEnrollmentSecret()
	}
	return err
}

func (j *Joiner) fetchLegacyConfig(ctx context.Context, checkpoint state.Checkpoint) (fetchedRuntimeConfig, error) {
	config, err := j.controlPlane.GetConfig(ctx, controlplane.ConfigRequest{
		DeviceID: checkpoint.DeviceID, NetworkID: checkpoint.NetworkID, NodeID: checkpoint.NodeID,
	})
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	return fetchedRuntimeConfig{Config: config, Contract: ConfigContractLegacy}, nil
}

func (j *Joiner) fetchSignedConfig(ctx context.Context, checkpoint state.Checkpoint) (fetchedRuntimeConfig, error) {
	signedControlPlane, ok := j.controlPlane.(SignedControlPlane)
	if !ok {
		return fetchedRuntimeConfig{}, fault.New(fault.CodeSignedConfigUnavailable, "use signed config control plane", nil)
	}
	cache, cacheErr := j.store.LoadSigningKeyCache(checkpoint.Server, checkpoint.DeviceID)
	if cacheErr != nil && !errors.Is(cacheErr, state.ErrNotFound) {
		return fetchedRuntimeConfig{}, cacheErr
	}
	etag := ""
	if cacheErr == nil {
		etag = cache.ETag
	}
	keyResponse, keyErr := signedControlPlane.GetSigningKeys(ctx, etag)
	var keys signedconfig.SigningKeys
	if keyErr != nil {
		if fault.Code(keyErr) != fault.CodeSignedConfigUnavailable || cacheErr != nil {
			return fetchedRuntimeConfig{}, keyErr
		}
		keys = cache.Keys
	} else if keyResponse.NotModified {
		if cacheErr != nil || strings.TrimSpace(etag) == "" {
			return fetchedRuntimeConfig{}, fault.New(fault.CodeInvalidSigningKeys, "reuse missing signing-key cache", nil)
		}
		keys = cache.Keys
	} else {
		keys = keyResponse.Keys
		if err := keys.Validate(); err != nil {
			return fetchedRuntimeConfig{}, err
		}
		if err := j.store.SaveSigningKeyCache(state.SigningKeyCache{
			Controller: checkpoint.Server, DeviceID: checkpoint.DeviceID,
			ETag: keyResponse.ETag, Keys: keys, FetchedAt: j.now().UTC(),
		}); err != nil {
			return fetchedRuntimeConfig{}, err
		}
	}
	config, err := signedControlPlane.GetSignedConfig(ctx, controlplane.SignedConfigRequest{
		DeviceID: checkpoint.DeviceID, NetworkID: checkpoint.NetworkID, NodeID: checkpoint.NodeID,
	})
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	if err := signedconfig.Verify(config, keys, j.now()); err != nil {
		return fetchedRuntimeConfig{}, err
	}
	if config.DeviceID != checkpoint.DeviceID || config.NetworkID != checkpoint.NetworkID {
		return fetchedRuntimeConfig{}, fault.New(fault.CodeInvalidSignedConfig, "validate signed config ownership", nil)
	}
	compiled, err := signedconfig.Compile(config)
	if err != nil {
		return fetchedRuntimeConfig{}, err
	}
	if err := j.store.AcceptSignedConfig(checkpoint.Server, checkpoint.DeviceID, checkpoint.NetworkID, config.ConfigID, compiled.Digest, config.Generation, j.now()); err != nil {
		return fetchedRuntimeConfig{}, err
	}
	return fetchedRuntimeConfig{
		Config: compiled, Contract: ConfigContractSigned,
		SignedConfigID: config.ConfigID, SignedGeneration: config.Generation,
	}, nil
}

func (j *Joiner) recoverLastKnown(ctx context.Context, lastKnown state.LastKnown) (JoinResult, error) {
	if ConfigContract(lastKnown.ConfigContract) == ConfigContractSigned {
		if err := j.store.AcceptSignedConfig(lastKnown.Server, lastKnown.DeviceID, lastKnown.NetworkID, lastKnown.SignedConfigID, lastKnown.Config.Digest, lastKnown.SignedGeneration, j.now()); err != nil {
			return JoinResult{}, err
		}
	}
	runtimeStatus, statusErr := j.runtime.Status(ctx)
	if statusErr != nil {
		return JoinResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read existing runtime status", statusErr)
	}
	if !runtimeStatus.Applied || runtimeStatus.Revision != lastKnown.Config.Revision || runtimeStatus.CoreID != model.CoreIDXray || !model.SupportedAdapterID(runtimeStatus.AdapterID) {
		applyResult, applyErr := j.runtime.Apply(ctx, runtime.ApplyRequest{Config: lastKnown.Config, WireGuardPrivateKey: lastKnown.WireGuardPrivateKey})
		if applyErr == nil && (applyResult.Revision != lastKnown.Config.Revision || applyResult.CoreID != model.CoreIDXray || !model.SupportedAdapterID(applyResult.AdapterID)) {
			applyErr = fault.New(fault.CodeRuntimeApplyFailed, "validate recovered runtime", nil)
		}
		if applyErr != nil {
			return JoinResult{}, fault.New(runtimeApplyErrorCode(applyErr), "recover existing runtime", applyErr)
		}
	}
	return JoinResult{DeviceID: lastKnown.DeviceID, NetworkID: lastKnown.NetworkID, Revision: lastKnown.Config.Revision, AlreadyJoined: true}, nil
}

func (j *Joiner) seedMigrationCheckpoint(lastKnown state.LastKnown) error {
	checkpoint, err := j.store.LoadCheckpoint()
	if err == nil {
		if checkpoint.Server != lastKnown.Server || checkpoint.DeviceID != lastKnown.DeviceID || checkpoint.NetworkID != lastKnown.NetworkID {
			return fault.New(fault.CodeStateConflict, "resume config-contract migration", nil)
		}
		return nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return err
	}
	return j.store.SaveCheckpoint(state.Checkpoint{
		Server: lastKnown.Server, DeviceID: lastKnown.DeviceID,
		NetworkID: lastKnown.NetworkID, NodeID: lastKnown.NodeID,
		WireGuardPrivateKey: lastKnown.WireGuardPrivateKey,
		WireGuardPublicKey:  lastKnown.WireGuardPublicKey,
		Phase:               state.PhaseDeviceRegistered, UpdatedAt: j.now().UTC(),
	})
}

func runtimeApplyErrorCode(err error) string {
	switch fault.Code(err) {
	case fault.CodeRuntimeUnavailable,
		fault.CodeRuntimeDependency,
		fault.CodeRuntimePermission,
		fault.CodeRuntimeProcessStale,
		fault.CodeRuntimeRollbackFailed:
		return fault.Code(err)
	default:
		return fault.CodeRuntimeApplyFailed
	}
}

func (j *Joiner) loadOrCreateCheckpoint(request JoinRequest) (state.Checkpoint, error) {
	checkpoint, err := j.store.LoadCheckpoint()
	if err == nil {
		if checkpoint.Server != request.Server || checkpoint.DeviceID != request.DeviceID {
			return state.Checkpoint{}, fault.New(fault.CodeStateConflict, "resume join", nil)
		}
		if strings.TrimSpace(request.JoinToken) != "" && !checkpoint.InviteEnrollment {
			return state.Checkpoint{}, fault.New(fault.CodeStateConflict, "resume join enrollment mode", nil)
		}
		return checkpoint, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return state.Checkpoint{}, err
	}
	privateKey, publicKey, err := j.generateKey()
	if err != nil {
		return state.Checkpoint{}, fault.New(fault.CodeInvalidConfig, "generate WireGuard key", err)
	}
	checkpoint = state.Checkpoint{
		Server:              request.Server,
		DeviceID:            request.DeviceID,
		DeviceName:          strings.TrimSpace(request.DeviceName),
		Platform:            strings.TrimSpace(request.Platform),
		Hostname:            strings.TrimSpace(request.Hostname),
		NetworkID:           strings.TrimSpace(request.NetworkID),
		NodeID:              strings.TrimSpace(request.NodeID),
		InviteEnrollment:    strings.TrimSpace(request.JoinToken) != "",
		WireGuardPrivateKey: privateKey,
		WireGuardPublicKey:  publicKey,
		Phase:               state.PhaseStarted,
		UpdatedAt:           j.now().UTC(),
	}
	if err := j.store.SaveCheckpoint(checkpoint); err != nil {
		return state.Checkpoint{}, err
	}
	return checkpoint, nil
}

func generateWireGuardKeyPair() (string, string, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privateKey.Bytes()), base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

// GenerateWireGuardKeyPair is shared by self-registration and invite join so
// both flows persist the same X25519 key representation.
func GenerateWireGuardKeyPair() (string, string, error) {
	return generateWireGuardKeyPair()
}

func generateUUIDv4() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func phaseAtLeast(current, target state.Phase) bool {
	order := map[state.Phase]int{
		state.PhaseStarted:          1,
		state.PhaseDeviceRegistered: 2,
		state.PhaseConfigFetched:    3,
		state.PhaseRuntimeApplied:   4,
		state.PhaseAcknowledged:     5,
	}
	return order[current] >= order[target]
}
