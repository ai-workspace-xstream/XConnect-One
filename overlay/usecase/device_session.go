// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/policy"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type DurableDeviceControlPlane interface {
	InviteControlPlane
	DeviceSessionControlPlane
	RotateDeviceCredential(context.Context, credential.Record, controlplane.DeviceCredentialRotateRequest, time.Time) (controlplane.DeviceCredentialRotateResponse, error)
}

// DeviceSessionV2ControlPlane is intentionally separate so existing v1-only
// test doubles and pre-v2 servers retain their explicit v1 behaviour. The
// shipped HTTP client implements it; a caller must opt in before durable sync
// requests v2, and a v2 request never falls back after a capability failure.
type DeviceSessionV2ControlPlane interface {
	GetEnrollmentSignedConfigV2(context.Context, string, controlplane.SignedConfigRequest) (signedconfig.Config, error)
	GetEnrollmentPolicyArtifact(context.Context, string, signedconfig.Policy) ([]byte, error)
}

type DeviceSessionManager struct {
	controlPlane DurableDeviceControlPlane
	state        *state.Store
	credentials  credential.Store
	runtime      runtime.Interface
	now          func() time.Time
	nonce        func() (string, error)
	secret       func() (credential.Secret, error)
	preferV2     bool
}

type SyncResult struct {
	DeviceID       string `json:"device_id"`
	NetworkID      string `json:"network_id"`
	Revision       string `json:"revision"`
	Generation     uint64 `json:"generation"`
	AlreadyCurrent bool   `json:"already_current"`
}

type RotationResult struct {
	CredentialID string    `json:"credential_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Recovered    bool      `json:"recovered"`
}

func NewDeviceSessionManager(controlPlane DurableDeviceControlPlane, stateStore *state.Store, credentialStore credential.Store, tunnelRuntime runtime.Interface) *DeviceSessionManager {
	return &DeviceSessionManager{controlPlane: controlPlane, state: stateStore, credentials: credentialStore, runtime: tunnelRuntime, now: time.Now, nonce: generateUUIDv4, secret: credential.Generate}
}

func (m *DeviceSessionManager) WithClock(now func() time.Time) *DeviceSessionManager {
	m.now = now
	return m
}

// WithSignedConfigV2 explicitly opts a caller into policy-bound config v2.
// The default stays v1 so an Accounts rollout can add the producer without
// changing the behaviour of already-installed clients.
func (m *DeviceSessionManager) WithSignedConfigV2() *DeviceSessionManager {
	m.preferV2 = true
	return m
}

func (m *DeviceSessionManager) Sync(ctx context.Context) (SyncResult, error) {
	lock, err := m.state.AcquireOperation(ctx, "sync")
	if err != nil {
		return SyncResult{}, err
	}
	defer lock.Release()
	lastKnown, err := m.state.LoadLastKnown()
	if errors.Is(err, state.ErrNotFound) {
		return SyncResult{}, fault.New(fault.CodeNotJoined, "sync overlay", nil)
	}
	if err != nil {
		return SyncResult{}, err
	}
	record, err := m.loadBoundCredential(ctx, lastKnown.Server, lastKnown.DeviceID, lastKnown.NetworkID, lastKnown.WireGuardPublicKey)
	if err != nil {
		return SyncResult{}, err
	}
	enrollment, err := m.loadOrMintSession(ctx, record)
	if err != nil {
		return SyncResult{}, err
	}
	request := controlplane.SignedConfigRequest{DeviceID: record.DeviceID, NetworkID: record.NetworkID, NodeID: lastKnown.NodeID}
	v2, supportsV2 := m.controlPlane.(DeviceSessionV2ControlPlane)
	supportsV2 = supportsV2 && m.preferV2
	var config signedconfig.Config
	if supportsV2 {
		config, err = v2.GetEnrollmentSignedConfigV2(ctx, enrollment.EnrollmentToken, request)
	} else {
		config, err = m.controlPlane.GetEnrollmentSignedConfig(ctx, enrollment.EnrollmentToken, request)
	}
	if err != nil {
		return SyncResult{}, handleDeviceSessionError(m.state, err)
	}
	if err := signedconfig.Verify(config, record.SigningKeys, m.now()); err != nil {
		return SyncResult{}, err
	}
	if config.DeviceID != record.DeviceID || config.NetworkID != record.NetworkID {
		return SyncResult{}, fault.New(fault.CodeInvalidSignedConfig, "validate device sync ownership", nil)
	}
	compiled, err := signedconfig.Compile(config)
	if err != nil {
		return SyncResult{}, err
	}
	if err := m.state.ValidateSignedConfigFloor(record.Controller, record.DeviceID, record.NetworkID, config.ConfigID, compiled.Digest, config.Generation); err != nil {
		return SyncResult{}, err
	}
	if !supportsV2 {
		// Preserve the established v1 floor timing. V2 intentionally commits only
		// after its policy has staged, runtime readback has succeeded, and ACK is
		// accepted below.
		if err := m.state.AcceptSignedConfig(record.Controller, record.DeviceID, record.NetworkID, config.ConfigID, compiled.Digest, config.Generation, m.now()); err != nil {
			return SyncResult{}, err
		}
	}
	var acceptedPolicy policy.Accepted
	if supportsV2 {
		if config.SchemaVersion != signedconfig.SchemaVersionV2 || config.Policy == nil {
			return SyncResult{}, fault.New(fault.CodeInvalidSignedConfig, "validate device sync v2 policy", nil)
		}
		reference, referenceErr := policy.ReferenceFromVerifiedSignedConfig(config.NetworkID, config.Policy.Generation, config.Policy.Digest, config.ExpiresAt.Time)
		if referenceErr != nil {
			return SyncResult{}, referenceErr
		}
		floor, floorErr := m.policyFloor(record.NetworkID)
		if floorErr != nil {
			return SyncResult{}, floorErr
		}
		raw, artifactErr := v2.GetEnrollmentPolicyArtifact(ctx, enrollment.EnrollmentToken, *config.Policy)
		if artifactErr != nil {
			return SyncResult{}, handleDeviceSessionError(m.state, artifactErr)
		}
		acceptedPolicy, err = policy.Consume(raw, reference, floor, m.now())
		if err != nil {
			return SyncResult{}, err
		}
	}
	status, err := m.runtime.Status(ctx)
	if err != nil {
		return SyncResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read runtime before sync", err)
	}
	alreadyCurrent := runtimeMatches(status, state.LastKnown{Config: compiled})
	if !alreadyCurrent {
		apply, applyErr := m.runtime.Apply(ctx, runtime.ApplyRequest{Config: compiled, WireGuardPrivateKey: lastKnown.WireGuardPrivateKey})
		if applyErr == nil && (apply.Revision != compiled.Revision || apply.CoreID != model.CoreIDXray || !model.SupportedAdapterID(apply.AdapterID)) {
			applyErr = fault.New(fault.CodeRuntimeApplyFailed, "validate synchronized runtime", nil)
		}
		if applyErr != nil {
			return SyncResult{}, fault.New(runtimeApplyErrorCode(applyErr), "apply synchronized runtime", applyErr)
		}
		readback, readbackErr := m.runtime.Status(ctx)
		if readbackErr != nil || !runtimeMatches(readback, state.LastKnown{Config: compiled}) {
			return SyncResult{}, fault.New(fault.CodeRuntimeApplyFailed, "read back synchronized runtime", readbackErr)
		}
	}
	ack, err := m.controlPlane.AckEnrollmentSignedConfig(ctx, enrollment.EnrollmentToken, controlplane.SignedConfigAckRequest{Generation: config.Generation, ConfigID: config.ConfigID, DeviceID: record.DeviceID, AppliedAt: m.now().UTC()})
	if err != nil {
		return SyncResult{}, handleDeviceSessionError(m.state, err)
	}
	if !ack.Acked || ack.Ack.DeviceID != record.DeviceID || ack.Ack.ConfigID != config.ConfigID || ack.Ack.Generation != config.Generation {
		return SyncResult{}, fault.New(fault.CodeInvalidResponse, "acknowledge device sync", nil)
	}
	if supportsV2 {
		if err := m.state.AcceptSignedConfig(record.Controller, record.DeviceID, record.NetworkID, config.ConfigID, compiled.Digest, config.Generation, m.now()); err != nil {
			return SyncResult{}, err
		}
		if err := m.state.SavePolicyState(state.PolicyState{NetworkID: acceptedPolicy.Artifact.NetworkID, Generation: acceptedPolicy.Generation, Digest: acceptedPolicy.Digest, Revision: acceptedPolicy.Artifact.Revision, ExpiresAt: acceptedPolicy.ExpiresAt, AcceptedAt: m.now().UTC()}); err != nil {
			return SyncResult{}, err
		}
	}
	lastKnown.Config = compiled
	lastKnown.ConfigContract = string(ConfigContractSigned)
	lastKnown.SignedConfigID = config.ConfigID
	lastKnown.SignedGeneration = config.Generation
	lastKnown.UpdatedAt = m.now().UTC()
	if err := m.state.SaveLastKnown(lastKnown); err != nil {
		return SyncResult{}, err
	}
	record.SigningKeys = enrollment.SigningKeys
	if err := m.credentials.Save(ctx, record); err != nil {
		return SyncResult{}, fault.New(fault.CodeCredentialStorage, "commit verified signing keys", err)
	}
	if err := m.state.ClearEnrollmentSecret(); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{DeviceID: record.DeviceID, NetworkID: record.NetworkID, Revision: compiled.Revision, Generation: config.Generation, AlreadyCurrent: alreadyCurrent}, nil
}

func (m *DeviceSessionManager) policyFloor(networkID string) (policy.Floor, error) {
	current, err := m.state.LoadPolicyState()
	if errors.Is(err, state.ErrNotFound) {
		return policy.Floor{NetworkID: networkID}, nil
	}
	if err != nil {
		return policy.Floor{}, err
	}
	return policy.Floor{NetworkID: current.NetworkID, Generation: current.Generation, Digest: current.Digest}, nil
}

func (m *DeviceSessionManager) Rotate(ctx context.Context) (RotationResult, error) {
	lock, err := m.state.AcquireOperation(ctx, "credential-rotate")
	if err != nil {
		return RotationResult{}, err
	}
	defer lock.Release()
	record, err := m.loadCredential(ctx)
	if err != nil {
		return RotationResult{}, err
	}
	if record.Pending != nil {
		probe, probeErr := record.PendingRecord()
		if probeErr != nil {
			return RotationResult{}, probeErr
		}
		nonce, nonceErr := m.nonce()
		if nonceErr != nil {
			return RotationResult{}, fault.New(fault.CodeDeviceSessionInvalid, "generate credential probe nonce", nonceErr)
		}
		if _, probeErr = m.controlPlane.MintDeviceSession(ctx, probe, controlplane.DeviceSessionRequest{ClientNonce: nonce, Now: m.now().UTC()}); probeErr == nil {
			promoted, promoteErr := record.PromotePending(probe.IssuedAt, probe.ExpiresAt, record.Scope)
			if promoteErr != nil {
				return RotationResult{}, promoteErr
			}
			if saveErr := m.credentials.Save(ctx, promoted); saveErr != nil {
				return RotationResult{}, saveErr
			}
			return RotationResult{CredentialID: promoted.CredentialID, ExpiresAt: promoted.ExpiresAt, Recovered: true}, nil
		} else if fault.Code(probeErr) != fault.CodeCredentialInvalid {
			return RotationResult{}, probeErr
		}
	} else {
		secret, generateErr := m.secret()
		if generateErr != nil {
			return RotationResult{}, fault.New(fault.CodeCredentialStorage, "generate successor device credential", generateErr)
		}
		record, err = record.WithPending(secret, m.now())
		if err != nil {
			return RotationResult{}, err
		}
		if err := m.credentials.Save(ctx, record); err != nil {
			return RotationResult{}, err
		}
	}
	response, err := m.controlPlane.RotateDeviceCredential(ctx, record, controlplane.DeviceCredentialRotateRequest{NewCredentialID: record.Pending.CredentialID, NewCredentialSHA256: record.Pending.Verifier}, m.now().UTC())
	if err != nil {
		return RotationResult{}, err
	}
	promoted, err := record.PromotePending(response.IssuedAt, response.ExpiresAt, response.Scope)
	if err != nil {
		return RotationResult{}, err
	}
	if err := m.credentials.Save(ctx, promoted); err != nil {
		return RotationResult{}, err
	}
	return RotationResult{CredentialID: promoted.CredentialID, ExpiresAt: promoted.ExpiresAt}, nil
}

func (m *DeviceSessionManager) loadOrMintSession(ctx context.Context, record credential.Record) (state.EnrollmentSecret, error) {
	enrollment, err := m.state.LoadEnrollmentSecret(record.Controller, record.DeviceID, record.WireGuardPublicKey)
	if err == nil && exactSessionScope(enrollment.Scope) && enrollment.ExpiresAt.After(m.now().UTC()) && enrollment.NetworkID == record.NetworkID {
		return enrollment, nil
	}
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return state.EnrollmentSecret{}, err
	}
	_ = m.state.ClearEnrollmentSecret()
	nonce, err := m.nonce()
	if err != nil {
		return state.EnrollmentSecret{}, fault.New(fault.CodeDeviceSessionInvalid, "generate device session nonce", err)
	}
	response, err := m.controlPlane.MintDeviceSession(ctx, record, controlplane.DeviceSessionRequest{ClientNonce: nonce, Now: m.now().UTC()})
	if err != nil {
		return state.EnrollmentSecret{}, err
	}
	enrollment = state.EnrollmentSecret{
		Controller: record.Controller, DeviceID: record.DeviceID, NetworkID: record.NetworkID, Platform: record.Platform,
		WireGuardPublicKey: record.WireGuardPublicKey, EnrollmentToken: response.EnrollmentToken,
		ExpiresAt: response.ExpiresAt, Scope: append([]string(nil), response.Scope...), CreatedAt: m.now().UTC(),
		Device:  model.Device{ID: record.DeviceID, NetworkID: record.NetworkID, Platform: record.Platform, WireGuardPublicKey: record.WireGuardPublicKey},
		Network: model.Network{ID: record.NetworkID}, SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), response.SigningKeys...)},
	}
	if err := m.state.SaveEnrollmentSecret(enrollment); err != nil {
		return state.EnrollmentSecret{}, err
	}
	return enrollment, nil
}

func (m *DeviceSessionManager) loadCredential(ctx context.Context) (credential.Record, error) {
	if m.credentials == nil {
		return credential.Record{}, fault.New(fault.CodeCredentialStorage, "use protected device credential storage", nil)
	}
	record, err := m.credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return credential.Record{}, fault.New(fault.CodeCredentialMissing, "load device credential", nil)
	}
	if err != nil {
		return credential.Record{}, err
	}
	if record.Expired(m.now()) {
		return credential.Record{}, fault.New(fault.CodeCredentialExpired, "load device credential", nil)
	}
	return record, nil
}

func (m *DeviceSessionManager) loadBoundCredential(ctx context.Context, controller, deviceID, networkID, publicKey string) (credential.Record, error) {
	record, err := m.loadCredential(ctx)
	if err != nil {
		return credential.Record{}, err
	}
	if record.Controller != controller || record.DeviceID != deviceID || record.NetworkID != networkID || record.WireGuardPublicKey != publicKey {
		return credential.Record{}, fault.New(fault.CodeStateConflict, "validate device credential state binding", nil)
	}
	return record, nil
}

func exactSessionScope(values []string) bool {
	return len(values) == 2 && (values[0] == "overlay:config:read" && values[1] == "overlay:config:ack" || values[1] == "overlay:config:read" && values[0] == "overlay:config:ack")
}

func handleDeviceSessionError(store *state.Store, err error) error {
	if fault.Code(err) == fault.CodeEnrollmentExpired {
		_ = store.ClearEnrollmentSecret()
	}
	return err
}
