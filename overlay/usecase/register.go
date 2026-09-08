// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type RegistrationControlPlane interface {
	CreateRegistration(context.Context, controlplane.RegistrationCreateRequest) (controlplane.RegistrationCreateResponse, error)
	ExchangeRegistration(context.Context, string, string) (controlplane.RegistrationExchangeResponse, error)
}

type RegistrationJoinControlPlane interface {
	RegistrationControlPlane
	ControlPlane
	InviteControlPlane
}

type RegisterRequest struct {
	Controller string
	DeviceID   string
	DeviceName string
	NetworkID  string
	Platform   string
	Hostname   string
}

type RegisterResult struct {
	DeviceID       string `json:"device_id"`
	NetworkID      string `json:"network_id"`
	RegistrationID string `json:"registration_id"`
	Status         string `json:"status"`
	Revision       string `json:"revision"`
}

// RegistrationProgress is deliberately limited to non-secret approval
// coordinates. It cannot carry either registration/enrollment bearers or a
// WireGuard private key.
type RegistrationProgress struct {
	Status                        string
	RegistrationID                string
	DeviceID                      string
	NetworkID                     string
	ExpiresAt                     time.Time
	WireGuardPublicKeyFingerprint string
}

type RegistrationProgressCallback func(RegistrationProgress)

type RegistrationWaiter func(context.Context, time.Duration) error

type Registrar struct {
	controlPlane RegistrationJoinControlPlane
	store        *state.Store
	credentials  credential.Store
	runtime      runtime.Interface
	now          func() time.Time
	generateKey  KeyGenerator
	wait         RegistrationWaiter
	progress     RegistrationProgressCallback
}

func NewRegistrar(controlPlane RegistrationJoinControlPlane, store *state.Store, credentials credential.Store, tunnelRuntime runtime.Interface) *Registrar {
	return &Registrar{
		controlPlane: controlPlane,
		store:        store,
		credentials:  credentials,
		runtime:      tunnelRuntime,
		now:          time.Now,
		generateKey:  generateWireGuardKeyPair,
		wait:         waitRegistration,
	}
}

func (r *Registrar) WithClock(now func() time.Time) *Registrar {
	r.now = now
	return r
}

func (r *Registrar) WithKeyGenerator(generator KeyGenerator) *Registrar {
	r.generateKey = generator
	return r
}

func (r *Registrar) WithWaiter(waiter RegistrationWaiter) *Registrar {
	r.wait = waiter
	return r
}

func (r *Registrar) WithProgress(callback RegistrationProgressCallback) *Registrar {
	r.progress = callback
	return r
}

func (r *Registrar) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	lock, err := r.store.AcquireOperation(ctx, "register")
	if err != nil {
		return RegisterResult{}, err
	}
	defer lock.Release()
	request.Controller = strings.TrimRight(strings.TrimSpace(request.Controller), "/")
	request.DeviceID = strings.TrimSpace(request.DeviceID)
	request.NetworkID = strings.TrimSpace(request.NetworkID)
	request.Platform = strings.TrimSpace(request.Platform)
	if !validRegisterController(request.Controller) || !validRegistrationFields(request) || r.credentials == nil || r.runtime == nil {
		return RegisterResult{}, fault.New(fault.CodeInvalidInput, "register overlay", nil)
	}
	if _, err := r.store.LoadLastKnown(); err == nil {
		return RegisterResult{}, fault.New(fault.CodeStateConflict, "register already joined device", nil)
	} else if !errors.Is(err, state.ErrNotFound) {
		return RegisterResult{}, err
	}

	registration, err := r.loadOrCreateRegistration(request)
	if err != nil {
		return RegisterResult{}, err
	}
	var exchange *controlplane.JoinTokenExchangeResponse
	if registration.Approved != nil {
		exchange = registrationExchangeToControlPlane(*registration.Approved)
	} else {
		if registration.RegistrationID == "" {
			created, createErr := r.controlPlane.CreateRegistration(ctx, controlplane.RegistrationCreateRequest{
				NetworkID: registration.NetworkID, DeviceID: registration.DeviceID, Name: registration.DeviceName,
				Hostname: registration.Hostname, Platform: registration.Platform, WireGuardPublicKey: registration.WireGuardPublicKey,
			})
			if createErr != nil {
				return RegisterResult{}, createErr
			}
			if created.ExpiresAt.Location() != time.UTC || !created.ExpiresAt.After(r.now().UTC()) || created.ExpiresAt.Sub(r.now().UTC()) > controlplane.RegistrationMaximumLifetime || created.Interval != int(controlplane.RegistrationPollInterval/time.Second) || created.Status != "pending" {
				return RegisterResult{}, fault.New(fault.CodeInvalidResponse, "validate registration response", nil)
			}
			registration.RegistrationID = created.RegistrationID
			registration.RegistrationToken = created.RegistrationToken
			registration.Status = "pending"
			registration.ExpiresAt = created.ExpiresAt
			registration.Interval = created.Interval
			registration.UpdatedAt = r.now().UTC()
			if err := r.store.SaveRegistration(registration); err != nil {
				return RegisterResult{}, err
			}
		}
		r.notifyPending(registration)
		exchange, err = r.poll(ctx, &registration)
		if err != nil {
			return RegisterResult{}, err
		}
		if _, err := r.validateApprovedExchange(registration, *exchange); err != nil {
			return RegisterResult{}, err
		}
		approved := controlPlaneExchangeToState(*exchange)
		registration.Status = "approved"
		registration.Approved = &approved
		registration.UpdatedAt = r.now().UTC()
		if err := r.store.SaveRegistration(registration); err != nil {
			return RegisterResult{}, err
		}
	}
	result, err := r.stageAndJoin(ctx, registration, *exchange)
	if err != nil {
		return RegisterResult{}, err
	}
	if err := r.store.ClearRegistration(); err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{DeviceID: result.DeviceID, NetworkID: result.NetworkID, RegistrationID: registration.RegistrationID, Status: "approved", Revision: result.Revision}, nil
}

func (r *Registrar) loadOrCreateRegistration(request RegisterRequest) (state.RegistrationState, error) {
	registration, err := r.store.LoadRegistration()
	if err == nil {
		if registration.Controller != request.Controller || registration.DeviceID != request.DeviceID || registration.NetworkID != request.NetworkID || registration.Platform != request.Platform || registration.WireGuardPublicKey == "" {
			return state.RegistrationState{}, fault.New(fault.CodeStateConflict, "resume registration binding", nil)
		}
		if registration.Approved == nil && !registration.ExpiresAt.IsZero() && !registration.ExpiresAt.After(r.now().UTC()) {
			return state.RegistrationState{}, fault.New(fault.CodeRegistrationExpired, "resume registration", nil)
		}
		return registration, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return state.RegistrationState{}, err
	}
	privateKey, publicKey, err := r.generateKey()
	if err != nil {
		return state.RegistrationState{}, fault.New(fault.CodeInvalidConfig, "generate registration WireGuard key", err)
	}
	now := r.now().UTC()
	registration = state.RegistrationState{
		Controller: request.Controller, Status: "creating", DeviceID: request.DeviceID, DeviceName: strings.TrimSpace(request.DeviceName),
		NetworkID: request.NetworkID, Platform: request.Platform, Hostname: strings.TrimSpace(request.Hostname),
		WireGuardPrivateKey: privateKey, WireGuardPublicKey: publicKey, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.store.SaveRegistration(registration); err != nil {
		return state.RegistrationState{}, err
	}
	return registration, nil
}

func (r *Registrar) poll(ctx context.Context, registration *state.RegistrationState) (*controlplane.JoinTokenExchangeResponse, error) {
	delay := time.Duration(registration.Interval) * time.Second
	if delay < controlplane.RegistrationPollInterval {
		delay = controlplane.RegistrationPollInterval
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	// Derive one shared deadline context from the injected clock. In production
	// this is the same absolute expiry as WithDeadline; using a duration also
	// keeps deterministic clock-based tests faithful to the contract.
	pollContext, cancel := context.WithTimeout(ctx, registration.ExpiresAt.Sub(r.now().UTC()))
	defer cancel()
	for {
		if !r.now().UTC().Before(registration.ExpiresAt) {
			return nil, fault.New(fault.CodeRegistrationExpired, "poll registration", nil)
		}
		response, err := r.controlPlane.ExchangeRegistration(pollContext, registration.RegistrationID, registration.RegistrationToken)
		pollErr := pollContext.Err()
		if err != nil {
			if errors.Is(pollErr, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil, fault.New(fault.CodeRegistrationExpired, "poll registration", nil)
			}
			switch fault.Code(err) {
			case fault.CodeRegistrationTokenInvalid, fault.CodeRegistrationRejected, fault.CodeRegistrationConsumed, fault.CodeRegistrationExpired, fault.CodeInvalidResponse:
				return nil, err
			}
			if err := r.wait(pollContext, r.pollDelay(registration, delay)); err != nil {
				if errors.Is(pollContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
					return nil, fault.New(fault.CodeRegistrationExpired, "poll registration", nil)
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
					return nil, fault.New(fault.CodeRegistrationPending, "registration remains pending", err)
				}
				return nil, err
			}
			if delay < 30*time.Second {
				delay *= 2
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
			continue
		}
		if response.Pending != nil {
			if response.Pending.Status != "pending" || response.Pending.Interval != registration.Interval || !response.Pending.ExpiresAt.Equal(registration.ExpiresAt) || response.Pending.ExpiresAt.Location() != time.UTC {
				return nil, fault.New(fault.CodeInvalidResponse, "validate pending registration", nil)
			}
			if err := r.wait(pollContext, r.pollDelay(registration, delay)); err != nil {
				if errors.Is(pollContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
					return nil, fault.New(fault.CodeRegistrationExpired, "poll registration", nil)
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
					return nil, fault.New(fault.CodeRegistrationPending, "registration remains pending", err)
				}
				return nil, err
			}
			continue
		}
		if response.Exchange != nil {
			return response.Exchange, nil
		}
		return nil, fault.New(fault.CodeInvalidResponse, "decode registration exchange", nil)
	}
}

func (r *Registrar) pollDelay(registration *state.RegistrationState, delay time.Duration) time.Duration {
	remaining := registration.ExpiresAt.Sub(r.now().UTC())
	if remaining <= 0 {
		return 0
	}
	if delay > remaining {
		return remaining
	}
	return delay
}

func (r *Registrar) notifyPending(registration state.RegistrationState) {
	if r.progress == nil {
		return
	}
	r.progress(RegistrationProgress{
		Status: "pending", RegistrationID: registration.RegistrationID, DeviceID: registration.DeviceID,
		NetworkID: registration.NetworkID, ExpiresAt: registration.ExpiresAt,
		WireGuardPublicKeyFingerprint: WireGuardPublicKeyFingerprint(registration.WireGuardPublicKey),
	})
}

func WireGuardPublicKeyFingerprint(publicKey string) string {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != publicKey {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (r *Registrar) validateApprovedExchange(registration state.RegistrationState, exchange controlplane.JoinTokenExchangeResponse) (credential.Record, error) {
	if exchange.Device.ID != registration.DeviceID || exchange.Device.NetworkID != registration.NetworkID || exchange.Device.Platform != registration.Platform || exchange.Device.WireGuardPublicKey != registration.WireGuardPublicKey || exchange.Network.ID != registration.NetworkID {
		return credential.Record{}, fault.New(fault.CodeStateConflict, "validate approved registration binding", nil)
	}
	secret, parseErr := credential.Parse(exchange.DeviceCredential.Credential)
	if parseErr != nil || secret.CredentialID != exchange.DeviceCredential.CredentialID {
		return credential.Record{}, fault.New(fault.CodeInvalidResponse, "validate approved registration credential", nil)
	}
	record := credential.Record{
		SchemaVersion: credential.SchemaVersion, Controller: registration.Controller, DeviceID: registration.DeviceID, NetworkID: registration.NetworkID,
		Platform: registration.Platform, WireGuardPublicKey: registration.WireGuardPublicKey, CredentialID: exchange.DeviceCredential.CredentialID,
		Credential: exchange.DeviceCredential.Credential, IssuedAt: exchange.DeviceCredential.IssuedAt, ExpiresAt: exchange.DeviceCredential.ExpiresAt,
		Scope: append([]string(nil), exchange.DeviceCredential.Scope...), SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), exchange.SigningKeys...)},
	}
	if err := record.Validate(); err != nil {
		return credential.Record{}, fault.New(fault.CodeInvalidResponse, "validate approved registration credential", nil)
	}
	enrollment := state.EnrollmentSecret{
		SchemaVersion: state.SchemaVersion,
		Controller:    registration.Controller, DeviceID: registration.DeviceID, NetworkID: registration.NetworkID, Platform: registration.Platform,
		WireGuardPublicKey: registration.WireGuardPublicKey, EnrollmentToken: exchange.EnrollmentToken, ExpiresAt: exchange.ExpiresAt,
		Scope: append([]string(nil), exchange.Scope...), Device: exchange.Device, Network: exchange.Network,
		SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), exchange.SigningKeys...)}, CreatedAt: r.now().UTC(),
	}
	if err := state.ValidateEnrollmentSecret(enrollment); err != nil {
		return credential.Record{}, fault.New(fault.CodeInvalidResponse, "validate approved registration enrollment", nil)
	}
	return record, nil
}

func (r *Registrar) stageAndJoin(ctx context.Context, registration state.RegistrationState, exchange controlplane.JoinTokenExchangeResponse) (JoinResult, error) {
	record, err := r.validateApprovedExchange(registration, exchange)
	if err != nil {
		return JoinResult{}, err
	}
	if existing, err := r.credentials.Load(ctx); err == nil {
		if existing.Controller != record.Controller || existing.DeviceID != record.DeviceID || existing.NetworkID != record.NetworkID || existing.WireGuardPublicKey != record.WireGuardPublicKey || existing.CredentialID != record.CredentialID || existing.Credential != record.Credential {
			return JoinResult{}, fault.New(fault.CodeStateConflict, "preserve existing device credential", nil)
		}
	} else if errors.Is(err, credential.ErrNotFound) {
		if err := r.credentials.Save(ctx, record); err != nil {
			return JoinResult{}, fault.New(fault.CodeCredentialStorage, "persist registered device credential", err)
		}
	} else {
		return JoinResult{}, err
	}

	enrollment := state.EnrollmentSecret{
		Controller: registration.Controller, DeviceID: registration.DeviceID, NetworkID: registration.NetworkID, Platform: registration.Platform,
		WireGuardPublicKey: registration.WireGuardPublicKey, EnrollmentToken: exchange.EnrollmentToken, ExpiresAt: exchange.ExpiresAt,
		Scope: append([]string(nil), exchange.Scope...), Device: exchange.Device, Network: exchange.Network,
		SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), exchange.SigningKeys...)}, CreatedAt: r.now().UTC(),
	}
	if existing, err := r.store.LoadEnrollmentSecret(registration.Controller, registration.DeviceID, registration.WireGuardPublicKey); err == nil {
		if existing.EnrollmentToken != enrollment.EnrollmentToken || !existing.ExpiresAt.Equal(enrollment.ExpiresAt) {
			return JoinResult{}, fault.New(fault.CodeStateConflict, "preserve existing enrollment session", nil)
		}
	} else if errors.Is(err, state.ErrNotFound) {
		if err := r.store.SaveEnrollmentSecret(enrollment); err != nil {
			return JoinResult{}, err
		}
	} else {
		return JoinResult{}, err
	}

	checkpoint, err := r.store.LoadCheckpoint()
	if errors.Is(err, state.ErrNotFound) {
		checkpoint = state.Checkpoint{Server: registration.Controller, DeviceID: registration.DeviceID, DeviceName: registration.DeviceName, Platform: registration.Platform, Hostname: registration.Hostname, NetworkID: registration.NetworkID, WireGuardPrivateKey: registration.WireGuardPrivateKey, WireGuardPublicKey: registration.WireGuardPublicKey, Phase: state.PhaseDeviceRegistered, ConfigContract: string(ConfigContractSigned), InviteEnrollment: true, EnrollmentExpiresAt: exchange.ExpiresAt, UpdatedAt: r.now().UTC()}
		if err := r.store.SaveCheckpoint(checkpoint); err != nil {
			return JoinResult{}, err
		}
	} else if err != nil {
		return JoinResult{}, err
	} else if checkpoint.Server != registration.Controller || checkpoint.DeviceID != registration.DeviceID || checkpoint.NetworkID != registration.NetworkID || checkpoint.WireGuardPublicKey != registration.WireGuardPublicKey || !checkpoint.InviteEnrollment || !phaseAtLeast(checkpoint.Phase, state.PhaseDeviceRegistered) {
		return JoinResult{}, fault.New(fault.CodeStateConflict, "preserve existing join state", nil)
	}

	return NewJoiner(r.controlPlane, r.store, r.runtime).WithCredentialStore(r.credentials).WithConfigContract(ConfigContractSigned).WithClock(r.now).Join(ctx, JoinRequest{Server: registration.Controller, DeviceID: registration.DeviceID, DeviceName: registration.DeviceName, Platform: registration.Platform, Hostname: registration.Hostname, NetworkID: registration.NetworkID})
}

func controlPlaneExchangeToState(response controlplane.JoinTokenExchangeResponse) state.RegistrationExchange {
	return state.RegistrationExchange{EnrollmentToken: response.EnrollmentToken, TokenType: response.TokenType, ExpiresAt: response.ExpiresAt, Scope: append([]string(nil), response.Scope...), DeviceCredential: state.RegistrationDeviceCredential{CredentialID: response.DeviceCredential.CredentialID, Credential: response.DeviceCredential.Credential, TokenType: response.DeviceCredential.TokenType, IssuedAt: response.DeviceCredential.IssuedAt, ExpiresAt: response.DeviceCredential.ExpiresAt, Scope: append([]string(nil), response.DeviceCredential.Scope...)}, Device: response.Device, Network: response.Network, SigningKeys: signedconfig.SigningKeys{Keys: append([]signedconfig.SigningKey(nil), response.SigningKeys...)}}
}

func registrationExchangeToControlPlane(response state.RegistrationExchange) *controlplane.JoinTokenExchangeResponse {
	return &controlplane.JoinTokenExchangeResponse{EnrollmentToken: response.EnrollmentToken, TokenType: response.TokenType, ExpiresAt: response.ExpiresAt, Scope: append([]string(nil), response.Scope...), DeviceCredential: controlplane.DeviceCredential{CredentialID: response.DeviceCredential.CredentialID, Credential: response.DeviceCredential.Credential, TokenType: response.DeviceCredential.TokenType, IssuedAt: response.DeviceCredential.IssuedAt, ExpiresAt: response.DeviceCredential.ExpiresAt, Scope: append([]string(nil), response.DeviceCredential.Scope...)}, Device: response.Device, Network: response.Network, SigningKeys: append([]signedconfig.SigningKey(nil), response.SigningKeys.Keys...)}
}

func validRegisterController(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validRegistrationFields(request RegisterRequest) bool {
	return request.DeviceID != "" && request.NetworkID != "" && request.Platform != "" && len(request.DeviceName) <= 255 && len(request.Hostname) <= 255 && !strings.ContainsAny(request.DeviceName+request.Hostname, "\r\n\x00")
}

func waitRegistration(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
