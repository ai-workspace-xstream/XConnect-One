// Modified for XConnect-One: standalone module imports.
package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

type registrationFixture struct {
	*inviteControlPlaneFixture
	registrationCalls int
	exchangeCalls     int
	now               time.Time
	approvedDeviceID  string
}

func newRegistrationFixture(t *testing.T, now time.Time) *registrationFixture {
	return &registrationFixture{inviteControlPlaneFixture: newInviteControlPlaneFixture(t), now: now, approvedDeviceID: "dev_laptop"}
}

func (f *registrationFixture) CreateRegistration(_ context.Context, request controlplane.RegistrationCreateRequest) (controlplane.RegistrationCreateResponse, error) {
	f.registrationCalls++
	return controlplane.RegistrationCreateResponse{RegistrationID: "xreg_test123", RegistrationToken: opaqueUsecaseSecret("xrt_", 33), Status: "pending", ExpiresAt: f.now.Add(10 * time.Minute), Interval: 5}, nil
}

func (f *registrationFixture) ExchangeRegistration(_ context.Context, registrationID, registrationToken string) (controlplane.RegistrationExchangeResponse, error) {
	f.exchangeCalls++
	if registrationID != "xreg_test123" || registrationToken == "" {
		return controlplane.RegistrationExchangeResponse{}, errors.New("registration binding was not supplied")
	}
	if f.exchangeCalls == 1 {
		return controlplane.RegistrationExchangeResponse{Pending: &controlplane.RegistrationPendingResponse{Status: "pending", ExpiresAt: f.now.Add(10 * time.Minute), Interval: 5}}, nil
	}
	enrollmentToken := opaqueUsecaseSecret("xenr_", 34)
	f.enrollmentTokens = append(f.enrollmentTokens, enrollmentToken)
	publicKey := "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	return controlplane.RegistrationExchangeResponse{Exchange: &controlplane.JoinTokenExchangeResponse{
		EnrollmentToken: enrollmentToken, TokenType: "Bearer", ExpiresAt: f.now.Add(10 * time.Minute),
		Scope:            []string{"overlay:config:read", "overlay:config:ack", "overlay:device:revoke"},
		DeviceCredential: fixtureDeviceCredential(f.now),
		Device:           model.Device{ID: f.approvedDeviceID, NetworkID: "net_private", Platform: "linux", WireGuardPublicKey: publicKey, WireGuardAddress: "10.77.0.10/32"},
		Network:          model.Network{ID: "net_private", CIDR: "10.77.0.0/16"}, SigningKeys: append([]signedconfig.SigningKey(nil), f.keys.Keys...),
	}}, nil
}

func TestRegisterPendingPersists0600AndNeverStartsRuntime(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC)
	fixture := newRegistrationFixture(t, now)
	store := state.NewStore(t.TempDir())
	credentials := &credential.MemoryStore{}
	tunnelRuntime := &overlayruntime.Fake{}
	var progress usecase.RegistrationProgress
	registrar := usecase.NewRegistrar(fixture, store, credentials, tunnelRuntime).
		WithClock(func() time.Time { return now }).
		WithKeyGenerator(fixedKeys).
		WithWaiter(func(context.Context, time.Duration) error { return context.Canceled }).
		WithProgress(func(value usecase.RegistrationProgress) { progress = value })
	_, err := registrar.Register(t.Context(), usecase.RegisterRequest{Controller: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux", Hostname: "laptop"})
	if fault.Code(err) != fault.CodeRegistrationPending {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
	if fixture.registrationCalls != 1 || fixture.exchangeCalls != 1 || tunnelRuntime.ApplyCalls != 0 || fixture.enrollmentAckCalls != 0 {
		t.Fatalf("create=%d exchange=%d apply=%d ack=%d", fixture.registrationCalls, fixture.exchangeCalls, tunnelRuntime.ApplyCalls, fixture.enrollmentAckCalls)
	}
	registration, err := store.LoadRegistration()
	if err != nil || registration.Status != "pending" || registration.RegistrationToken == "" {
		t.Fatalf("registration=%#v err=%v", registration, err)
	}
	if err := state.ValidatePermissions(store.RegistrationPath(), 0o600); err != nil {
		t.Fatalf("registration permissions: %v", err)
	}
	if progress.Status != "pending" || progress.RegistrationID != "xreg_test123" || progress.DeviceID != "dev_laptop" || progress.NetworkID != "net_private" || progress.WireGuardPublicKeyFingerprint != "75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a" {
		t.Fatalf("unexpected safe progress=%#v", progress)
	}
	if progress.WireGuardPublicKeyFingerprint == usecase.WireGuardPublicKeyFingerprint("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI") {
		t.Fatal("non-canonical WireGuard key unexpectedly produced a fingerprint")
	}
}

func TestRegisterApprovalReusesSignedConfigApplyAndAckPath(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC)
	fixture := newRegistrationFixture(t, now)
	store := state.NewStore(t.TempDir())
	credentials := &credential.MemoryStore{}
	tunnelRuntime := &overlayruntime.Fake{}
	waiter := func(context.Context, time.Duration) error { return nil }
	registrar := usecase.NewRegistrar(fixture, store, credentials, tunnelRuntime).
		WithClock(func() time.Time { return now }).
		WithKeyGenerator(fixedKeys).
		WithWaiter(waiter)
	// Establish a resumable pending request first; the second call receives the
	// exact existing exchange response and must enter the ordinary invite-style
	// signed-config path without replaying an invite.
	fixture.exchangeCalls = 1
	fixture.registrationCalls = 1
	registration := state.RegistrationState{Controller: "https://accounts.example", RegistrationID: "xreg_test123", RegistrationToken: opaqueUsecaseSecret("xrt_", 33), Status: "pending", ExpiresAt: now.Add(10 * time.Minute), Interval: 5, DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux", WireGuardPrivateKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", WireGuardPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", CreatedAt: now, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	result, err := registrar.Register(t.Context(), usecase.RegisterRequest{Controller: registration.Controller, DeviceID: registration.DeviceID, NetworkID: registration.NetworkID, Platform: registration.Platform, Hostname: "laptop"})
	if err != nil {
		t.Fatalf("register approval: %v", err)
	}
	if result.Status != "approved" || result.Revision != "cfg_42" || fixture.enrollmentConfigCalls != 1 || fixture.enrollmentAckCalls != 1 || tunnelRuntime.ApplyCalls != 1 {
		t.Fatalf("result=%#v config=%d ack=%d apply=%d", result, fixture.enrollmentConfigCalls, fixture.enrollmentAckCalls, tunnelRuntime.ApplyCalls)
	}
	if _, err := store.LoadLastKnown(); err != nil {
		t.Fatalf("last-known state: %v", err)
	}
	if _, err := store.LoadRegistration(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("registration state remains: %v", err)
	}
}

func TestRegisterApprovalRejectsExchangeIdentityMismatchWithoutRuntime(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC)
	fixture := newRegistrationFixture(t, now)
	store := state.NewStore(t.TempDir())
	tunnelRuntime := &overlayruntime.Fake{}
	registrar := usecase.NewRegistrar(fixture, store, &credential.MemoryStore{}, tunnelRuntime).
		WithClock(func() time.Time { return now }).
		WithKeyGenerator(fixedKeys).
		WithWaiter(func(context.Context, time.Duration) error { return context.Canceled })
	_, err := registrar.Register(t.Context(), usecase.RegisterRequest{Controller: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux"})
	if fault.Code(err) != fault.CodeRegistrationPending {
		t.Fatalf("initial code=%q err=%v", fault.Code(err), err)
	}
	fixture.approvedDeviceID = "dev_other"
	registrar.WithWaiter(func(context.Context, time.Duration) error { return nil })
	_, err = registrar.Register(t.Context(), usecase.RegisterRequest{Controller: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux"})
	if fault.Code(err) != fault.CodeStateConflict || tunnelRuntime.ApplyCalls != 0 || fixture.enrollmentAckCalls != 0 {
		t.Fatalf("code=%q err=%v apply=%d ack=%d", fault.Code(err), err, tunnelRuntime.ApplyCalls, fixture.enrollmentAckCalls)
	}
	approved, loadErr := store.LoadRegistration()
	if loadErr != nil || approved.Status != "pending" || approved.Approved != nil {
		t.Fatalf("mismatched response poisoned resumable state: %#v err=%v", approved, loadErr)
	}
}

func TestRegisterRejectsExistingJoinedStateBeforeCreatingRegistration(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC)
	fixture := newRegistrationFixture(t, now)
	store := state.NewStore(t.TempDir())
	lastKnown := state.LastKnown{Server: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", WireGuardPrivateKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", WireGuardPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", Phase: state.PhaseAcknowledged, Config: validConfig(), UpdatedAt: now}
	if err := store.SaveLastKnown(lastKnown); err != nil {
		t.Fatal(err)
	}
	_, err := usecase.NewRegistrar(fixture, store, &credential.MemoryStore{}, &overlayruntime.Fake{}).WithClock(func() time.Time { return now }).Register(t.Context(), usecase.RegisterRequest{Controller: lastKnown.Server, DeviceID: lastKnown.DeviceID, NetworkID: lastKnown.NetworkID, Platform: "linux"})
	if fault.Code(err) != fault.CodeStateConflict || fixture.registrationCalls != 0 {
		t.Fatalf("code=%q err=%v create=%d", fault.Code(err), err, fixture.registrationCalls)
	}
}
