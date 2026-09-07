// Modified for XConnect-One: standalone module imports.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

type signedControlPlaneFixture struct {
	config          signedconfig.Config
	keys            signedconfig.SigningKeys
	signingKeysErr  error
	signedConfigErr error
	signedAckErrors []error
	registerCalls   int
	legacyCalls     int
	legacyAckCalls  int
	keyCalls        int
	signedCalls     int
	signedAckCalls  int
}

func newSignedControlPlaneFixture(t *testing.T) *signedControlPlaneFixture {
	t.Helper()
	config, keys := validSignedContract(t)
	return &signedControlPlaneFixture{config: config, keys: keys}
}

func (f *signedControlPlaneFixture) RegisterDevice(_ context.Context, request controlplane.RegisterDeviceRequest) (controlplane.RegisterDeviceResponse, error) {
	f.registerCalls++
	return controlplane.RegisterDeviceResponse{
		Device:  model.Device{ID: request.DeviceID, NetworkID: "net_private", WireGuardPublicKey: request.WireGuardPublicKey, WireGuardAddress: "10.77.0.10/32"},
		Network: model.Network{ID: "net_private", CIDR: "10.77.0.0/16"},
	}, nil
}

func (f *signedControlPlaneFixture) GetConfig(context.Context, controlplane.ConfigRequest) (model.Config, error) {
	f.legacyCalls++
	return validConfig(), nil
}

func (f *signedControlPlaneFixture) AckConfig(_ context.Context, request controlplane.ConfigAckRequest) (controlplane.ConfigAckResponse, error) {
	f.legacyAckCalls++
	return controlplane.ConfigAckResponse{Acked: true, DeviceID: request.DeviceID, NetworkID: request.NetworkID, Revision: request.Revision}, nil
}

func (f *signedControlPlaneFixture) GetSigningKeys(context.Context, string) (controlplane.SigningKeysResponse, error) {
	f.keyCalls++
	if f.signingKeysErr != nil {
		return controlplane.SigningKeysResponse{}, f.signingKeysErr
	}
	return controlplane.SigningKeysResponse{Keys: f.keys, ETag: `"keys-1"`}, nil
}

func (f *signedControlPlaneFixture) GetSignedConfig(context.Context, controlplane.SignedConfigRequest) (signedconfig.Config, error) {
	f.signedCalls++
	if f.signedConfigErr != nil {
		return signedconfig.Config{}, f.signedConfigErr
	}
	return f.config, nil
}

func (f *signedControlPlaneFixture) AckSignedConfig(_ context.Context, request controlplane.SignedConfigAckRequest) (controlplane.SignedConfigAckResponse, error) {
	f.signedAckCalls++
	if len(f.signedAckErrors) > 0 {
		err := f.signedAckErrors[0]
		f.signedAckErrors = f.signedAckErrors[1:]
		if err != nil {
			return controlplane.SignedConfigAckResponse{}, err
		}
	}
	return controlplane.SignedConfigAckResponse{Acked: true, Ack: controlplane.SignedConfigAck{
		DeviceID: request.DeviceID, ConfigID: request.ConfigID, Generation: request.Generation,
		AppliedAt:  request.AppliedAt.UTC().Truncate(time.Second),
		ReceivedAt: request.AppliedAt.UTC().Truncate(time.Second),
	}}, nil
}

func TestSignedJoinAppliesBeforeGenerationAckAndPersistsLock(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	tunnelRuntime := &overlayruntime.Fake{}
	joiner, store := newSignedJoiner(t, controlPlane, tunnelRuntime, usecase.ConfigContractSigned)

	result, err := joiner.Join(t.Context(), signedJoinRequest())
	if err != nil {
		t.Fatalf("signed join: %v", err)
	}
	if result.Revision != "cfg_42" || tunnelRuntime.ApplyCalls != 1 || controlPlane.signedAckCalls != 1 || controlPlane.legacyCalls != 0 || controlPlane.legacyAckCalls != 0 {
		t.Fatalf("result=%#v apply=%d signedAck=%d legacy=%d/%d", result, tunnelRuntime.ApplyCalls, controlPlane.signedAckCalls, controlPlane.legacyCalls, controlPlane.legacyAckCalls)
	}
	lastKnown, err := store.LoadLastKnown()
	if err != nil || lastKnown.ConfigContract != string(usecase.ConfigContractSigned) || lastKnown.SignedGeneration != 42 || lastKnown.SignedConfigID != "cfg_42" {
		t.Fatalf("last known = %#v, err=%v", lastKnown, err)
	}
	locked, err := store.IsSignedLocked(signedJoinRequest().Server, "dev_laptop", "net_private")
	if err != nil || !locked {
		t.Fatalf("signed lock = %t, err=%v", locked, err)
	}
}

func TestSignedJoinRuntimeFailureNeverAcknowledgesAndResumes(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	tunnelRuntime := &overlayruntime.Fake{ApplyError: errors.New("apply failed with secret material")}
	joiner, store := newSignedJoiner(t, controlPlane, tunnelRuntime, usecase.ConfigContractSigned)

	_, err := joiner.Join(t.Context(), signedJoinRequest())
	if fault.Code(err) != fault.CodeRuntimeApplyFailed || controlPlane.signedAckCalls != 0 {
		t.Fatalf("first error=%v signed ACK calls=%d", err, controlPlane.signedAckCalls)
	}
	checkpoint, err := store.LoadCheckpoint()
	if err != nil || checkpoint.Phase != state.PhaseConfigFetched || checkpoint.ConfigContract != string(usecase.ConfigContractSigned) {
		t.Fatalf("checkpoint=%#v err=%v", checkpoint, err)
	}
	tunnelRuntime.ApplyError = nil
	if _, err := joiner.Join(t.Context(), signedJoinRequest()); err != nil {
		t.Fatalf("resume signed join: %v", err)
	}
	if tunnelRuntime.ApplyCalls != 2 || controlPlane.keyCalls != 1 || controlPlane.signedCalls != 1 || controlPlane.signedAckCalls != 1 {
		t.Fatalf("resume calls apply=%d keys=%d config=%d ack=%d", tunnelRuntime.ApplyCalls, controlPlane.keyCalls, controlPlane.signedCalls, controlPlane.signedAckCalls)
	}
}

func TestSignedJoinAckInterruptionDoesNotReapply(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	controlPlane.signedAckErrors = []error{fault.New(fault.CodeControlPlaneUnavailable, "ack", nil), nil}
	tunnelRuntime := &overlayruntime.Fake{}
	joiner, _ := newSignedJoiner(t, controlPlane, tunnelRuntime, usecase.ConfigContractSigned)

	if _, err := joiner.Join(t.Context(), signedJoinRequest()); fault.Code(err) != fault.CodeControlPlaneUnavailable {
		t.Fatalf("first ack error code=%q err=%v", fault.Code(err), err)
	}
	if _, err := joiner.Join(t.Context(), signedJoinRequest()); err != nil {
		t.Fatalf("resume ack: %v", err)
	}
	if tunnelRuntime.ApplyCalls != 1 || controlPlane.signedAckCalls != 2 {
		t.Fatalf("apply=%d ack=%d", tunnelRuntime.ApplyCalls, controlPlane.signedAckCalls)
	}
}

func TestAutoFallsBackOnlyBeforeSignedAcceptance(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	controlPlane.signingKeysErr = fault.New(fault.CodeSignedConfigUnavailable, "missing capability", nil)
	tunnelRuntime := &overlayruntime.Fake{}
	joiner, _ := newSignedJoiner(t, controlPlane, tunnelRuntime, usecase.ConfigContractAuto)

	if _, err := joiner.Join(t.Context(), signedJoinRequest()); err != nil {
		t.Fatalf("auto legacy fallback: %v", err)
	}
	if controlPlane.legacyCalls != 1 || controlPlane.legacyAckCalls != 1 || controlPlane.signedAckCalls != 0 {
		t.Fatalf("fallback calls legacy=%d ack=%d signedAck=%d", controlPlane.legacyCalls, controlPlane.legacyAckCalls, controlPlane.signedAckCalls)
	}
}

func TestAutoNeverDowngradesAfterSignedAcceptance(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	tunnelRuntime := &overlayruntime.Fake{ApplyError: errors.New("runtime unavailable")}
	joiner, store := newSignedJoiner(t, controlPlane, tunnelRuntime, usecase.ConfigContractAuto)
	if _, err := joiner.Join(t.Context(), signedJoinRequest()); fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("signed acceptance error=%v", err)
	}
	if err := store.ClearCheckpoint(); err != nil {
		t.Fatal(err)
	}
	controlPlane.signingKeysErr = fault.New(fault.CodeSignedConfigUnavailable, "capability unavailable", nil)
	controlPlane.signedConfigErr = fault.New(fault.CodeSignedConfigUnavailable, "capability unavailable", nil)
	_, err := joiner.Join(t.Context(), signedJoinRequest())
	if fault.Code(err) != fault.CodeConfigDowngradeBlocked || controlPlane.legacyCalls != 0 || controlPlane.signedAckCalls != 0 {
		t.Fatalf("downgrade error=%v legacy=%d signedAck=%d", err, controlPlane.legacyCalls, controlPlane.signedAckCalls)
	}
}

func TestAutoBadSignatureNeverFallsBack(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	controlPlane.config.Signature.Value = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, ed25519.SignatureSize))
	joiner, _ := newSignedJoiner(t, controlPlane, &overlayruntime.Fake{}, usecase.ConfigContractAuto)
	_, err := joiner.Join(t.Context(), signedJoinRequest())
	if fault.Code(err) != fault.CodeInvalidSignature || controlPlane.legacyCalls != 0 || controlPlane.signedAckCalls != 0 {
		t.Fatalf("error=%v legacy=%d ack=%d", err, controlPlane.legacyCalls, controlPlane.signedAckCalls)
	}
}

func TestSignedJoinRejectsSignedConfigForAnotherDevice(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	controlPlane.config.DeviceID = "dev_other"
	resignSignedConfig(t, &controlPlane.config)
	joiner, _ := newSignedJoiner(t, controlPlane, &overlayruntime.Fake{}, usecase.ConfigContractSigned)
	_, err := joiner.Join(t.Context(), signedJoinRequest())
	if fault.Code(err) != fault.CodeInvalidSignedConfig || controlPlane.signedAckCalls != 0 {
		t.Fatalf("ownership error=%v ack=%d", err, controlPlane.signedAckCalls)
	}
}

func TestAutoMigratesAcknowledgedLegacyStateWithoutRotatingLocalKey(t *testing.T) {
	controlPlane := newSignedControlPlaneFixture(t)
	store := state.NewStore(t.TempDir())
	tunnelRuntime := &overlayruntime.Fake{}
	now := func() time.Time { return time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC) }
	legacyJoiner := usecase.NewJoiner(controlPlane, store, tunnelRuntime).WithKeyGenerator(fixedKeys).WithClock(now)
	if _, err := legacyJoiner.Join(t.Context(), signedJoinRequest()); err != nil {
		t.Fatalf("legacy join: %v", err)
	}
	legacyState, err := store.LoadLastKnown()
	if err != nil {
		t.Fatal(err)
	}
	autoJoiner := usecase.NewJoiner(controlPlane, store, tunnelRuntime).WithKeyGenerator(fixedKeys).WithClock(now).WithConfigContract(usecase.ConfigContractAuto)
	result, err := autoJoiner.Join(t.Context(), signedJoinRequest())
	if err != nil {
		t.Fatalf("signed migration: %v", err)
	}
	migratedState, err := store.LoadLastKnown()
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != "cfg_42" || migratedState.ConfigContract != string(usecase.ConfigContractSigned) || migratedState.WireGuardPrivateKey != legacyState.WireGuardPrivateKey || migratedState.WireGuardPublicKey != legacyState.WireGuardPublicKey {
		t.Fatalf("migration result=%#v state=%#v", result, migratedState)
	}
	if controlPlane.registerCalls != 1 || controlPlane.legacyCalls != 1 || controlPlane.legacyAckCalls != 1 || controlPlane.signedCalls != 1 || controlPlane.signedAckCalls != 1 || tunnelRuntime.ApplyCalls != 2 {
		t.Fatalf("migration calls register=%d legacy=%d/%d signed=%d/%d apply=%d", controlPlane.registerCalls, controlPlane.legacyCalls, controlPlane.legacyAckCalls, controlPlane.signedCalls, controlPlane.signedAckCalls, tunnelRuntime.ApplyCalls)
	}
}

func newSignedJoiner(t *testing.T, controlPlane *signedControlPlaneFixture, tunnelRuntime overlayruntime.Interface, contract usecase.ConfigContract) (*usecase.Joiner, *state.Store) {
	t.Helper()
	store := state.NewStore(t.TempDir())
	joiner := usecase.NewJoiner(controlPlane, store, tunnelRuntime).
		WithKeyGenerator(fixedKeys).
		WithClock(func() time.Time { return time.Date(2026, 8, 27, 12, 15, 0, 0, time.UTC) }).
		WithConfigContract(contract)
	return joiner, store
}

func signedJoinRequest() usecase.JoinRequest {
	return usecase.JoinRequest{Server: "https://accounts.example", DeviceID: "dev_laptop", DeviceName: "Laptop", Platform: "linux", Hostname: "laptop"}
}

func validSignedContract(t *testing.T) (signedconfig.Config, signedconfig.SigningKeys) {
	t.Helper()
	privateKey := signedTestPrivateKey()
	notAfter := signedconfig.CanonicalTime{Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	config := signedconfig.Config{
		SchemaVersion: signedconfig.SchemaVersionV1, ConfigID: "cfg_42", NetworkID: "net_private", DeviceID: "dev_laptop", Generation: 42,
		IssuedAt:  signedconfig.CanonicalTime{Time: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)},
		ExpiresAt: signedconfig.CanonicalTime{Time: time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)},
		ProxyCore: signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{Kind: signedconfig.TransportVLESS, Loopback: signedconfig.Endpoint{Host: signedconfig.LoopbackHost, Port: 51830}, Remote: signedconfig.RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "gateway.example.net"}, AuthID: "11111111-1111-1111-1111-111111111111"},
		WireGuard: signedconfig.WireGuard{InterfaceName: "wg-xco", Addresses: []string{"10.77.0.10/32"}, MTU: 1280, Peers: []signedconfig.Peer{{GatewayID: "gw_tokyo_01", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.77.0.0/16"}, Endpoint: signedconfig.Endpoint{Host: signedconfig.LoopbackHost, Port: 51830}, PersistentKeepaliveSeconds: 25}}},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "signing_key_01"},
	}
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	config.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	keys := signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{
		KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Status: "current",
		NotBefore: signedconfig.CanonicalTime{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}, NotAfter: &notAfter,
	}}}
	return config, keys
}

func resignSignedConfig(t *testing.T, config *signedconfig.Config) {
	t.Helper()
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	config.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(signedTestPrivateKey(), payload))
}

func signedTestPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}
