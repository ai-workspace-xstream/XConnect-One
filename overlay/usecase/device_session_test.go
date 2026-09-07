// Modified for XConnect-One: standalone module imports.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

func TestDeviceSyncMintsVerifiesAppliesAcknowledgesAndClearsBearer(t *testing.T) {
	controlPlane := newInviteControlPlaneFixture(t)
	now := controlPlane.config.IssuedAt.Time.Add(time.Minute)
	stateStore := state.NewStore(t.TempDir())
	lastKnown := lifecycleLastKnown()
	if err := stateStore.SaveLastKnown(lastKnown); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, controlPlane.keys, now)); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &overlayruntime.Fake{}
	manager := usecase.NewDeviceSessionManager(controlPlane, stateStore, credentials, runtimeFake).WithClock(func() time.Time { return now })
	result, err := manager.Sync(t.Context())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if result.Generation != controlPlane.config.Generation || controlPlane.deviceSessionCalls != 1 || controlPlane.enrollmentConfigCalls != 1 || controlPlane.enrollmentAckCalls != 1 || runtimeFake.ApplyCalls != 1 {
		t.Fatalf("result=%#v mint=%d config=%d ack=%d apply=%d", result, controlPlane.deviceSessionCalls, controlPlane.enrollmentConfigCalls, controlPlane.enrollmentAckCalls, runtimeFake.ApplyCalls)
	}
	if _, err := os.Stat(stateStore.EnrollmentSecretPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("short bearer remains: %v", err)
	}
	if _, err := credentials.Load(t.Context()); err != nil {
		t.Fatalf("durable credential was removed: %v", err)
	}
}

func TestDeviceSyncRuntimeOrAckFailureDoesNotLoseCredentialOrReapply(t *testing.T) {
	controlPlane := newInviteControlPlaneFixture(t)
	now := controlPlane.config.IssuedAt.Time.Add(time.Minute)
	controlPlane.enrollmentAckErrors = []error{fault.New(fault.CodeControlPlaneUnavailable, "ack interrupted", nil), nil}
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, controlPlane.keys, now)); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &overlayruntime.Fake{}
	manager := usecase.NewDeviceSessionManager(controlPlane, stateStore, credentials, runtimeFake).WithClock(func() time.Time { return now })
	if _, err := manager.Sync(t.Context()); fault.Code(err) != fault.CodeControlPlaneUnavailable {
		t.Fatalf("first sync code=%q err=%v", fault.Code(err), err)
	}
	activeRevision := runtimeFake.StatusResult.Revision
	if _, err := usecase.Up(t.Context(), stateStore, runtimeFake); fault.Code(err) != fault.CodeConfigDowngradeBlocked {
		t.Fatalf("cached up allowed after ACK failure: %v", err)
	}
	if runtimeFake.ApplyCalls != 1 || runtimeFake.StatusResult.Revision != activeRevision {
		t.Fatal("cached up downgraded active runtime after ACK failure")
	}
	if _, err := manager.Sync(t.Context()); err != nil {
		t.Fatalf("resume sync: %v", err)
	}
	if runtimeFake.ApplyCalls != 1 || controlPlane.deviceSessionCalls != 1 || controlPlane.enrollmentAckCalls != 2 {
		t.Fatalf("apply=%d mint=%d ack=%d", runtimeFake.ApplyCalls, controlPlane.deviceSessionCalls, controlPlane.enrollmentAckCalls)
	}
	if _, err := credentials.Load(t.Context()); err != nil {
		t.Fatalf("credential lost: %v", err)
	}
}

func TestDeviceSyncFailedConfigCannotPoisonDurableSigningKeys(t *testing.T) {
	controlPlane := newInviteControlPlaneFixture(t)
	now := controlPlane.config.IssuedAt.Time.Add(time.Minute)
	previousUntil := signedconfig.CanonicalTime{Time: now.Add(24 * time.Hour)}
	old := controlPlane.keys.Keys[0]
	old.Status = "previous"
	old.NotAfter = &previousUntil
	controlPlane.sessionKeys = []signedconfig.SigningKey{old, {
		KeyID: "signing_key_untrusted", Algorithm: signedconfig.SignatureEd25519, PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", Status: "current", NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)},
	}}
	controlPlane.enrollmentConfigError = fault.New(fault.CodeControlPlaneUnavailable, "config unavailable", nil)
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	original := durableRecord(t, controlPlane.keys, now)
	if err := credentials.Save(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	manager := usecase.NewDeviceSessionManager(controlPlane, stateStore, credentials, &overlayruntime.Fake{}).WithClock(func() time.Time { return now })
	if _, err := manager.Sync(t.Context()); fault.Code(err) != fault.CodeControlPlaneUnavailable {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
	stored, err := credentials.Load(t.Context())
	if err != nil || !reflect.DeepEqual(stored.SigningKeys, original.SigningKeys) {
		t.Fatalf("durable trust changed on failed config: stored=%#v original=%#v err=%v", stored.SigningKeys, original.SigningKeys, err)
	}
}

func TestDeviceSyncV2StagesPolicyBeforeRuntimeAndPersistsFloor(t *testing.T) {
	base := newInviteControlPlaneFixture(t)
	policyRaw, digest := v2PolicyArtifact(t)
	controlPlane := &v2DeviceControlPlane{inviteControlPlaneFixture: base, policyRaw: policyRaw, policyDigest: digest}
	now := base.config.IssuedAt.Time.Add(time.Minute)
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, base.keys, now)); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &overlayruntime.Fake{}
	manager := usecase.NewDeviceSessionManager(controlPlane, stateStore, credentials, runtimeFake).WithClock(func() time.Time { return now }).WithSignedConfigV2()
	if _, err := manager.Sync(t.Context()); err != nil {
		t.Fatalf("v2 sync: %v", err)
	}
	policyState, err := stateStore.LoadPolicyState()
	if err != nil || policyState.Generation != 9 || policyState.Digest != digest {
		t.Fatalf("policy state=%#v err=%v", policyState, err)
	}
	if controlPlane.v2Calls != 1 || controlPlane.policyCalls != 1 || runtimeFake.ApplyCalls != 1 {
		t.Fatalf("v2=%d policy=%d apply=%d", controlPlane.v2Calls, controlPlane.policyCalls, runtimeFake.ApplyCalls)
	}
}

func TestDeviceSyncV2RejectsPolicyBeforeRuntimeOrFloorMutation(t *testing.T) {
	base := newInviteControlPlaneFixture(t)
	controlPlane := &v2DeviceControlPlane{inviteControlPlaneFixture: base, policyRaw: []byte(`{"schema_version":1}`), policyDigest: v2PolicyDigest}
	now := base.config.IssuedAt.Time.Add(time.Minute)
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, base.keys, now)); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &overlayruntime.Fake{}
	manager := usecase.NewDeviceSessionManager(controlPlane, stateStore, credentials, runtimeFake).WithClock(func() time.Time { return now }).WithSignedConfigV2()
	if _, err := manager.Sync(t.Context()); fault.Code(err) != fault.CodePolicyInvalid {
		t.Fatalf("policy error=%q err=%v", fault.Code(err), err)
	}
	if runtimeFake.ApplyCalls != 0 {
		t.Fatalf("runtime applied before policy validation: %d", runtimeFake.ApplyCalls)
	}
	if _, err := stateStore.LoadContractState(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("config floor advanced on rejected policy: %v", err)
	}
}

const v2PolicyDigest = "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c"

type v2DeviceControlPlane struct {
	*inviteControlPlaneFixture
	policyRaw    []byte
	policyDigest string
	v2Calls      int
	policyCalls  int
}

func (f *v2DeviceControlPlane) GetEnrollmentSignedConfigV2(_ context.Context, enrollmentToken string, _ controlplane.SignedConfigRequest) (signedconfig.Config, error) {
	f.v2Calls++
	if len(f.enrollmentTokens) == 0 || enrollmentToken != f.enrollmentTokens[len(f.enrollmentTokens)-1] {
		return signedconfig.Config{}, fault.New(fault.CodeEnrollmentExpired, "invalid enrollment", nil)
	}
	config := f.config
	config.SchemaVersion = signedconfig.SchemaVersionV2
	config.Policy = &signedconfig.Policy{Generation: 9, Digest: f.policyDigest, Path: signedconfig.PolicyPath(9, f.policyDigest), MediaType: signedconfig.PolicyMediaType}
	payload, err := config.SigningBytes()
	if err != nil {
		return signedconfig.Config{}, err
	}
	config.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(signedTestPrivateKey(), payload))
	return config, nil
}

func (f *v2DeviceControlPlane) GetEnrollmentPolicyArtifact(_ context.Context, _ string, _ signedconfig.Policy) ([]byte, error) {
	f.policyCalls++
	return append([]byte(nil), f.policyRaw...), nil
}

func v2PolicyArtifact(t *testing.T) ([]byte, string) {
	t.Helper()
	raw := []byte(`{"schema_version":1,"compiler_version":"xconnect-acl-v1alpha1.1","network_id":"net_private","revision":7,"default_action":"deny","protected_flows":["control:controller-session","control:gateway-apply-result","control:gateway-heartbeat","control:gateway-policy-artifact","control:gateway-snapshot"],"rules":[]}`)
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestDeviceCredentialRotationPersistsPendingAndRecoversLostResponse(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	controlPlane := newInviteControlPlaneFixture(t)
	controlPlane.rotateErrors = []error{fault.New(fault.CodeControlPlaneUnavailable, "response lost", nil)}
	credentials := &credential.MemoryStore{}
	original := durableRecord(t, controlPlane.keys, now)
	if err := credentials.Save(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	manager := usecase.NewDeviceSessionManager(controlPlane, state.NewStore(t.TempDir()), credentials, &overlayruntime.Fake{}).WithClock(func() time.Time { return now })
	if _, err := manager.Rotate(t.Context()); fault.Code(err) != fault.CodeControlPlaneUnavailable {
		t.Fatalf("lost response code=%q err=%v", fault.Code(err), err)
	}
	pending, err := credentials.Load(t.Context())
	if err != nil || pending.Pending == nil || pending.CredentialID != original.CredentialID {
		t.Fatalf("pending=%#v err=%v", pending.Pending, err)
	}
	result, err := manager.Rotate(t.Context())
	if err != nil || !result.Recovered || result.CredentialID != pending.Pending.CredentialID {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	promoted, err := credentials.Load(t.Context())
	if err != nil || promoted.Pending != nil || promoted.CredentialID != result.CredentialID {
		t.Fatalf("promoted=%#v err=%v", promoted, err)
	}
	if strings.Contains(result.CredentialID, promoted.Credential) {
		t.Fatal("rotation output exposed raw credential")
	}
}

func TestStatusAndDiagnoseExposeMetadataWithoutCredentialSecret(t *testing.T) {
	controlPlane := newInviteControlPlaneFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	record := durableRecord(t, controlPlane.keys, now)
	if err := credentials.Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &overlayruntime.Fake{}
	status, err := usecase.StatusWithCredential(t.Context(), stateStore, runtimeFake, credentials)
	if err != nil || !status.Credential.Present || status.Credential.CredentialID != record.CredentialID {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	diagnostics, err := usecase.DiagnoseWithCredential(t.Context(), stateStore, runtimeFake, credentials)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	raw, _ := json.Marshal(struct {
		Status      usecase.StatusResult       `json:"status"`
		Diagnostics []usecase.DiagnosticResult `json:"diagnostics"`
	}{status, diagnostics})
	if bytes.Contains(raw, []byte(record.Credential)) {
		t.Fatalf("metadata leaked protected credential: %s", raw)
	}
}

func durableRecord(t *testing.T, keys signedconfig.SigningKeys, now time.Time) credential.Record {
	t.Helper()
	secret, err := credential.GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x33}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	return credential.Record{
		SchemaVersion: credential.SchemaVersion, Controller: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux",
		WireGuardPublicKey: lifecycleLastKnown().WireGuardPublicKey, CredentialID: secret.CredentialID, Credential: secret.Value,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * 24 * time.Hour), Scope: []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke}, SigningKeys: keys,
	}
}
