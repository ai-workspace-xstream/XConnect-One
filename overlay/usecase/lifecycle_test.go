// Modified for XConnect-One: standalone module imports.
package usecase_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

type fakeDeviceLifecycle struct {
	mu    sync.Mutex
	calls int
	err   error
}

type fakeDurableRevoke struct {
	calls int
	err   error
	nonce string
}

func (f *fakeDurableRevoke) RevokeDevice(_ context.Context, record credential.Record, request controlplane.DeviceRevokeRequest, _ time.Time) (controlplane.DeviceRevokeResponse, error) {
	f.calls++
	f.nonce = request.ClientNonce
	if f.err != nil {
		return controlplane.DeviceRevokeResponse{}, f.err
	}
	revokedAt := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	return controlplane.DeviceRevokeResponse{Revoked: true, Duplicate: f.calls > 1, Device: controlplane.LifecycleDevice{ID: record.DeviceID, NetworkID: record.NetworkID, Status: "revoked", RevokedAt: &revokedAt}}, nil
}

func (f *fakeDeviceLifecycle) RevokeDevice(_ context.Context, _ usecase.DeviceLifecycleRequest) (usecase.DeviceLifecycleResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return usecase.DeviceLifecycleResponse{}, f.err
	}
	return usecase.DeviceLifecycleResponse{Revoked: true, Duplicate: f.calls > 1}, nil
}

func lifecycleLastKnown() state.LastKnown {
	config := validConfig()
	return state.LastKnown{
		Server: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private",
		WireGuardPrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		WireGuardPublicKey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Phase:               state.PhaseAcknowledged, Config: config, ConfigContract: string(usecase.ConfigContractSigned),
		SignedConfigID: "cfg_42", SignedGeneration: 42,
	}
}

func TestCachedUpIsDisabledAndUnhealthyDownDelegatesCleanup(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	backend := &runtime.Fake{StatusResult: runtime.Status{Available: true}}
	if _, err := usecase.Up(t.Context(), store, backend); fault.Code(err) != fault.CodeConfigDowngradeBlocked || backend.ApplyCalls != 0 {
		t.Fatalf("cached up must require sync: %v", err)
	}
	if _, err := usecase.Down(t.Context(), store, backend); err != nil || backend.DownCalls != 1 {
		t.Fatalf("unhealthy cleanup: calls=%d err=%v", backend.DownCalls, err)
	}
}

func TestLeaveRequiresStableServerContractUnlessExplicitLocalOnly(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &runtime.Fake{}
	if _, err := usecase.Leave(t.Context(), store, runtimeFake, nil, false); fault.Code(err) != fault.CodeDeviceLifecyclePending {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
	if runtimeFake.DownCalls != 0 || runtimeFake.CleanupCalls != 0 {
		t.Fatal("local state changed before revocation contract")
	}
	result, err := usecase.Leave(t.Context(), store, runtimeFake, nil, true)
	if err != nil || !result.LocalOnly || runtimeFake.DownCalls != 1 || runtimeFake.CleanupCalls != 1 {
		t.Fatalf("leave=%#v err=%v", result, err)
	}
	if _, err := store.LoadLastKnown(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("state remains: %v", err)
	}
	repeat, err := usecase.Leave(t.Context(), store, runtimeFake, nil, true)
	if err != nil || !repeat.AlreadyInState {
		t.Fatalf("repeat=%#v err=%v", repeat, err)
	}
}

func TestDefaultLeaveNeverClaimsRemoteRevocationWithoutDurableCredential(t *testing.T) {
	store := state.NewStore(t.TempDir())
	result, err := usecase.Leave(t.Context(), store, &runtime.Fake{}, nil, false)
	if fault.Code(err) != fault.CodeDeviceLifecyclePending || result.State != "" {
		t.Fatalf("leave=%#v code=%q err=%v", result, fault.Code(err), err)
	}
}

func TestLeaveDoesNotClearStateWhenRuntimeCleanupFails(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &runtime.Fake{CleanupError: fault.New(fault.CodeRuntimeApplyFailed, "cleanup", nil)}
	_, err := usecase.Leave(t.Context(), store, runtimeFake, nil, true)
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
	if _, loadErr := store.LoadLastKnown(); loadErr != nil {
		t.Fatalf("state cleared after failure: %v", loadErr)
	}
}

func TestLeaveRetriesIdempotentRevocationAfterRuntimeInterruption(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	revoker := &fakeDeviceLifecycle{}
	runtimeFake := &runtime.Fake{DownError: fault.New(fault.CodeRuntimeApplyFailed, "down", nil)}
	if _, err := usecase.Leave(t.Context(), store, runtimeFake, revoker, false); fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("first leave code=%q err=%v", fault.Code(err), err)
	}
	if revoker.calls != 1 {
		t.Fatalf("revoke calls=%d", revoker.calls)
	}
	runtimeFake.DownError = nil
	result, err := usecase.Leave(t.Context(), store, runtimeFake, revoker, false)
	if err != nil || result.State != "left" || revoker.calls != 2 {
		t.Fatalf("retry=%#v err=%v revoke=%d", result, err, revoker.calls)
	}
}

func TestDownAndStatusRecoverOwnedRuntimeWithoutLastKnownState(t *testing.T) {
	store := state.NewStore(t.TempDir())
	runtimeFake := &runtime.Fake{StatusResult: runtime.Status{
		Available: true, Applied: true, Revision: "revision-orphan",
		CoreID: "xray", AdapterID: "xray-core",
	}}
	status, err := usecase.Status(t.Context(), store, runtimeFake)
	if err != nil || status.Joined || !status.Runtime.Applied || status.Generations.RuntimeRevision != "revision-orphan" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	result, err := usecase.Down(t.Context(), store, runtimeFake)
	if err != nil || result.AlreadyInState || runtimeFake.DownCalls != 1 {
		t.Fatalf("down=%#v err=%v calls=%d", result, err, runtimeFake.DownCalls)
	}
}

func TestLocalLeaveClearsInterruptedJoinWithoutClaimingServerRevocation(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.SaveCheckpoint(state.Checkpoint{Server: "https://accounts.example", DeviceID: "dev_partial", Phase: state.PhaseDeviceRegistered}); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &runtime.Fake{}
	if _, err := usecase.Leave(t.Context(), store, runtimeFake, nil, false); fault.Code(err) != fault.CodeDeviceLifecyclePending {
		t.Fatalf("default leave code=%q err=%v", fault.Code(err), err)
	}
	if _, err := store.LoadCheckpoint(); err != nil {
		t.Fatalf("default leave removed partial state: %v", err)
	}
	result, err := usecase.Leave(t.Context(), store, runtimeFake, nil, true)
	if err != nil || !result.LocalOnly || result.AlreadyInState {
		t.Fatalf("local leave=%#v err=%v", result, err)
	}
	if _, err := store.LoadCheckpoint(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("checkpoint remains: %v", err)
	}
	repeat, err := usecase.Leave(t.Context(), store, runtimeFake, nil, true)
	if err != nil || !repeat.AlreadyInState {
		t.Fatalf("repeat=%#v err=%v", repeat, err)
	}
}

func TestDurableLeaveCommitsRemoteBeforeCleanupAndResumesWithoutSecondRevoke(t *testing.T) {
	stateStore := state.NewStore(t.TempDir())
	lastKnown := lifecycleLastKnown()
	if err := stateStore.SaveLastKnown(lastKnown); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, newSignedControlPlaneFixture(t).keys, now)); err != nil {
		t.Fatal(err)
	}
	revoker := &fakeDurableRevoke{}
	runtimeFake := &runtime.Fake{StatusResult: runtime.Status{Available: true, Applied: true, Revision: lastKnown.Config.Revision, CoreID: "xray", AdapterID: "xray-core"}, DownError: fault.New(fault.CodeRuntimeApplyFailed, "down failed", nil)}
	if _, err := usecase.LeaveWithDeviceCredential(t.Context(), stateStore, runtimeFake, credentials, revoker, false); fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("first leave code=%q err=%v", fault.Code(err), err)
	}
	operation, err := stateStore.LoadDeviceOperation()
	if err != nil || !operation.RemoteCommitted || operation.ClientNonce != revoker.nonce || revoker.calls != 1 {
		t.Fatalf("operation=%#v calls=%d err=%v", operation, revoker.calls, err)
	}
	if _, err := credentials.Load(t.Context()); err != nil {
		t.Fatalf("credential removed before local cleanup: %v", err)
	}
	runtimeFake.DownError = nil
	result, err := usecase.LeaveWithDeviceCredential(t.Context(), stateStore, runtimeFake, credentials, revoker, false)
	if err != nil || result.State != "left" || revoker.calls != 1 {
		t.Fatalf("resume=%#v calls=%d err=%v", result, revoker.calls, err)
	}
	if _, err := credentials.Load(t.Context()); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("credential remains: %v", err)
	}
	if _, err := stateStore.LoadLastKnown(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("last known remains: %v", err)
	}
}

func TestDurableLeaveFailsClosedWhenCredentialMissing(t *testing.T) {
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &runtime.Fake{StatusResult: runtime.Status{Available: true, Applied: true}}
	_, err := usecase.LeaveWithDeviceCredential(t.Context(), stateStore, runtimeFake, &credential.MemoryStore{}, &fakeDurableRevoke{}, false)
	if fault.Code(err) != fault.CodeCredentialMissing || runtimeFake.DownCalls != 0 || runtimeFake.CleanupCalls != 0 {
		t.Fatalf("code=%q down=%d cleanup=%d err=%v", fault.Code(err), runtimeFake.DownCalls, runtimeFake.CleanupCalls, err)
	}
}

func TestLocalOnlyLeaveDeletesDurableCredentialWithoutRemoteClaim(t *testing.T) {
	stateStore := state.NewStore(t.TempDir())
	if err := stateStore.SaveLastKnown(lifecycleLastKnown()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	credentials := &credential.MemoryStore{}
	if err := credentials.Save(t.Context(), durableRecord(t, newSignedControlPlaneFixture(t).keys, now)); err != nil {
		t.Fatal(err)
	}
	runtimeFake := &runtime.Fake{StatusResult: runtime.Status{Available: true, Applied: true, Revision: lifecycleLastKnown().Config.Revision}}
	result, err := usecase.LeaveWithDeviceCredential(t.Context(), stateStore, runtimeFake, credentials, nil, true)
	if err != nil || !result.LocalOnly {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := credentials.Load(t.Context()); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("credential remains: %v", err)
	}
}
