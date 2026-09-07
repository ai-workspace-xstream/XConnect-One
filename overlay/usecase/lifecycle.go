// Modified for XConnect-One: disable cached up and clean unhealthy owned runtimes.
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type DeviceLifecycleRequest struct {
	Controller string
	DeviceID   string
	NetworkID  string
}

type DeviceLifecycleResponse struct {
	Revoked   bool
	Duplicate bool
}

// DeviceLifecycleControlPlane intentionally has no HTTP path in the client.
// Accounts Batch 07 owns that contract; the CLI wires an implementation only
// after its versioned route and response become canonical.
type DeviceLifecycleControlPlane interface {
	RevokeDevice(context.Context, DeviceLifecycleRequest) (DeviceLifecycleResponse, error)
}

type DurableRevokeControlPlane interface {
	RevokeDevice(context.Context, credential.Record, controlplane.DeviceRevokeRequest, time.Time) (controlplane.DeviceRevokeResponse, error)
}

type LifecycleResult struct {
	State                  string   `json:"state"`
	DeviceID               string   `json:"device_id,omitempty"`
	NetworkID              string   `json:"network_id,omitempty"`
	Revision               string   `json:"revision,omitempty"`
	AlreadyInState         bool     `json:"already_in_state"`
	LocalOnly              bool     `json:"local_only,omitempty"`
	Removed                []string `json:"removed,omitempty"`
	RetainedFiles          bool     `json:"retained_unknown_files,omitempty"`
	PolicyReconcilePending bool     `json:"policy_reconcile_pending,omitempty"`
}

// Up intentionally refuses cached configuration: compiled state omits signed
// expiry and may predate an active revision whose ACK failed. Sync revalidates.
func Up(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) (LifecycleResult, error) {
	return LifecycleResult{}, fault.New(fault.CodeConfigDowngradeBlocked, "cached up disabled; run sync to verify and start the tunnel", nil)
}

func Down(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) (LifecycleResult, error) {
	lock, err := store.AcquireOperation(ctx, "down")
	if err != nil {
		return LifecycleResult{}, err
	}
	defer lock.Release()
	lastKnown, err := store.LoadLastKnown()
	statePresent := err == nil
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return LifecycleResult{}, err
	}
	result := LifecycleResult{State: "down"}
	if statePresent {
		result = lifecycleResult("down", lastKnown)
	}
	status, err := tunnelRuntime.Status(ctx)
	if err != nil {
		return LifecycleResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read runtime status", err)
	}
	// Unhealthy is not stopped: owned WireGuard routes can survive Xray failure.
	// Always let the lifecycle backend inspect its trusted ownership metadata.
	result.AlreadyInState = !status.Applied && status.Revision == "" && !statePresent
	if !status.Available {
		return LifecycleResult{}, fault.New(fault.CodeRuntimeUnavailable, "stop overlay runtime", nil)
	}
	lifecycle, ok := tunnelRuntime.(runtime.Lifecycle)
	if !ok {
		return LifecycleResult{}, fault.New(fault.CodeRuntimeUnavailable, "stop overlay runtime", nil)
	}
	if err := lifecycle.Down(ctx); err != nil {
		return LifecycleResult{}, err
	}
	return result, nil
}

func Leave(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, deviceLifecycle DeviceLifecycleControlPlane, localOnly bool) (LifecycleResult, error) {
	lock, err := store.AcquireOperation(ctx, "leave")
	if err != nil {
		return LifecycleResult{}, err
	}
	defer lock.Release()
	if !localOnly && deviceLifecycle == nil {
		return LifecycleResult{}, fault.New(fault.CodeDeviceLifecyclePending, "revoke overlay device", nil)
	}
	lastKnown, err := store.LoadLastKnown()
	if errors.Is(err, state.ErrNotFound) {
		return leaveWithoutLastKnown(ctx, store, tunnelRuntime, localOnly)
	}
	if err != nil {
		return LifecycleResult{}, err
	}
	if !localOnly {
		response, revokeErr := deviceLifecycle.RevokeDevice(ctx, DeviceLifecycleRequest{Controller: lastKnown.Server, DeviceID: lastKnown.DeviceID, NetworkID: lastKnown.NetworkID})
		if revokeErr != nil {
			return LifecycleResult{}, revokeErr
		}
		if !response.Revoked {
			return LifecycleResult{}, fault.New(fault.CodeInvalidResponse, "validate device revocation", nil)
		}
	}
	lifecycle, ok := tunnelRuntime.(runtime.Lifecycle)
	if !ok {
		return LifecycleResult{}, fault.New(fault.CodeRuntimeUnavailable, "leave overlay runtime", nil)
	}
	if err := lifecycle.Down(ctx); err != nil {
		return LifecycleResult{}, err
	}
	if err := lifecycle.Cleanup(ctx); err != nil {
		return LifecycleResult{}, err
	}
	cleaned, err := store.ClearOwnedState()
	if err != nil {
		return LifecycleResult{}, err
	}
	result := lifecycleResult("left", lastKnown)
	result.LocalOnly = localOnly
	result.Removed = append([]string(nil), cleaned.Removed...)
	result.RetainedFiles = cleaned.Retained
	return result, nil
}

// LeaveWithDeviceCredential is the durable device-bound leave path. It keeps
// the credential and replay nonce until the server receipt and local runtime
// cleanup have both completed.
func LeaveWithDeviceCredential(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, credentials credential.Store, controlPlane DurableRevokeControlPlane, localOnly bool) (LifecycleResult, error) {
	lock, err := store.AcquireOperation(ctx, "leave")
	if err != nil {
		return LifecycleResult{}, err
	}
	defer lock.Release()

	lastKnown, lastErr := store.LoadLastKnown()
	statePresent := lastErr == nil
	if lastErr != nil && !errors.Is(lastErr, state.ErrNotFound) {
		return LifecycleResult{}, lastErr
	}
	var record credential.Record
	credentialPresent := false
	if credentials != nil {
		record, err = credentials.Load(ctx)
		credentialPresent = err == nil
		if err != nil && !errors.Is(err, credential.ErrNotFound) {
			return LifecycleResult{}, err
		}
	}
	operation, operationErr := store.LoadDeviceOperation()
	operationPresent := operationErr == nil
	if operationErr != nil && !errors.Is(operationErr, state.ErrNotFound) {
		return LifecycleResult{}, operationErr
	}
	if !statePresent && !credentialPresent && !operationPresent {
		return LifecycleResult{State: "left", AlreadyInState: true, LocalOnly: localOnly}, nil
	}

	controller, deviceID, networkID := record.Controller, record.DeviceID, record.NetworkID
	if statePresent {
		if credentialPresent && (record.Controller != lastKnown.Server || record.DeviceID != lastKnown.DeviceID || record.NetworkID != lastKnown.NetworkID || record.WireGuardPublicKey != lastKnown.WireGuardPublicKey) {
			return LifecycleResult{}, fault.New(fault.CodeStateConflict, "validate leave credential binding", nil)
		}
		controller, deviceID, networkID = lastKnown.Server, lastKnown.DeviceID, lastKnown.NetworkID
	}
	if controller == "" && operationPresent {
		controller, deviceID, networkID = operation.Controller, operation.DeviceID, operation.NetworkID
	}
	if operationPresent && (operation.Controller != controller || operation.DeviceID != deviceID || operation.NetworkID != networkID) {
		return LifecycleResult{}, fault.New(fault.CodeStateConflict, "resume device leave", nil)
	}
	if !localOnly && !operation.RemoteCommitted {
		if !credentialPresent {
			return LifecycleResult{}, fault.New(fault.CodeCredentialMissing, "revoke overlay device", nil)
		}
		if record.Expired(time.Now().UTC()) {
			return LifecycleResult{}, fault.New(fault.CodeCredentialExpired, "revoke overlay device", nil)
		}
		if controlPlane == nil {
			return LifecycleResult{}, fault.New(fault.CodeDeviceLifecyclePending, "revoke overlay device", nil)
		}
		if !operationPresent {
			nonce, nonceErr := generateUUIDv4()
			if nonceErr != nil {
				return LifecycleResult{}, fault.New(fault.CodeStateIO, "create leave replay identity", nonceErr)
			}
			operation = state.DeviceOperation{Kind: "leave", Controller: controller, DeviceID: deviceID, NetworkID: networkID, ClientNonce: nonce, UpdatedAt: time.Now().UTC()}
			if err := store.SaveDeviceOperation(operation); err != nil {
				return LifecycleResult{}, err
			}
			operationPresent = true
		}
		response, revokeErr := controlPlane.RevokeDevice(ctx, record, controlplane.DeviceRevokeRequest{ClientNonce: operation.ClientNonce}, time.Now().UTC())
		if revokeErr != nil {
			return LifecycleResult{}, revokeErr
		}
		if !response.Revoked {
			return LifecycleResult{}, fault.New(fault.CodeInvalidResponse, "validate durable device revocation", nil)
		}
		operation.RemoteCommitted = true
		operation.PolicyReconcilePending = response.PolicyReconcilePending
		operation.UpdatedAt = time.Now().UTC()
		if err := store.SaveDeviceOperation(operation); err != nil {
			return LifecycleResult{}, err
		}
	}
	if err := cleanupOwnedRuntime(ctx, tunnelRuntime); err != nil {
		return LifecycleResult{}, err
	}
	if credentialPresent {
		if err := credentials.Delete(ctx); err != nil {
			return LifecycleResult{}, err
		}
	}
	cleaned, err := store.ClearOwnedState()
	if err != nil {
		return LifecycleResult{}, err
	}
	result := LifecycleResult{State: "left", DeviceID: deviceID, NetworkID: networkID, LocalOnly: localOnly, Removed: cleaned.Removed, RetainedFiles: cleaned.Retained, PolicyReconcilePending: operation.PolicyReconcilePending}
	if statePresent {
		result.Revision = lastKnown.Config.Revision
	}
	return result, nil
}

func cleanupOwnedRuntime(ctx context.Context, tunnelRuntime runtime.Interface) error {
	status, err := tunnelRuntime.Status(ctx)
	if err != nil {
		return fault.New(fault.CodeRuntimeStatusFailed, "read runtime before leave", err)
	}
	if !status.Applied && status.Revision == "" {
		return nil
	}
	lifecycle, ok := tunnelRuntime.(runtime.Lifecycle)
	if !ok || !status.Available {
		return fault.New(fault.CodeRuntimeUnavailable, "leave overlay runtime", nil)
	}
	if status.Applied {
		if err := lifecycle.Down(ctx); err != nil {
			return err
		}
	}
	return lifecycle.Cleanup(ctx)
}

func leaveWithoutLastKnown(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, localOnly bool) (LifecycleResult, error) {
	_, checkpointErr := store.LoadCheckpoint()
	partialState := checkpointErr == nil
	if checkpointErr != nil && !errors.Is(checkpointErr, state.ErrNotFound) {
		return LifecycleResult{}, checkpointErr
	}
	if !localOnly {
		if partialState {
			return LifecycleResult{}, fault.New(fault.CodeDeviceLifecyclePending, "revoke partial overlay enrollment", nil)
		}
		return LifecycleResult{State: "left", AlreadyInState: true}, nil
	}
	status, err := tunnelRuntime.Status(ctx)
	if err != nil {
		return LifecycleResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read runtime status", err)
	}
	if status.Applied || status.Revision != "" {
		lifecycle, ok := tunnelRuntime.(runtime.Lifecycle)
		if !ok {
			return LifecycleResult{}, fault.New(fault.CodeRuntimeUnavailable, "leave partial overlay runtime", nil)
		}
		if status.Applied {
			if err := lifecycle.Down(ctx); err != nil {
				return LifecycleResult{}, err
			}
		}
		if err := lifecycle.Cleanup(ctx); err != nil {
			return LifecycleResult{}, err
		}
	}
	cleaned, err := store.ClearOwnedState()
	if err != nil {
		return LifecycleResult{}, err
	}
	return LifecycleResult{State: "left", AlreadyInState: !partialState && len(cleaned.Removed) == 0, LocalOnly: true, Removed: cleaned.Removed, RetainedFiles: cleaned.Retained}, nil
}

func lifecycleResult(value string, lastKnown state.LastKnown) LifecycleResult {
	return LifecycleResult{State: value, DeviceID: lastKnown.DeviceID, NetworkID: lastKnown.NetworkID, Revision: lastKnown.Config.Revision}
}

func runtimeMatches(status runtime.Status, lastKnown state.LastKnown) bool {
	return status.Applied && status.Revision == lastKnown.Config.Revision && status.CoreID == model.CoreIDXray && model.SupportedAdapterID(status.AdapterID)
}
