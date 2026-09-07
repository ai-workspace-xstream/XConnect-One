// Modified for XConnect-One: standalone module imports.
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

type StatusResult struct {
	Joined      bool             `json:"joined"`
	DeviceID    string           `json:"device_id,omitempty"`
	NetworkID   string           `json:"network_id,omitempty"`
	Revision    string           `json:"revision,omitempty"`
	Generations GenerationStatus `json:"generations"`
	Runtime     runtime.Status   `json:"runtime"`
	Credential  CredentialStatus `json:"credential"`
}

type CredentialStatus struct {
	Backend      string    `json:"backend"`
	Present      bool      `json:"present"`
	CredentialID string    `json:"credential_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Expired      bool      `json:"expired"`
	RotationDue  bool      `json:"rotation_due"`
	Pending      bool      `json:"rotation_pending"`
}

type GenerationStatus struct {
	State           uint64 `json:"state"`
	RuntimeRevision string `json:"runtime_revision,omitempty"`
	Policy          uint64 `json:"policy"`
	PolicyExpired   bool   `json:"policy_expired"`
}

type DiagnosticResult struct {
	Code       string `json:"code"`
	Healthy    bool   `json:"healthy"`
	Generation uint64 `json:"generation,omitempty"`
	Revision   string `json:"revision,omitempty"`
}

func Status(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) (StatusResult, error) {
	return StatusWithCredential(ctx, store, tunnelRuntime, nil)
}

func StatusWithCredential(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, credentials credential.Store) (StatusResult, error) {
	lastKnown, err := store.LoadLastKnown()
	statePresent := err == nil
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return StatusResult{}, err
	}
	runtimeStatus, err := tunnelRuntime.Status(ctx)
	if err != nil {
		return StatusResult{}, fault.New(fault.CodeRuntimeStatusFailed, "read runtime status", err)
	}
	credentialStatus, err := inspectCredential(ctx, credentials, time.Now().UTC())
	if err != nil {
		return StatusResult{}, err
	}
	generations := GenerationStatus{State: lastKnown.SignedGeneration, RuntimeRevision: runtimeStatus.Revision}
	if !statePresent {
		return StatusResult{Generations: generations, Runtime: runtimeStatus, Credential: credentialStatus}, nil
	}
	policyState, policyErr := store.LoadPolicyState()
	if policyErr == nil && policyState.NetworkID == lastKnown.NetworkID {
		generations.Policy = policyState.Generation
		generations.PolicyExpired = !policyState.ExpiresAt.After(time.Now().UTC())
	} else if policyErr != nil && !errors.Is(policyErr, state.ErrNotFound) {
		return StatusResult{}, policyErr
	}
	return StatusResult{
		Joined: lastKnown.Phase == state.PhaseAcknowledged &&
			runtimeStatus.Applied &&
			runtimeStatus.Revision == lastKnown.Config.Revision &&
			runtimeStatus.CoreID == model.CoreIDXray &&
			model.SupportedAdapterID(runtimeStatus.AdapterID),
		DeviceID:    lastKnown.DeviceID,
		NetworkID:   lastKnown.NetworkID,
		Revision:    lastKnown.Config.Revision,
		Generations: generations,
		Runtime:     runtimeStatus,
		Credential:  credentialStatus,
	}, nil
}

func Diagnose(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface) ([]DiagnosticResult, error) {
	return DiagnoseWithCredential(ctx, store, tunnelRuntime, nil)
}

func DiagnoseWithCredential(ctx context.Context, store *state.Store, tunnelRuntime runtime.Interface, credentials credential.Store) ([]DiagnosticResult, error) {
	results := make([]DiagnosticResult, 0, 6)
	lastKnown, err := store.LoadLastKnown()
	statePresent := err == nil
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}
	results = append(results, DiagnosticResult{Code: "last_known_state_present", Healthy: statePresent})
	if statePresent {
		results = append(results,
			DiagnosticResult{Code: "state_file_permissions_0600", Healthy: state.ValidatePermissions(store.LastKnownPath(), 0o600) == nil},
			DiagnosticResult{Code: "proxy_core_xray", Healthy: lastKnown.Config.CoreID() == model.CoreIDXray},
			DiagnosticResult{Code: "state_generation", Healthy: lastKnown.SignedGeneration > 0 || lastKnown.ConfigContract == string(ConfigContractLegacy), Generation: lastKnown.SignedGeneration},
		)
	}
	runtimeDiagnostics, err := tunnelRuntime.Diagnose(ctx)
	if err != nil {
		return nil, fault.New(fault.CodeRuntimeStatusFailed, "diagnose runtime", err)
	}
	for _, item := range runtimeDiagnostics {
		results = append(results, DiagnosticResult{Code: item.Code, Healthy: item.Healthy})
	}
	runtimeStatus, statusErr := tunnelRuntime.Status(ctx)
	if statusErr != nil {
		return nil, fault.New(fault.CodeRuntimeStatusFailed, "diagnose runtime generation", statusErr)
	}
	results = append(results, DiagnosticResult{Code: "runtime_revision", Healthy: runtimeStatus.Revision != "", Revision: runtimeStatus.Revision})
	credentialStatus, credentialErr := inspectCredential(ctx, credentials, time.Now().UTC())
	if credentialErr != nil {
		return nil, credentialErr
	}
	results = append(results,
		DiagnosticResult{Code: "credential_storage_available", Healthy: credentials != nil},
		DiagnosticResult{Code: "device_credential_present", Healthy: credentialStatus.Present},
		DiagnosticResult{Code: "device_credential_not_expired", Healthy: credentialStatus.Present && !credentialStatus.Expired},
	)
	policyState, policyErr := store.LoadPolicyState()
	if errors.Is(policyErr, state.ErrNotFound) {
		results = append(results, DiagnosticResult{Code: "policy_generation", Healthy: false})
	} else if policyErr != nil {
		return nil, policyErr
	} else {
		healthy := statePresent && policyState.NetworkID == lastKnown.NetworkID && policyState.ExpiresAt.After(time.Now().UTC())
		results = append(results, DiagnosticResult{Code: "policy_generation", Healthy: healthy, Generation: policyState.Generation})
	}
	return results, nil
}

func inspectCredential(ctx context.Context, credentials credential.Store, now time.Time) (CredentialStatus, error) {
	if credentials == nil {
		return CredentialStatus{Backend: "unavailable"}, nil
	}
	result := CredentialStatus{Backend: credentials.Backend()}
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return CredentialStatus{}, err
	}
	result.Present = true
	result.CredentialID = record.CredentialID
	result.ExpiresAt = record.ExpiresAt
	result.Expired = record.Expired(now)
	result.RotationDue = record.RotationDue(now)
	result.Pending = record.Pending != nil
	return result, nil
}
