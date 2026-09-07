package fault

import "errors"

const (
	CodeInvalidInput              = "invalid_input"
	CodeStateIO                   = "state_io"
	CodeStateConflict             = "state_conflict"
	CodeAuthenticationFailed      = "authentication_failed"
	CodeAccessDenied              = "access_denied"
	CodeControlPlaneRejected      = "controlplane_rejected"
	CodeControlPlaneUnavailable   = "controlplane_unavailable"
	CodeInvalidResponse           = "invalid_response"
	CodeInvalidConfig             = "invalid_config"
	CodeInvalidSignedConfig       = "invalid_signed_config"
	CodeInvalidSigningKeys        = "invalid_signing_keys"
	CodeInvalidSignature          = "invalid_signature"
	CodeSigningKeyUnknown         = "signing_key_unknown"
	CodeSigningKeyWindow          = "signing_key_window"
	CodeSignedConfigExpired       = "signed_config_expired"
	CodeSignedConfigFuture        = "signed_config_future"
	CodeSignedConfigUnavailable   = "signed_config_unavailable"
	CodeConfigReplay              = "config_replay_detected"
	CodeConfigDowngradeBlocked    = "config_downgrade_blocked"
	CodeJoinInviteInvalid         = "join_invite_invalid"
	CodeJoinConstraint            = "join_constraint_mismatch"
	CodeJoinRateLimited           = "join_rate_limited"
	CodeEnrollmentExpired         = "enrollment_expired"
	CodeEnrollmentUnavailable     = "enrollment_session_unavailable"
	CodeUnsupportedRuntimeCore    = "unsupported_runtime_core"
	CodeRuntimeUnavailable        = "runtime_unavailable"
	CodeRuntimeDependency         = "runtime_dependency_missing"
	CodeRuntimePermission         = "runtime_permission_denied"
	CodeRuntimeApplyFailed        = "runtime_apply_failed"
	CodeRuntimeProcessStale       = "runtime_process_stale"
	CodeRuntimeRollbackFailed     = "runtime_rollback_failed"
	CodeRuntimeStatusFailed       = "runtime_status_failed"
	CodeNotJoined                 = "not_joined"
	CodeOperationInProgress       = "operation_in_progress"
	CodeDeviceLifecyclePending    = "device_lifecycle_contract_pending"
	CodePolicyInvalid             = "policy_artifact_invalid"
	CodePolicyExpired             = "policy_artifact_expired"
	CodePolicyReplay              = "policy_generation_replay"
	CodeCredentialInvalid         = "device_credential_invalid"
	CodeCredentialMissing         = "device_credential_missing"
	CodeCredentialExpired         = "device_credential_expired"
	CodeCredentialStorage         = "device_credential_storage_unavailable"
	CodeCredentialRotationPending = "device_credential_rotation_pending"
	CodeDeviceSessionInvalid      = "device_session_invalid"
)

// Error exposes a stable code while deliberately withholding the wrapped
// cause from user-facing output. Callers may inspect the cause with errors.Is.
type Error struct {
	code  string
	op    string
	cause error
}

func New(code, operation string, cause error) *Error {
	return &Error{code: code, op: operation, cause: cause}
}

func (e *Error) Error() string {
	if e.op == "" {
		return e.code
	}
	return e.op + ": " + e.code
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Code() string { return e.code }

func Code(err error) string {
	var coded interface{ Code() string }
	if errors.As(err, &coded) {
		return coded.Code()
	}
	return CodeInvalidResponse
}
