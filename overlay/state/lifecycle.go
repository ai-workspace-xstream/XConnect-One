// Modified for XConnect-One: standalone module imports.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const staleOperationAge = 5 * time.Minute

var operationNoncePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type PolicyState struct {
	SchemaVersion int       `json:"schema_version"`
	NetworkID     string    `json:"network_id"`
	Generation    uint64    `json:"generation"`
	Digest        string    `json:"digest"`
	Revision      uint64    `json:"revision"`
	ExpiresAt     time.Time `json:"expires_at"`
	AcceptedAt    time.Time `json:"accepted_at"`
}

type DeviceOperation struct {
	SchemaVersion          int       `json:"schema_version"`
	Kind                   string    `json:"kind"`
	Controller             string    `json:"controller"`
	DeviceID               string    `json:"device_id"`
	NetworkID              string    `json:"network_id"`
	ClientNonce            string    `json:"client_nonce"`
	RemoteCommitted        bool      `json:"remote_committed"`
	PolicyReconcilePending bool      `json:"policy_reconcile_pending"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type operationOwner struct {
	SchemaVersion int       `json:"schema_version"`
	Token         string    `json:"token"`
	Operation     string    `json:"operation"`
	StartedAt     time.Time `json:"started_at"`
}

type OperationLock struct {
	path  string
	token string
}

type CleanupResult struct {
	Removed  []string `json:"removed"`
	Retained bool     `json:"retained_unknown_files"`
}

func (s *Store) PolicyStatePath() string { return filepath.Join(s.dir, "policy-state.json") }

func (s *Store) DeviceOperationPath() string { return filepath.Join(s.dir, "device-operation.json") }

func (s *Store) LoadDeviceOperation() (DeviceOperation, error) {
	var result DeviceOperation
	if err := readJSON(s.DeviceOperationPath(), &result); err != nil {
		return DeviceOperation{}, err
	}
	if err := validateDeviceOperation(result); err != nil {
		return DeviceOperation{}, err
	}
	return result, nil
}

func (s *Store) SaveDeviceOperation(result DeviceOperation) error {
	result.SchemaVersion = SchemaVersion
	if err := validateDeviceOperation(result); err != nil {
		return err
	}
	return writeJSON0600(s.DeviceOperationPath(), result)
}

func validateDeviceOperation(result DeviceOperation) error {
	if result.SchemaVersion != SchemaVersion || result.Kind != "leave" || result.Controller == "" || result.DeviceID == "" || result.NetworkID == "" || !operationNoncePattern.MatchString(result.ClientNonce) || result.UpdatedAt.IsZero() {
		return fault.New(fault.CodeStateIO, "validate device operation", nil)
	}
	return nil
}

func (s *Store) LoadPolicyState() (PolicyState, error) {
	var result PolicyState
	if err := readJSON(s.PolicyStatePath(), &result); err != nil {
		return PolicyState{}, err
	}
	if result.SchemaVersion != SchemaVersion || result.NetworkID == "" || result.Generation == 0 || result.Digest == "" || result.ExpiresAt.IsZero() || result.AcceptedAt.IsZero() {
		return PolicyState{}, fault.New(fault.CodeStateIO, "validate policy state", nil)
	}
	return result, nil
}

func (s *Store) SavePolicyState(result PolicyState) error {
	result.SchemaVersion = SchemaVersion
	if result.NetworkID == "" || result.Generation == 0 || result.Digest == "" || result.ExpiresAt.IsZero() || result.AcceptedAt.IsZero() {
		return fault.New(fault.CodeStateIO, "validate policy state", nil)
	}
	return writeJSON0600(s.PolicyStatePath(), result)
}

func (s *Store) AcquireOperation(ctx context.Context, operation string) (*OperationLock, error) {
	if operation == "" {
		return nil, fault.New(fault.CodeInvalidInput, "acquire operation lock", nil)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fault.New(fault.CodeStateIO, "create operation directory", err)
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return nil, fault.New(fault.CodeStateIO, "secure operation directory", err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, fault.New(fault.CodeStateIO, "create operation identity", err)
	}
	token := hex.EncodeToString(random)
	lockPath := filepath.Join(s.dir, ".operation-lock")
	for {
		if err := ctx.Err(); err != nil {
			return nil, fault.New(fault.CodeOperationInProgress, "wait for operation lock", nil)
		}
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			owner := operationOwner{SchemaVersion: SchemaVersion, Token: token, Operation: operation, StartedAt: time.Now().UTC()}
			if err := writeJSON0600(filepath.Join(lockPath, "owner.json"), owner); err != nil {
				_ = os.RemoveAll(lockPath)
				return nil, err
			}
			return &OperationLock{path: lockPath, token: token}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fault.New(fault.CodeStateIO, "create operation lock", err)
		}
		var owner operationOwner
		ownerErr := readJSON(filepath.Join(lockPath, "owner.json"), &owner)
		now := time.Now().UTC()
		ownerValid := ownerErr == nil && owner.SchemaVersion == SchemaVersion && owner.Token != "" && owner.Operation != "" && !owner.StartedAt.IsZero()
		if ownerValid && !owner.StartedAt.After(now.Add(30*time.Second)) {
			if owner.StartedAt.Add(staleOperationAge).After(now) {
				return nil, fault.New(fault.CodeOperationInProgress, "serialize overlay operation", nil)
			}
			// A verified stale owner is authoritative even if a test or recovery
			// tool has only just recreated its directory.
			ownerErr = nil
		} else {
			ownerErr = fault.New(fault.CodeStateIO, "validate operation owner", nil)
		}
		// A contender can observe the atomic directory before its owner file is
		// committed. Never steal a fresh directory merely because that tiny
		// initialization window produced ErrNotFound.
		if ownerErr != nil {
			if info, statErr := os.Stat(lockPath); statErr == nil && info.ModTime().Add(staleOperationAge).After(time.Now()) {
				return nil, fault.New(fault.CodeOperationInProgress, "serialize overlay operation", nil)
			}
		}
		stalePath := filepath.Join(s.dir, ".operation-lock-stale-"+token)
		if renameErr := os.Rename(lockPath, stalePath); renameErr != nil {
			if errors.Is(renameErr, os.ErrNotExist) {
				continue
			}
			return nil, fault.New(fault.CodeOperationInProgress, "recover operation lock", nil)
		}
		_ = os.RemoveAll(stalePath)
	}
}

func (l *OperationLock) Release() error {
	if l == nil || l.path == "" || l.token == "" {
		return nil
	}
	var owner operationOwner
	if err := readJSON(filepath.Join(l.path, "owner.json"), &owner); err != nil {
		return fault.New(fault.CodeStateConflict, "release operation lock", nil)
	}
	if owner.Token != l.token {
		return fault.New(fault.CodeStateConflict, "release operation lock", nil)
	}
	if err := os.Remove(filepath.Join(l.path, "owner.json")); err != nil {
		return fault.New(fault.CodeStateIO, "release operation lock", err)
	}
	if err := os.Remove(l.path); err != nil {
		return fault.New(fault.CodeStateIO, "release operation lock", err)
	}
	l.path = ""
	return nil
}

func (s *Store) ClearOwnedState() (CleanupResult, error) {
	paths := []string{
		s.CheckpointPath(),
		s.LastKnownPath(),
		s.ContractStatePath(),
		s.SigningKeyCachePath(),
		s.EnrollmentSecretPath(),
		s.PolicyStatePath(),
		s.DeviceOperationPath(),
	}
	result := CleanupResult{}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return CleanupResult{}, fault.New(fault.CodeStateIO, "validate owned state cleanup", err)
		}
		if err := os.Remove(path); err != nil {
			return CleanupResult{}, fault.New(fault.CodeStateIO, "remove owned state", err)
		}
		result.Removed = append(result.Removed, filepath.Base(path))
	}
	entries, err := os.ReadDir(s.dir)
	if err == nil {
		for _, entry := range entries {
			if entry.Name() != ".operation-lock" {
				result.Retained = true
				break
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CleanupResult{}, fault.New(fault.CodeStateIO, "inspect state cleanup", err)
	}
	return result, nil
}
