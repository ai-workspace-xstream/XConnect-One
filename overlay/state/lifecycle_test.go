// Modified for XConnect-One: standalone module imports.
package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestOperationLockSerializesFreshOwner(t *testing.T) {
	store := NewStore(t.TempDir())
	first, err := store.AcquireOperation(t.Context(), "join")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireOperation(t.Context(), "down"); fault.Code(err) != fault.CodeOperationInProgress {
		t.Fatalf("second lock code=%q err=%v", fault.Code(err), err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestOperationLockRecoversVerifiedStaleOwner(t *testing.T) {
	store := NewStore(t.TempDir())
	stalePath := filepath.Join(store.Directory(), ".operation-lock")
	if err := os.Mkdir(stalePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON0600(filepath.Join(stalePath, "owner.json"), operationOwner{SchemaVersion: SchemaVersion, Token: "old", Operation: "up", StartedAt: time.Now().UTC().Add(-staleOperationAge - time.Second)}); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.AcquireOperation(t.Context(), "leave")
	if err != nil {
		t.Fatalf("recover stale lock: %v", err)
	}
	if err := recovered.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestOperationLockProtectsMissingOwnerInitializationWindow(t *testing.T) {
	store := NewStore(t.TempDir())
	lockPath := filepath.Join(store.Directory(), ".operation-lock")
	if err := os.MkdirAll(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireOperation(t.Context(), "join"); fault.Code(err) != fault.CodeOperationInProgress {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
}

func TestOperationLockFutureOwnerCannotExtendBeyondDirectoryStaleness(t *testing.T) {
	store := NewStore(t.TempDir())
	lockPath := filepath.Join(store.Directory(), ".operation-lock")
	if err := os.MkdirAll(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON0600(filepath.Join(lockPath, "owner.json"), operationOwner{SchemaVersion: SchemaVersion, Token: "future", Operation: "join", StartedAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireOperation(t.Context(), "down"); fault.Code(err) != fault.CodeOperationInProgress {
		t.Fatalf("fresh future owner code=%q err=%v", fault.Code(err), err)
	}
	stale := time.Now().Add(-staleOperationAge - time.Second)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.AcquireOperation(t.Context(), "leave")
	if err != nil {
		t.Fatalf("recover future owner after directory staleness: %v", err)
	}
	if err := recovered.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestClearOwnedStateRetainsUnknownFilesAndRejectsSymlinks(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := writeJSON0600(store.PolicyStatePath(), PolicyState{SchemaVersion: SchemaVersion, NetworkID: "net", Generation: 1, Digest: "digest", ExpiresAt: time.Now().UTC().Add(time.Hour), AcceptedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(store.Directory(), "user-file.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := store.ClearOwnedState()
	if err != nil || !result.Retained {
		t.Fatalf("cleanup=%#v err=%v", result, err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown file removed: %v", err)
	}
	if err := os.Symlink(unknown, store.LastKnownPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClearOwnedState(); fault.Code(err) != fault.CodeStateIO {
		t.Fatalf("symlink cleanup code=%q err=%v", fault.Code(err), err)
	}
	if _, err := os.Lstat(store.LastKnownPath()); errors.Is(err, os.ErrNotExist) {
		t.Fatal("symlink was removed")
	}
}
