//go:build (linux && !android) || (darwin && !ios)

package credential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreIsPrivateAtomicAndRejectsSymlink(t *testing.T) {
	store := NewFileStore(t.TempDir())
	record := validRecord(t)
	if err := store.Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file=%v err=%v", info, err)
	}
	directory, err := os.Stat(filepath.Dir(store.Path()))
	if err != nil || directory.Mode().Perm() != 0o700 {
		t.Fatalf("directory=%v err=%v", directory, err)
	}
	loaded, err := store.Load(t.Context())
	if err != nil || loaded.Credential != record.Credential {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}

	if err := store.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load after delete: %v", err)
	}
	target := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.Path()); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context()); err == nil {
		t.Fatal("symlink credential deleted")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
		t.Fatalf("target changed raw=%q err=%v", raw, err)
	}
}

func TestFileStoreRejectsUnknownAndTrailingJSON(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if err := store.Save(t.Context(), validRecord(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range [][]byte{
		append(raw[:len(raw)-2], []byte(`,"token":"secret"}\n`)...),
		append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		if err := os.WriteFile(store.Path(), unsafe, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(t.Context()); err == nil {
			t.Fatal("unsafe credential JSON accepted")
		}
	}
}
