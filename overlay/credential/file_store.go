// Modified for XConnect-One: standalone module imports.
//go:build (linux && !android) || (darwin && !ios)

package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

type FileStore struct{ path string }

func NewFileStore(stateDirectory string) *FileStore {
	return &FileStore{path: filepath.Join(stateDirectory, "protected", "device-credential.json")}
}

func (s *FileStore) Backend() string { return "linux-0600-file" }

func (s *FileStore) Path() string { return s.path }

func (s *FileStore) Load(context.Context) (Record, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil || !privateOwnedRegular(info) {
		return Record{}, fault.New(fault.CodeCredentialStorage, "validate device credential file", nil)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "open device credential file", nil)
	}
	defer file.Close()
	const maximumRecordSize = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maximumRecordSize+1))
	if err != nil || len(raw) > maximumRecordSize {
		return Record{}, fault.New(fault.CodeCredentialStorage, "read device credential file", nil)
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode device credential file", nil)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode device credential file", nil)
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *FileStore) Save(_ context.Context, record Record) error {
	record.SchemaVersion = SchemaVersion
	if err := record.Validate(); err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := ensurePrivateOwnedDirectory(directory); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "encode device credential file", nil)
	}
	temporary, err := os.CreateTemp(directory, ".device-credential-*")
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "create device credential file", nil)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fault.New(fault.CodeCredentialStorage, "secure device credential file", nil)
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		return fault.New(fault.CodeCredentialStorage, "write device credential file", nil)
	}
	if err := temporary.Sync(); err != nil {
		return fault.New(fault.CodeCredentialStorage, "sync device credential file", nil)
	}
	if err := temporary.Close(); err != nil {
		return fault.New(fault.CodeCredentialStorage, "close device credential file", nil)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fault.New(fault.CodeCredentialStorage, "commit device credential file", nil)
	}
	committed = true
	return nil
}

func (s *FileStore) Delete(context.Context) error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !privateOwnedRegular(info) {
		return fault.New(fault.CodeCredentialStorage, "validate device credential deletion", nil)
	}
	if err := os.Remove(s.path); err != nil {
		return fault.New(fault.CodeCredentialStorage, "delete device credential", nil)
	}
	return nil
}

func ensurePrivateOwnedDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fault.New(fault.CodeCredentialStorage, "create device credential directory", nil)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return fault.New(fault.CodeCredentialStorage, "validate device credential directory", nil)
	}
	return nil
}

func privateOwnedRegular(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && ownedByCurrentUser(info)
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
