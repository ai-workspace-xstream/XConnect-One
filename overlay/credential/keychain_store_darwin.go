// Modified for XConnect-One: standalone module imports.
//go:build darwin && !ios

package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const keychainService = "plus.svc.xconnect.one.device-session"

type keychainCommand interface {
	Run(context.Context, []string, []byte) ([]byte, error)
}

type osKeychainCommand struct{}

func (osKeychainCommand) Run(ctx context.Context, arguments []string, stdin []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/security", arguments...)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &bytes.Buffer{}
	if err := command.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

type KeychainStore struct {
	account string
	command keychainCommand
}

func NewKeychainStore(stateDirectory string) *KeychainStore {
	sum := sha256.Sum256([]byte(stateDirectory))
	return &KeychainStore{account: "state-" + hex.EncodeToString(sum[:16]), command: osKeychainCommand{}}
}

func (s *KeychainStore) Backend() string { return "macos-keychain" }

func (s *KeychainStore) Load(ctx context.Context) (Record, error) {
	raw, err := s.command.Run(ctx, []string{"find-generic-password", "-a", s.account, "-s", keychainService, "-w"}, nil)
	if err != nil {
		return Record{}, ErrNotFound
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode Keychain device credential", nil)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode Keychain device credential", nil)
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *KeychainStore) Save(ctx context.Context, record Record) error {
	record.SchemaVersion = SchemaVersion
	if err := record.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "encode Keychain device credential", nil)
	}
	// Passing -w as the final option makes `security` read the password from
	// stdin, keeping the credential out of argv and process listings.
	arguments := []string{"add-generic-password", "-a", s.account, "-s", keychainService, "-U", "-w"}
	if _, err := s.command.Run(ctx, arguments, append(raw, '\n')); err != nil {
		return fault.New(fault.CodeCredentialStorage, "save Keychain device credential", nil)
	}
	return nil
}

func (s *KeychainStore) Delete(ctx context.Context) error {
	_, err := s.command.Run(ctx, []string{"delete-generic-password", "-a", s.account, "-s", keychainService}, nil)
	if err != nil && !strings.Contains(err.Error(), "could not be found") {
		// Command output is deliberately discarded, and no raw credential is an
		// argument. Treat an absent item as idempotent through a read probe.
		if _, loadErr := s.Load(ctx); !errors.Is(loadErr, ErrNotFound) {
			return fault.New(fault.CodeCredentialStorage, "delete Keychain device credential", nil)
		}
	}
	return nil
}
