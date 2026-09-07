//go:build darwin && !ios

package credential

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type fakeKeychainCommand struct {
	value []byte
	calls [][]string
	stdin [][]byte
}

func (f *fakeKeychainCommand) Run(_ context.Context, arguments []string, stdin []byte) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), arguments...))
	f.stdin = append(f.stdin, append([]byte(nil), stdin...))
	switch arguments[0] {
	case "add-generic-password":
		f.value = bytes.TrimSpace(append([]byte(nil), stdin...))
		return nil, nil
	case "find-generic-password":
		if f.value == nil {
			return nil, errors.New("missing")
		}
		return append(append([]byte(nil), f.value...), '\n'), nil
	case "delete-generic-password":
		if f.value == nil {
			return nil, errors.New("missing")
		}
		f.value = nil
		return nil, nil
	default:
		return nil, errors.New("unexpected")
	}
}

func TestKeychainStoreUsesStdinAndNeverArgvForSecret(t *testing.T) {
	command := &fakeKeychainCommand{}
	store := &KeychainStore{account: "test-account", command: command}
	record := validRecord(t)
	if err := store.Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(command.calls) != 1 || command.calls[0][len(command.calls[0])-1] != "-w" {
		t.Fatalf("arguments=%v", command.calls)
	}
	for _, argument := range command.calls[0] {
		if bytes.Contains([]byte(argument), []byte(record.Credential)) {
			t.Fatal("credential leaked in argv")
		}
	}
	if !bytes.Contains(command.stdin[0], []byte(record.Credential)) {
		t.Fatal("credential was not delivered through stdin")
	}
	loaded, err := store.Load(t.Context())
	if err != nil || loaded.CredentialID != record.CredentialID {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	if err := store.Delete(t.Context()); err != nil {
		t.Fatal(err)
	}
}
