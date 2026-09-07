// Modified for XConnect-One: standalone module imports.
//go:build windows

package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unsafe"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"golang.org/x/sys/windows"
)

const (
	credentialTypeGeneric         = 1
	credentialPersistLocalMachine = 2
	maximumCredentialBlob         = 5 * 512
)

var (
	advapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procCredWriteW  = advapi32.NewProc("CredWriteW")
	procCredReadW   = advapi32.NewProc("CredReadW")
	procCredDeleteW = advapi32.NewProc("CredDeleteW")
	procCredFree    = advapi32.NewProc("CredFree")
)

type windowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type WindowsStore struct{ target string }

func NewWindowsStore(stateDirectory string) *WindowsStore {
	sum := sha256.Sum256([]byte(stateDirectory))
	return &WindowsStore{target: "XConnect-One/device-session/" + hex.EncodeToString(sum[:16])}
}

func NewPlatformStore(stateDirectory string) Store { return NewWindowsStore(stateDirectory) }

func (s *WindowsStore) Backend() string { return "windows-credential-manager" }

func (s *WindowsStore) Save(_ context.Context, record Record) error {
	record.SchemaVersion = SchemaVersion
	if err := record.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) == 0 || len(raw) > maximumCredentialBlob {
		return fault.New(fault.CodeCredentialStorage, "encode Credential Manager device credential", nil)
	}
	target, err := windows.UTF16PtrFromString(s.target)
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "address Credential Manager device credential", nil)
	}
	username, _ := windows.UTF16PtrFromString("XConnect-One")
	credential := windowsCredential{
		Type: credentialTypeGeneric, TargetName: target, UserName: username,
		CredentialBlobSize: uint32(len(raw)), CredentialBlob: &raw[0], Persist: credentialPersistLocalMachine,
	}
	result, _, _ := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0)
	if result == 0 {
		return fault.New(fault.CodeCredentialStorage, "save Credential Manager device credential", nil)
	}
	return nil
}

func (s *WindowsStore) Load(context.Context) (Record, error) {
	target, err := windows.UTF16PtrFromString(s.target)
	if err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "address Credential Manager device credential", nil)
	}
	var credential *windowsCredential
	result, _, callErr := procCredReadW.Call(uintptr(unsafe.Pointer(target)), credentialTypeGeneric, 0, uintptr(unsafe.Pointer(&credential)))
	if result == 0 {
		if errors.Is(callErr, windows.ERROR_NOT_FOUND) {
			return Record{}, ErrNotFound
		}
		return Record{}, fault.New(fault.CodeCredentialStorage, "load Credential Manager device credential", nil)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credential)))
	if credential == nil || credential.CredentialBlob == nil || credential.CredentialBlobSize == 0 || credential.CredentialBlobSize > maximumCredentialBlob {
		return Record{}, fault.New(fault.CodeCredentialStorage, "validate Credential Manager device credential", nil)
	}
	raw := append([]byte(nil), unsafe.Slice(credential.CredentialBlob, credential.CredentialBlobSize)...)
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode Credential Manager device credential", nil)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, fault.New(fault.CodeCredentialStorage, "decode Credential Manager device credential", nil)
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *WindowsStore) Delete(context.Context) error {
	target, err := windows.UTF16PtrFromString(s.target)
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "address Credential Manager device credential", nil)
	}
	result, _, callErr := procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), credentialTypeGeneric, 0)
	if result == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return fault.New(fault.CodeCredentialStorage, "delete Credential Manager device credential", nil)
	}
	return nil
}
