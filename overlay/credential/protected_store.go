// Modified for XConnect-One: standalone module imports.
package credential

import (
	"context"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

// ProtectedHostIPC is implemented by the owning platform host. Mobile
// callers must cross this boundary to Keychain/Keystore; Dart preferences and
// direct Flutter filesystem persistence are not implementations of this API.
type ProtectedHostIPC interface {
	LoadDeviceCredential(context.Context) (Record, error)
	SaveDeviceCredential(context.Context, Record) error
	DeleteDeviceCredential(context.Context) error
}

type ProtectedStore struct {
	boundary string
	ipc      ProtectedHostIPC
}

func NewProtectedStore(boundary string, ipc ProtectedHostIPC) *ProtectedStore {
	return &ProtectedStore{boundary: boundary, ipc: ipc}
}

func (s *ProtectedStore) Backend() string { return s.boundary }

func (s *ProtectedStore) Load(ctx context.Context) (Record, error) {
	if s.ipc == nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "load protected device credential", nil)
	}
	return s.ipc.LoadDeviceCredential(ctx)
}

func (s *ProtectedStore) Save(ctx context.Context, record Record) error {
	if s.ipc == nil {
		return fault.New(fault.CodeCredentialStorage, "save protected device credential", nil)
	}
	if err := record.Validate(); err != nil {
		return err
	}
	return s.ipc.SaveDeviceCredential(ctx, record)
}

func (s *ProtectedStore) Delete(ctx context.Context) error {
	if s.ipc == nil {
		return fault.New(fault.CodeCredentialStorage, "delete protected device credential", nil)
	}
	return s.ipc.DeleteDeviceCredential(ctx)
}
