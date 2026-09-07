// Modified for XConnect-One: standalone module imports.
package credential

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

type Store interface {
	Load(context.Context) (Record, error)
	Save(context.Context, Record) error
	Delete(context.Context) error
	Backend() string
}

type MemoryStore struct {
	mu        sync.Mutex
	record    *Record
	SaveErr   error
	LoadErr   error
	DeleteErr error
}

func (s *MemoryStore) Backend() string { return "memory-test" }

func (s *MemoryStore) Load(context.Context) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LoadErr != nil {
		return Record{}, s.LoadErr
	}
	if s.record == nil {
		return Record{}, ErrNotFound
	}
	return clone(*s.record)
}

func (s *MemoryStore) Save(_ context.Context, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SaveErr != nil {
		return s.SaveErr
	}
	if err := record.Validate(); err != nil {
		return err
	}
	copy, err := clone(record)
	if err != nil {
		return err
	}
	s.record = &copy
	return nil
}

func (s *MemoryStore) Delete(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DeleteErr != nil {
		return s.DeleteErr
	}
	s.record = nil
	return nil
}

func clone(record Record) (Record, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "copy device credential", nil)
	}
	var result Record
	if err := json.Unmarshal(raw, &result); err != nil {
		return Record{}, fault.New(fault.CodeCredentialStorage, "copy device credential", nil)
	}
	return result, nil
}
