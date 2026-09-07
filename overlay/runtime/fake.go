package runtime

import (
	"context"
	"sync"
)

type Fake struct {
	mu sync.Mutex

	ApplyError    error
	StatusError   error
	DiagnoseError error
	DownError     error
	CleanupError  error
	StatusResult  Status
	Diagnostics   []Diagnostic

	ApplyCalls    int
	StatusCalls   int
	DiagnoseCalls int
	DownCalls     int
	CleanupCalls  int
	LastApply     ApplyRequest
}

func (f *Fake) Down(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DownCalls++
	if f.DownError != nil {
		return f.DownError
	}
	f.StatusResult.Applied = false
	return nil
}

func (f *Fake) Cleanup(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CleanupCalls++
	return f.CleanupError
}

func (f *Fake) Apply(_ context.Context, request ApplyRequest) (ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ApplyCalls++
	f.LastApply = request
	if f.ApplyError != nil {
		return ApplyResult{}, f.ApplyError
	}
	f.StatusResult = Status{
		Available: true,
		Applied:   true,
		Revision:  request.Config.Revision,
		CoreID:    request.Config.CoreID(),
		AdapterID: request.Config.AdapterID(),
	}
	return ApplyResult{
		Revision:  request.Config.Revision,
		CoreID:    request.Config.CoreID(),
		AdapterID: request.Config.AdapterID(),
	}, nil
}

func (f *Fake) Status(_ context.Context) (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.StatusCalls++
	return f.StatusResult, f.StatusError
}

func (f *Fake) Diagnose(_ context.Context) ([]Diagnostic, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DiagnoseCalls++
	return append([]Diagnostic(nil), f.Diagnostics...), f.DiagnoseError
}
