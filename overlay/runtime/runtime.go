// Modified for XConnect-One: standalone module imports.
package runtime

import (
	"context"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

type ApplyRequest struct {
	Config              model.Config
	WireGuardPrivateKey string
}

type ApplyResult struct {
	Revision  string
	CoreID    string
	AdapterID string
}

type Status struct {
	Available bool   `json:"available"`
	Applied   bool   `json:"applied"`
	Revision  string `json:"revision,omitempty"`
	CoreID    string `json:"core_id,omitempty"`
	AdapterID string `json:"adapter_id,omitempty"`
}

type Diagnostic struct {
	Code    string `json:"code"`
	Healthy bool   `json:"healthy"`
}

type Interface interface {
	Apply(context.Context, ApplyRequest) (ApplyResult, error)
	Status(context.Context) (Status, error)
	Diagnose(context.Context) ([]Diagnostic, error)
}

// Lifecycle is implemented only by runtimes that can safely stop and clean up
// resources they own. Callers fail closed when the selected platform host does
// not provide this contract.
type Lifecycle interface {
	Interface
	Down(context.Context) error
	Cleanup(context.Context) error
}

// ProtectedHostIPC is the narrow contract implemented by a privileged native
// host. The CLI never invokes shell networking on Apple, Windows, or mobile
// platforms; it can only request the owning System VPN/Service boundary.
type ProtectedHostIPC interface {
	Apply(context.Context, ApplyRequest) (ApplyResult, error)
	Down(context.Context) error
	Cleanup(context.Context) error
	Status(context.Context) (Status, error)
	Diagnose(context.Context) ([]Diagnostic, error)
}

type ProtectedHost struct {
	boundary string
	ipc      ProtectedHostIPC
}

func NewProtectedHost(boundary string, ipc ProtectedHostIPC) *ProtectedHost {
	return &ProtectedHost{boundary: boundary, ipc: ipc}
}

func (r *ProtectedHost) Apply(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	if r.ipc == nil {
		return ApplyResult{}, fault.New(fault.CodeRuntimeUnavailable, "request protected host runtime", nil)
	}
	return r.ipc.Apply(ctx, request)
}

func (r *ProtectedHost) Down(ctx context.Context) error {
	if r.ipc == nil {
		return fault.New(fault.CodeRuntimeUnavailable, "request protected host runtime", nil)
	}
	return r.ipc.Down(ctx)
}

func (r *ProtectedHost) Cleanup(ctx context.Context) error {
	if r.ipc == nil {
		return fault.New(fault.CodeRuntimeUnavailable, "request protected host runtime", nil)
	}
	return r.ipc.Cleanup(ctx)
}

func (r *ProtectedHost) Status(ctx context.Context) (Status, error) {
	if r.ipc == nil {
		return Status{Available: false}, nil
	}
	return r.ipc.Status(ctx)
}

func (r *ProtectedHost) Diagnose(ctx context.Context) ([]Diagnostic, error) {
	if r.ipc != nil {
		return r.ipc.Diagnose(ctx)
	}
	return []Diagnostic{
		{Code: "platform_runtime_available", Healthy: false},
		{Code: r.boundary, Healthy: true},
	}, nil
}

// Unavailable is the production-safe Batch 02 default. It prevents an
// enrollment-only CLI from acknowledging a config before a platform runtime
// has actually applied it.
type Unavailable struct {
	diagnostics []Diagnostic
}

func NewUnavailable() *Unavailable {
	return &Unavailable{diagnostics: []Diagnostic{{Code: "platform_runtime_available", Healthy: false}}}
}

// NewProtectedHostUnavailable represents a platform whose system networking
// must be supplied by a protected native host (for example Apple's Packet
// Tunnel extension), not by the external Linux command runtime.
func NewProtectedHostUnavailable() *Unavailable {
	return &Unavailable{diagnostics: []Diagnostic{
		{Code: "platform_runtime_available", Healthy: false},
		{Code: "protected_host_runtime_required", Healthy: true},
	}}
}

func (r *Unavailable) Apply(context.Context, ApplyRequest) (ApplyResult, error) {
	return ApplyResult{}, fault.New(fault.CodeRuntimeUnavailable, "apply runtime profile", nil)
}

func (r *Unavailable) Status(context.Context) (Status, error) {
	return Status{Available: false}, nil
}

func (r *Unavailable) Diagnose(context.Context) ([]Diagnostic, error) {
	return append([]Diagnostic(nil), r.diagnostics...), nil
}
