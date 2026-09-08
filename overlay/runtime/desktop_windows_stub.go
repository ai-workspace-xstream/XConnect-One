//go:build !windows

package runtime

// NewWindowsDesktop preserves the protected-host boundary when this package
// is compiled on a non-Windows host. A native Windows build supplies the
// external tunnel-service implementation.
func NewWindowsDesktop(string) Interface {
	return NewProtectedHost("windows_service_host_required", nil)
}
