//go:build ios || android || (!linux && !darwin && !windows)

package credential

func NewPlatformStore(string) Store {
	return NewProtectedStore("mobile_protected_credential_host_required", nil)
}
