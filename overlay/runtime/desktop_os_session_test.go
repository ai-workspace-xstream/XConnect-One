//go:build linux || darwin

package runtime

import "testing"

func TestExternalRuntimeStartsInDetachedSession(t *testing.T) {
	attributes := detachedProcessAttributes()
	if attributes == nil || !attributes.Setsid || attributes.Setpgid {
		t.Fatalf("external runtime must start in a detached session: %#v", attributes)
	}
}
