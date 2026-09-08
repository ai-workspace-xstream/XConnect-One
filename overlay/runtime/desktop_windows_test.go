//go:build windows

package runtime

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsWireGuardServiceArgsUseOfficialTunnelServiceCLI(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "wg-xco.conf")
	up, tunnelName, err := windowsWireGuardServiceArgs("up", configPath)
	if err != nil {
		t.Fatalf("up args: %v", err)
	}
	if tunnelName != "wg-xco" || !reflect.DeepEqual(up, []string{"/installtunnelservice", configPath}) {
		t.Fatalf("up=%#v tunnel=%q", up, tunnelName)
	}
	down, tunnelName, err := windowsWireGuardServiceArgs("down", configPath)
	if err != nil {
		t.Fatalf("down args: %v", err)
	}
	if tunnelName != "wg-xco" || !reflect.DeepEqual(down, []string{"/uninstalltunnelservice", "wg-xco"}) {
		t.Fatalf("down=%#v tunnel=%q", down, tunnelName)
	}
}

func TestWindowsWireGuardServiceArgsRejectUnsafeTunnelNames(t *testing.T) {
	for _, path := range []string{
		filepath.Join(t.TempDir(), "wg-xco.conf.dpapi"),
		filepath.Join(t.TempDir(), "bad name.conf"),
		filepath.Join(t.TempDir(), "abcdefghijklmnop.conf"),
	} {
		if _, _, err := windowsWireGuardServiceArgs("up", path); err == nil {
			t.Fatalf("accepted unsafe WireGuard config path %q", path)
		}
	}
}

func TestWindowsPrivateRuntimeSDDLIsProtectedAndAdministratorBound(t *testing.T) {
	if windowsPrivateRuntimeSDDL != "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)" {
		t.Fatalf("unexpected runtime SDDL %q", windowsPrivateRuntimeSDDL)
	}
}

func TestMatchesWindowsPrivateDACL(t *testing.T) {
	owner := "S-1-5-21-100-200-300-1001"
	valid := "O:" + owner + "G:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + owner + ")"
	if !matchesWindowsPrivateDACL(valid) {
		t.Fatal("expected protected DACL with only SYSTEM, Administrators, and owner access to be trusted")
	}
	if matchesWindowsPrivateDACL("O:" + owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)") {
		t.Fatal("world-readable DACL must not be trusted")
	}
	if !strings.Contains(valid, owner) {
		t.Fatal("test descriptor must contain the owner SID")
	}
}

func TestWindowsPrivateACLReadbackIsTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("write runtime artifact: %v", err)
	}
	if err := setWindowsPrivateACL(path); err != nil {
		t.Fatalf("set private ACL: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read private ACL: %v", err)
	}
	if !hasWindowsPrivateACL(path) {
		t.Fatalf("private ACL readback was not trusted: %q", descriptor.String())
	}
}
