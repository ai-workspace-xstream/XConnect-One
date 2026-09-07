package runtime

import (
	"errors"
	"strings"
	"testing"
)

func TestStartRefusesExistingOrUninspectableInterface(t *testing.T) {
	for _, inspectionError := range []error{nil, errors.New("inspection denied")} {
		backend := newFakeDesktopBackend()
		backend.interfaceIndex = 99
		backend.interfaceError = inspectionError
		tunnel := newDesktop(t.TempDir(), backend)
		if _, err := tunnel.Apply(t.Context(), desktopApplyRequest("collision")); err == nil {
			t.Fatal("accepted existing interface")
		}
		if len(backend.starts) != 0 || strings.Contains(strings.Join(backend.runs, "\n"), "wg-quick") {
			t.Fatal("touched existing interface")
		}
	}
}

func TestFailedWireGuardUpNeverRunsBlindDown(t *testing.T) {
	backend := newFakeDesktopBackend()
	backend.runErrorContains["wg-quick up"] = []error{errors.New("name collision after preflight")}
	tunnel := newDesktop(t.TempDir(), backend)
	if _, err := tunnel.Apply(t.Context(), desktopApplyRequest("race")); err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(strings.Join(backend.runs, "\n"), "wg-quick down") {
		t.Fatal("blind cleanup after failed up")
	}
}

func TestDownCleansOwnedInterfaceAfterXrayDeathOrListenerLoss(t *testing.T) {
	for _, dead := range []bool{true, false} {
		backend := newFakeDesktopBackend()
		tunnel := newDesktop(t.TempDir(), backend)
		if _, err := tunnel.Apply(t.Context(), desktopApplyRequest("unhealthy")); err != nil {
			t.Fatal(err)
		}
		manifest, err := tunnel.loadManifest(tunnel.activeManifestPath())
		if err != nil {
			t.Fatal(err)
		}
		backend.portOwned = false
		if dead {
			backend.alive[manifest.Xray.PID] = false
		}
		status, err := tunnel.Status(t.Context())
		if err != nil || status.Applied {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		if err := tunnel.Down(t.Context()); err != nil {
			t.Fatal(err)
		}
		if backend.interfaceIndex != 0 {
			t.Fatal("owned WireGuard interface remained")
		}
		if err := tunnel.Down(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDownRefusesSameNameReplacement(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnel := newDesktop(t.TempDir(), backend)
	if _, err := tunnel.Apply(t.Context(), desktopApplyRequest("replaced")); err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex = 99
	backend.runs = nil
	diagnostics, err := tunnel.Diagnose(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == "wireguard_interface_healthy" && diagnostic.Healthy {
			t.Fatal("replacement interface reported healthy")
		}
	}
	if err := tunnel.Down(t.Context()); err == nil {
		t.Fatal("accepted replacement")
	}
	if strings.Contains(strings.Join(backend.runs, "\n"), "wg-quick down") {
		t.Fatal("deleted replacement")
	}
}
