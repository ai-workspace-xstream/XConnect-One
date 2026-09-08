// Modified for XConnect-One: standalone module imports.
package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

type fakeDesktopBackend struct {
	paths            map[string]string
	privileged       bool
	runErrors        map[string][]error
	runErrorContains map[string][]error
	ownedErrors      []error
	portAvailable    bool
	portOwned        bool
	startError       error
	startAlive       bool
	nextPID          int
	alive            map[int]bool
	stale            map[int]bool
	runs             []string
	starts           []string
	stops            []int
	interfaceIndex   int
	interfaceError   error
}

func newFakeDesktopBackend() *fakeDesktopBackend {
	testRuntimeRoot := filepath.Join(os.TempDir(), "xconnect-runtime-test", "bin")
	return &fakeDesktopBackend{
		paths: map[string]string{
			"xray":     filepath.Join(testRuntimeRoot, "xray"),
			"wg":       filepath.Join(testRuntimeRoot, "wg"),
			"wg-quick": filepath.Join(testRuntimeRoot, "wg-quick"),
		},
		privileged:       true,
		runErrors:        make(map[string][]error),
		runErrorContains: make(map[string][]error),
		startAlive:       true,
		portAvailable:    true,
		portOwned:        true,
		nextPID:          100,
		alive:            make(map[int]bool),
		stale:            make(map[int]bool),
	}
}

func (f *fakeDesktopBackend) LookPath(name string) (string, error) {
	path, ok := f.paths[name]
	if !ok {
		return "", errors.New("missing " + name)
	}
	return path, nil
}

func (f *fakeDesktopBackend) Privileged() bool { return f.privileged }
func (f *fakeDesktopBackend) InterfaceIndex(string) (int, error) {
	return f.interfaceIndex, f.interfaceError
}

func (f *fakeDesktopBackend) Run(_ context.Context, name string, args ...string) error {
	key := filepath.Base(name) + " " + strings.Join(args, " ")
	f.runs = append(f.runs, key)
	if queued := f.runErrors[key]; len(queued) > 0 {
		err := queued[0]
		f.runErrors[key] = queued[1:]
		return err
	}
	for fragment, queued := range f.runErrorContains {
		if strings.Contains(key, fragment) && len(queued) > 0 {
			err := queued[0]
			f.runErrorContains[fragment] = queued[1:]
			return err
		}
	}
	if strings.HasPrefix(key, "wg-quick up ") {
		f.interfaceIndex = 42
	}
	if strings.HasPrefix(key, "wg-quick down ") {
		f.interfaceIndex = 0
	}
	return nil
}

func (f *fakeDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	f.starts = append(f.starts, filepath.Base(executable)+" "+strings.Join(args, " "))
	if f.startError != nil {
		return processIdentity{}, f.startError
	}
	f.nextPID++
	identity := processIdentity{
		PID:          f.nextPID,
		Executable:   executable,
		ConfigPath:   configArgument(args),
		ConfigSHA256: configDigest,
		Revision:     revision,
		StartToken:   fmt.Sprintf("start-%d", f.nextPID),
	}
	f.alive[identity.PID] = f.startAlive
	return identity, nil
}

func (f *fakeDesktopBackend) ProcessAlive(identity processIdentity) (bool, error) {
	if f.stale[identity.PID] {
		return false, errors.New("identity mismatch containing secret")
	}
	return f.alive[identity.PID], nil
}

func (f *fakeDesktopBackend) Stop(identity processIdentity) error {
	f.stops = append(f.stops, identity.PID)
	if f.stale[identity.PID] {
		return errors.New("refuse stale process")
	}
	f.alive[identity.PID] = false
	return nil
}

func (f *fakeDesktopBackend) LoopbackAvailable(string) (bool, error) {
	return f.portAvailable, nil
}

func (f *fakeDesktopBackend) LoopbackOwned(processIdentity, string) (bool, error) {
	if len(f.ownedErrors) == 0 {
		return f.portOwned, nil
	}
	err := f.ownedErrors[0]
	f.ownedErrors = f.ownedErrors[1:]
	return false, err
}

func TestDesktopApplyStartsVerifiedRuntimeAndSecuresArtifacts(t *testing.T) {
	backend := newFakeDesktopBackend()
	stateDirectory := t.TempDir()
	tunnelRuntime := newDesktop(stateDirectory, backend)
	request := desktopApplyRequest("revision-1")

	result, err := tunnelRuntime.Apply(t.Context(), request)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Revision != request.Config.Revision || result.CoreID != model.CoreIDXray || result.AdapterID != model.AdapterIDXrayCore {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(backend.starts) != 1 {
		t.Fatalf("Xray starts = %d, want 1", len(backend.starts))
	}
	joinedRuns := strings.Join(backend.runs, "\n")
	if !strings.Contains(joinedRuns, "xray run -test -config") || !strings.Contains(joinedRuns, "wg-quick up") || !strings.Contains(joinedRuns, "wg show wg-xco") {
		t.Fatalf("missing runtime verification commands:\n%s", joinedRuns)
	}
	manifest, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatalf("load active manifest: %v", err)
	}
	for _, path := range []string{manifest.XrayConfigPath, manifest.WGConfigPath, tunnelRuntime.activeManifestPath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !privateRegularFile(path) {
			t.Fatalf("%s permissions = %04o, want 0600", path, info.Mode().Perm())
		}
	}
	for _, path := range []string{tunnelRuntime.dir, filepath.Dir(manifest.XrayConfigPath)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !privateDirectory(path) {
			t.Fatalf("%s permissions = %04o, want 0700", path, info.Mode().Perm())
		}
	}
}

func TestDesktopApplyRejectsMissingDependenciesAndPermission(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(*fakeDesktopBackend)
		wantCode string
	}{
		{
			name: "missing dependency",
			prepare: func(backend *fakeDesktopBackend) {
				delete(backend.paths, "wg-quick")
			},
			wantCode: fault.CodeRuntimeDependency,
		},
		{
			name: "missing permission",
			prepare: func(backend *fakeDesktopBackend) {
				backend.privileged = false
			},
			wantCode: fault.CodeRuntimePermission,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeDesktopBackend()
			test.prepare(backend)
			tunnelRuntime := newDesktop(t.TempDir(), backend)
			_, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1"))
			if fault.Code(err) != test.wantCode {
				t.Fatalf("error code = %q, want %q, err=%v", fault.Code(err), test.wantCode, err)
			}
			if len(backend.starts) != 0 {
				t.Fatalf("runtime started before preflight: %v", backend.starts)
			}
		})
	}
}

func TestDesktopApplyXrayTestAndEarlyExitFailBeforeWireGuard(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*fakeDesktopBackend)
	}{
		{
			name: "xray config test fails",
			prepare: func(backend *fakeDesktopBackend) {
				backend.runErrorContains["xray run -test -config"] = []error{errors.New("bad config with UUID 11111111-1111-1111-1111-111111111111")}
			},
		},
		{
			name: "xray exits early",
			prepare: func(backend *fakeDesktopBackend) {
				backend.startAlive = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeDesktopBackend()
			tunnelRuntime := newDesktop(t.TempDir(), backend)
			request := desktopApplyRequest("revision-1")
			test.prepare(backend)
			_, err := tunnelRuntime.Apply(t.Context(), request)
			if fault.Code(err) != fault.CodeRuntimeApplyFailed {
				t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
			}
			if strings.Contains(err.Error(), request.Config.Transport.UUID) {
				t.Fatalf("error leaked UUID: %v", err)
			}
			if strings.Contains(strings.Join(backend.runs, "\n"), "wg-quick up") {
				t.Fatalf("WireGuard started after Xray failure: %v", backend.runs)
			}
		})
	}
}

func TestDesktopApplyRejectsOccupiedPortBeforeStartingXray(t *testing.T) {
	backend := newFakeDesktopBackend()
	backend.portAvailable = false
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	_, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1"))
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if len(backend.starts) != 0 {
		t.Fatalf("Xray started on an occupied port: %v", backend.starts)
	}
}

func TestDesktopApplyReadinessHasInternalTimeout(t *testing.T) {
	backend := newFakeDesktopBackend()
	backend.portOwned = false
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	tunnelRuntime.readinessTimeout = 25 * time.Millisecond
	_, err := tunnelRuntime.Apply(context.Background(), desktopApplyRequest("revision-1"))
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if len(backend.stops) != 1 {
		t.Fatalf("unready Xray was not stopped: %v", backend.stops)
	}
	if strings.Contains(strings.Join(backend.runs, "\n"), "wg-quick up") {
		t.Fatalf("WireGuard started before owned port readiness: %v", backend.runs)
	}
}

func TestDesktopApplyWireGuardFailureStopsXrayAndDoesNotCommitActive(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	backend.runErrorContains["wg-quick up"] = []error{errors.New("permission failure with private key " + request.WireGuardPrivateKey)}

	_, err := tunnelRuntime.Apply(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if strings.Contains(err.Error(), request.WireGuardPrivateKey) {
		t.Fatalf("error leaked private key: %v", err)
	}
	if len(backend.stops) != 1 || backend.alive[backend.stops[0]] {
		t.Fatalf("candidate Xray was not stopped: stops=%v alive=%v", backend.stops, backend.alive)
	}
	if _, err := os.Stat(tunnelRuntime.activeManifestPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed runtime committed active metadata: %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(tunnelRuntime.dir, "revisions"))
	if readErr != nil {
		t.Fatalf("read revisions: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed candidate retained secret revision directories: %v", entries)
	}
}

func TestDesktopApplySameRevisionIsIdempotent(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	starts := len(backend.starts)
	upCalls := countRunPrefix(backend.runs, "wg-quick up ")
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(backend.starts) != starts || countRunPrefix(backend.runs, "wg-quick up ") != upCalls {
		t.Fatalf("same revision restarted runtime: starts=%v runs=%v", backend.starts, backend.runs)
	}
}

func TestDesktopDownAndUpAreIdempotent(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := tunnelRuntime.Down(t.Context()); err != nil {
		t.Fatalf("down: %v", err)
	}
	downCalls := countRunPrefix(backend.runs, "wg-quick down ")
	stops := len(backend.stops)
	if err := tunnelRuntime.Down(t.Context()); err != nil {
		t.Fatalf("repeat down: %v", err)
	}
	if countRunPrefix(backend.runs, "wg-quick down ") != downCalls || len(backend.stops) != stops {
		t.Fatalf("repeat down changed runtime: runs=%v stops=%v", backend.runs, backend.stops)
	}
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("up: %v", err)
	}
	status, err := tunnelRuntime.Status(t.Context())
	if err != nil || !status.Applied || status.Revision != request.Config.Revision || status.Interface != request.Config.WireGuard.Interface {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestDesktopDownRefusesStalePIDAndCleanupRetainsUnknownFiles(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	if _, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1")); err != nil {
		t.Fatal(err)
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	backend.stale[active.Xray.PID] = true
	stops := len(backend.stops)
	if err := tunnelRuntime.Down(t.Context()); fault.Code(err) != fault.CodeRuntimeProcessStale {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
	if len(backend.stops) != stops {
		t.Fatalf("stale PID stopped: %v", backend.stops)
	}
	backend.stale[active.Xray.PID] = false
	if err := tunnelRuntime.Down(t.Context()); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(tunnelRuntime.dir, "operator-note.txt")
	if err := os.WriteFile(unknown, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	revisionUnknown := filepath.Join(filepath.Dir(active.XrayConfigPath), "operator-note.txt")
	if err := os.WriteFile(revisionUnknown, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tunnelRuntime.Cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown file removed: %v", err)
	}
	if _, err := os.Stat(revisionUnknown); err != nil {
		t.Fatalf("unknown revision file removed: %v", err)
	}
	if _, err := os.Stat(tunnelRuntime.activeManifestPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned manifest remains: %v", err)
	}
}

func TestDesktopApplyNewRevisionFailureRestoresLastKnownGood(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	first := desktopApplyRequest("revision-1")
	if _, err := tunnelRuntime.Apply(t.Context(), first); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second := desktopApplyRequest("revision-2")
	backend.runErrorContains["wg-quick up"] = []error{errors.New("candidate wg failed")}

	_, err := tunnelRuntime.Apply(t.Context(), second)
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatalf("load restored active: %v", err)
	}
	if active.Revision != first.Config.Revision {
		t.Fatalf("active revision = %q, want LKG %q", active.Revision, first.Config.Revision)
	}
	if len(backend.starts) != 3 {
		t.Fatalf("starts = %d, want old + candidate + restored old", len(backend.starts))
	}
	status, err := tunnelRuntime.Status(t.Context())
	if err != nil || !status.Applied || status.Revision != first.Config.Revision {
		t.Fatalf("restored status = %#v, err=%v", status, err)
	}
}

func TestDesktopApplyRetainsOnlyActiveAndLastKnownGoodRevisions(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	for _, revision := range []string{"revision-1", "revision-2", "revision-3"} {
		if _, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest(revision)); err != nil {
			t.Fatalf("apply %s: %v", revision, err)
		}
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil || active.Revision != "revision-3" {
		t.Fatalf("active = %#v, err=%v", active, err)
	}
	lastKnownGood, err := tunnelRuntime.loadManifest(tunnelRuntime.lastKnownGoodPath())
	if err != nil || lastKnownGood.Revision != "revision-2" {
		t.Fatalf("LKG = %#v, err=%v", lastKnownGood, err)
	}
	entries, err := os.ReadDir(filepath.Join(tunnelRuntime.dir, "revisions"))
	if err != nil {
		t.Fatalf("read revisions: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("retained revision directories = %d, want active + LKG only", len(entries))
	}
}

func TestDesktopApplyRefusesStalePIDWithoutStoppingIt(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	if _, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1")); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	backend.stale[active.Xray.PID] = true
	stopsBefore := len(backend.stops)
	_, err = tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-2"))
	if fault.Code(err) != fault.CodeRuntimeProcessStale {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if len(backend.stops) != stopsBefore {
		t.Fatalf("stale PID was stopped: stops=%v", backend.stops)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("stale process error leaked backend details: %v", err)
	}
}

func TestDesktopApplyNeverStopsProcessWhoseConfigIsOutsideOwnedRevision(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	if _, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1")); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	externalConfig := filepath.Join(t.TempDir(), "unrelated-xray.json")
	raw, err := os.ReadFile(active.XrayConfigPath)
	if err != nil {
		t.Fatalf("read owned config: %v", err)
	}
	if err := os.WriteFile(externalConfig, raw, 0o600); err != nil {
		t.Fatalf("write unrelated config: %v", err)
	}
	active.XrayConfigPath = externalConfig
	active.Xray.ConfigPath = externalConfig
	if err := tunnelRuntime.saveManifest(tunnelRuntime.activeManifestPath(), active); err != nil {
		t.Fatalf("save tampered metadata: %v", err)
	}
	stopsBefore := len(backend.stops)
	_, err = tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-2"))
	if fault.Code(err) != fault.CodeRuntimeProcessStale {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if len(backend.stops) != stopsBefore {
		t.Fatalf("non-owned process was stopped: %v", backend.stops)
	}
	if _, err := os.Stat(externalConfig); err != nil {
		t.Fatalf("unrelated config was removed: %v", err)
	}
}

func TestDesktopApplyRefusesTamperedWireGuardConfigBeforeExecutingDown(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	if _, err := tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-1")); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	active, err := tunnelRuntime.loadManifest(tunnelRuntime.activeManifestPath())
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	file, err := os.OpenFile(active.WGConfigPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open WireGuard config: %v", err)
	}
	if _, err := file.WriteString("PostDown = unsafe-command\n"); err != nil {
		_ = file.Close()
		t.Fatalf("tamper WireGuard config: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close WireGuard config: %v", err)
	}
	downBefore := countRunPrefix(backend.runs, "wg-quick down ")
	stopsBefore := len(backend.stops)
	_, err = tunnelRuntime.Apply(t.Context(), desktopApplyRequest("revision-2"))
	if fault.Code(err) != fault.CodeRuntimeProcessStale {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if countRunPrefix(backend.runs, "wg-quick down ") != downBefore || len(backend.stops) != stopsBefore {
		t.Fatalf("tampered config triggered runtime stop: runs=%v stops=%v", backend.runs, backend.stops)
	}
}

func TestDesktopStatusAndDiagnoseAreSecretFree(t *testing.T) {
	backend := newFakeDesktopBackend()
	tunnelRuntime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := tunnelRuntime.Apply(t.Context(), request); err != nil {
		t.Fatalf("apply: %v", err)
	}
	status, err := tunnelRuntime.Status(t.Context())
	if err != nil || !status.Available || !status.Applied || status.Interface != request.Config.WireGuard.Interface || status.AdapterID != model.AdapterIDXrayCore {
		t.Fatalf("status = %#v, err=%v", status, err)
	}
	diagnostics, err := tunnelRuntime.Diagnose(t.Context())
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	raw := fmt.Sprintf("%#v %#v", status, diagnostics)
	for _, secret := range []string{request.WireGuardPrivateKey, request.Config.Transport.UUID} {
		if strings.Contains(raw, secret) {
			t.Fatalf("status/diagnose leaked a secret: %s", raw)
		}
	}
	for _, expected := range []string{"runtime_metadata_valid", "xray_process_healthy", "xray_loopback_port_healthy", "wireguard_interface_healthy"} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("diagnostics missing %q: %s", expected, raw)
		}
	}
}

func TestRenderedProfilesContainOnlySupportedXrayRuntime(t *testing.T) {
	request := desktopApplyRequest("revision-1")
	xray, err := renderXrayConfig(request.Config)
	if err != nil {
		t.Fatalf("render Xray: %v", err)
	}
	wireGuard := renderWireGuardConfig(request.Config, request.WireGuardPrivateKey)
	if !bytes.Contains(xray, []byte(`"protocol": "vless"`)) || !bytes.Contains(xray, []byte(`"packetEncoding": "xudp"`)) || bytes.Contains(bytes.ToLower(xray), []byte("sing-box")) {
		t.Fatalf("unexpected Xray profile: %s", xray)
	}
	if !strings.Contains(wireGuard, request.WireGuardPrivateKey) || !strings.Contains(wireGuard, "Endpoint = 127.0.0.1:51830") {
		t.Fatal("WireGuard profile does not use the protected local transport")
	}
}

func TestSignedConfigRendersFixedCohostedWireGuardRelayTarget(t *testing.T) {
	config := signedconfig.Config{
		SchemaVersion: signedconfig.SchemaVersionV1,
		ConfigID:      "cfg_42",
		NetworkID:     "net_private",
		DeviceID:      "dev_linux",
		Generation:    42,
		IssuedAt:      signedconfig.CanonicalTime{Time: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)},
		ExpiresAt:     signedconfig.CanonicalTime{Time: time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)},
		ProxyCore:     signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{
			Kind: signedconfig.TransportVLESS, Loopback: signedconfig.Endpoint{Host: signedconfig.LoopbackHost, Port: 51830},
			Remote: signedconfig.RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "tls.example.net"},
			AuthID: "11111111-1111-1111-1111-111111111111",
		},
		WireGuard: signedconfig.WireGuard{
			InterfaceName: "wg-xco", Addresses: []string{"10.77.0.20/32"}, MTU: 1280,
			Peers: []signedconfig.Peer{{GatewayID: "gw_tokyo_01", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.77.0.0/16"}, Endpoint: signedconfig.Endpoint{Host: signedconfig.LoopbackHost, Port: 51830}, PersistentKeepaliveSeconds: 25}},
		},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "signing_key_01", Value: base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
	compiled, err := signedconfig.Compile(config)
	if err != nil {
		t.Fatalf("compile signed config: %v", err)
	}
	rendered, err := renderXrayConfig(compiled)
	if err != nil {
		t.Fatalf("render compiled signed config: %v", err)
	}
	for _, expected := range []string{`"address": "127.0.0.1"`, `"port": 51820`, `"serverName": "tls.example.net"`, `"packetEncoding": "xudp"`} {
		if !bytes.Contains(rendered, []byte(expected)) {
			t.Fatalf("compiled Xray profile does not lock %s: %s", expected, rendered)
		}
	}
}

func desktopApplyRequest(revision string) ApplyRequest {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	return ApplyRequest{
		WireGuardPrivateKey: privateKey,
		Config: model.Config{
			SchemaVersion: 1,
			Revision:      revision,
			Digest:        "digest-" + revision,
			Network:       model.Network{ID: "net_private", CIDR: "10.77.0.0/16"},
			Device:        model.Device{ID: "dev_linux", NetworkID: "net_private"},
			WireGuard: model.WireGuardConfig{
				Interface:            "wg-xco",
				Address:              "10.77.0.20/32",
				MTU:                  1280,
				DNS:                  []string{"10.77.0.1"},
				PrivateKeyRef:        "local-keychain",
				LocalProxyEndpoint:   "127.0.0.1:51830",
				PersistentKeepalive:  25,
				PeerPublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PeerAllowedIPs:       []string{"10.77.0.0/16"},
				PeerEndpoint:         "127.0.0.1:51830",
				GatewayWireGuardIP:   "10.77.0.1",
				GatewayWireGuardCIDR: "10.77.0.1/32",
			},
			Transport: model.TransportConfig{
				Runtime:        model.WireRuntimeXrayCore,
				Type:           model.TransportVLESSTLS,
				Security:       model.TransportSecurityTLS,
				Server:         "gateway.example.net",
				Port:           443,
				UUID:           "11111111-1111-1111-1111-111111111111",
				PacketEncoding: model.PacketEncodingXUDP,
				LocalPort:      51830,
			},
		},
	}
}

func countRunPrefix(runs []string, prefix string) int {
	count := 0
	for _, run := range runs {
		if strings.HasPrefix(run, prefix) {
			count++
		}
	}
	return count
}
