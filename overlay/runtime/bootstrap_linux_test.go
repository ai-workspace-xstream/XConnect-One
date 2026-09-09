//go:build linux

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestBootstrapLinuxInstallsAndReusesVerifiedManagedXray(t *testing.T) {
	archive := testXrayArchive(t, []byte("managed-xray"))
	digest := sha256.Sum256(archive)
	var requests atomic.Int64
	server := httptest.NewTLSServer(httpHandler(func([]byte) []byte {
		requests.Add(1)
		return archive
	}))
	defer server.Close()

	stateDirectory := filepath.Join(t.TempDir(), "state")
	now := time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC)
	artifact := managedRuntimeArtifact{
		Version:       "vtest",
		Name:          "Xray-linux-test.zip",
		ArchiveSHA256: hex.EncodeToString(digest[:]),
	}
	dependencies := bootstrapLinuxDependencies{
		architecture: goruntime.GOARCH,
		effectiveUID: func() int { return 0 },
		lookPath: func(name string) (string, error) {
			return filepath.Join("/usr/bin", name), nil
		},
		run: func(context.Context, string, ...string) error {
			return errors.New("package manager must not run")
		},
		client:   server.Client(),
		now:      func() time.Time { return now },
		artifact: artifact,
	}
	options := BootstrapOptions{StateDirectory: stateDirectory, ReleaseBaseURL: server.URL}
	result, err := bootstrapLinux(t.Context(), options, dependencies)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if result.AlreadyProvisioned || result.XrayVersion != "vtest" || !result.SystemWireGuard || result.InstalledAt != now {
		t.Fatalf("unexpected result: %#v", result)
	}
	raw, err := os.ReadFile(result.XrayPath)
	if err != nil || string(raw) != "managed-xray" {
		t.Fatalf("managed Xray: raw=%q err=%v", raw, err)
	}
	info, err := os.Stat(result.XrayPath)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("managed Xray mode: info=%v err=%v", info, err)
	}
	manifestInfo, err := os.Stat(managedRuntimeManifestPath(stateDirectory))
	if err != nil || manifestInfo.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode: info=%v err=%v", manifestInfo, err)
	}
	if resolved, ok := resolveManagedXray(stateDirectory); !ok || resolved != canonicalPath(result.XrayPath) {
		t.Fatalf("managed Xray was not selected: resolved=%q ok=%v", resolved, ok)
	}

	reused, err := bootstrapLinux(t.Context(), options, dependencies)
	if err != nil || !reused.AlreadyProvisioned {
		t.Fatalf("reuse: result=%#v err=%v", reused, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d want=1", requests.Load())
	}

	if err := os.WriteFile(result.XrayPath, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolveManagedXray(stateDirectory); ok {
		t.Fatal("tampered managed Xray must not be selected")
	}
}

func TestBootstrapLinuxRejectsArchiveChecksumMismatch(t *testing.T) {
	archive := testXrayArchive(t, []byte("managed-xray"))
	server := httptest.NewTLSServer(httpHandler(func([]byte) []byte { return archive }))
	defer server.Close()
	dependencies := bootstrapLinuxDependencies{
		architecture: goruntime.GOARCH,
		effectiveUID: func() int { return 0 },
		lookPath: func(name string) (string, error) {
			return filepath.Join("/usr/bin", name), nil
		},
		run:      func(context.Context, string, ...string) error { return nil },
		client:   server.Client(),
		now:      func() time.Time { return time.Now().UTC() },
		artifact: managedRuntimeArtifact{Version: "vtest", Name: "xray.zip", ArchiveSHA256: string(bytes.Repeat([]byte{'0'}, 64))},
	}
	_, err := bootstrapLinux(t.Context(), BootstrapOptions{StateDirectory: filepath.Join(t.TempDir(), "state"), ReleaseBaseURL: server.URL}, dependencies)
	if fault.Code(err) != fault.CodeRuntimeDependency {
		t.Fatalf("error=%v code=%q", err, fault.Code(err))
	}
}
