//go:build windows

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapWindowsInstallsAndReusesManagedXray(t *testing.T) {
	archive := testNamedXrayArchive(t, "xray.exe", []byte("windows-xray"))
	digest := sha256.Sum256(archive)
	server := httptest.NewTLSServer(httpHandler(func([]byte) []byte { return archive }))
	defer server.Close()
	now := time.Date(2026, 9, 9, 2, 0, 0, 0, time.UTC)
	dependencies := bootstrapWindowsDependencies{architecture: "amd64", elevated: func() bool { return true },
		lookPath: func(name string) (string, error) { return filepath.Join(`C:\Program Files\WireGuard`, name), nil },
		run:      func(context.Context, string, ...string) error { return errors.New("package manager must not run") },
		client:   server.Client(), now: func() time.Time { return now },
		artifact: managedRuntimeArtifact{Version: "vtest", Name: "Xray-windows-test.zip", ArchiveSHA256: hex.EncodeToString(digest[:])}}
	options := BootstrapOptions{StateDirectory: filepath.Join(t.TempDir(), "state"), ReleaseBaseURL: server.URL}
	result, err := bootstrapWindows(t.Context(), options, dependencies)
	if err != nil || result.Platform != "windows" || result.AlreadyProvisioned {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	reused, err := bootstrapWindows(t.Context(), options, dependencies)
	if err != nil || !reused.AlreadyProvisioned {
		t.Fatalf("reused=%#v err=%v", reused, err)
	}
}
