//go:build darwin

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

func TestBootstrapDarwinInstallsAndReusesManagedXray(t *testing.T) {
	archive := testXrayArchive(t, []byte("darwin-xray"))
	digest := sha256.Sum256(archive)
	server := httptest.NewTLSServer(httpHandler(func([]byte) []byte { return archive }))
	defer server.Close()
	now := time.Date(2026, 9, 9, 2, 0, 0, 0, time.UTC)
	dependencies := bootstrapDarwinDependencies{architecture: "arm64", effectiveUID: func() int { return 0 },
		lookPath: func(name string) (string, error) { return filepath.Join("/usr/local/bin", name), nil },
		run:      func(context.Context, string, ...string) error { return errors.New("package manager must not run") },
		client:   server.Client(), now: func() time.Time { return now },
		artifact: managedRuntimeArtifact{Version: "vtest", Name: "Xray-macos-test.zip", ArchiveSHA256: hex.EncodeToString(digest[:])}}
	options := BootstrapOptions{StateDirectory: filepath.Join(t.TempDir(), "state"), ReleaseBaseURL: server.URL}
	result, err := bootstrapDarwin(t.Context(), options, dependencies)
	if err != nil || result.Platform != "darwin" || result.AlreadyProvisioned {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	reused, err := bootstrapDarwin(t.Context(), options, dependencies)
	if err != nil || !reused.AlreadyProvisioned {
		t.Fatalf("reused=%#v err=%v", reused, err)
	}
}
