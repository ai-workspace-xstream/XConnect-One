package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const (
	managedRuntimeSchemaVersion = 1
	DefaultManagedXrayVersion   = "v26.3.27"
	defaultXrayReleaseBaseURL   = "https://github.com/XTLS/Xray-core/releases/download"
)

type BootstrapOptions struct {
	StateDirectory        string
	ReleaseBaseURL        string
	InstallSystemPackages bool
}

type BootstrapResult struct {
	SchemaVersion      int       `json:"schema_version"`
	Platform           string    `json:"platform"`
	Architecture       string    `json:"architecture"`
	XrayVersion        string    `json:"xray_version"`
	XrayPath           string    `json:"xray_path"`
	XraySHA256         string    `json:"xray_sha256"`
	SystemWireGuard    bool      `json:"system_wireguard"`
	InstalledAt        time.Time `json:"installed_at"`
	AlreadyProvisioned bool      `json:"already_provisioned"`
}

type managedRuntimeManifest struct {
	SchemaVersion     int       `json:"schema_version"`
	Platform          string    `json:"platform"`
	Architecture      string    `json:"architecture"`
	XrayVersion       string    `json:"xray_version"`
	XrayAsset         string    `json:"xray_asset"`
	XrayArchiveSHA256 string    `json:"xray_archive_sha256"`
	XrayBinarySHA256  string    `json:"xray_binary_sha256"`
	XrayPath          string    `json:"xray_path"`
	SourceURL         string    `json:"source_url"`
	SystemWireGuard   bool      `json:"system_wireguard"`
	InstalledAt       time.Time `json:"installed_at"`
}

type managedRuntimeArtifact struct {
	Version       string
	Name          string
	ArchiveSHA256 string
}

func Bootstrap(ctx context.Context, options BootstrapOptions) (BootstrapResult, error) {
	options.StateDirectory = filepath.Clean(strings.TrimSpace(options.StateDirectory))
	if options.StateDirectory == "." || !filepath.IsAbs(options.StateDirectory) {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "bootstrap runtime state directory", nil)
	}
	if strings.TrimSpace(options.ReleaseBaseURL) == "" {
		options.ReleaseBaseURL = defaultXrayReleaseBaseURL
	}
	return bootstrapPlatform(ctx, options)
}

func managedRuntimeDirectory(stateDirectory string) string {
	return filepath.Join(stateDirectory, "managed-runtime")
}

func managedRuntimeManifestPath(stateDirectory string) string {
	return filepath.Join(managedRuntimeDirectory(stateDirectory), "manifest.json")
}

func managedXrayPath(stateDirectory string) string {
	name := "xray"
	if runtime.GOOS == "windows" {
		name = "xray.exe"
	}
	return filepath.Join(managedRuntimeDirectory(stateDirectory), "bin", name)
}

func resolveManagedXray(stateDirectory string) (string, bool) {
	manifest, ok := loadManagedRuntimeManifest(stateDirectory)
	if !ok {
		return "", false
	}
	return canonicalPath(manifest.XrayPath), true
}

func loadManagedRuntimeManifest(stateDirectory string) (managedRuntimeManifest, bool) {
	path := managedRuntimeManifestPath(stateDirectory)
	if !privateRegularFile(path) {
		return managedRuntimeManifest{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return managedRuntimeManifest{}, false
	}
	var manifest managedRuntimeManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return managedRuntimeManifest{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return managedRuntimeManifest{}, false
	}
	source, err := url.Parse(manifest.SourceURL)
	if manifest.SchemaVersion != managedRuntimeSchemaVersion || manifest.Platform != runtime.GOOS ||
		manifest.Architecture != runtime.GOARCH || manifest.XrayVersion == "" || manifest.XrayAsset == "" ||
		len(manifest.XrayArchiveSHA256) != 64 || len(manifest.XrayBinarySHA256) != 64 ||
		filepath.Clean(manifest.XrayPath) != filepath.Clean(managedXrayPath(stateDirectory)) ||
		err != nil || source.Scheme != "https" || source.Host == "" || source.User != nil ||
		source.RawQuery != "" || source.Fragment != "" || !manifest.SystemWireGuard || manifest.InstalledAt.IsZero() {
		return managedRuntimeManifest{}, false
	}
	info, err := os.Lstat(manifest.XrayPath)
	if err != nil || !info.Mode().IsRegular() {
		return managedRuntimeManifest{}, false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return managedRuntimeManifest{}, false
	}
	binary, err := os.ReadFile(manifest.XrayPath)
	if err != nil {
		return managedRuntimeManifest{}, false
	}
	digest := sha256.Sum256(binary)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.XrayBinarySHA256) {
		return managedRuntimeManifest{}, false
	}
	return manifest, true
}
