//go:build linux

package runtime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const managedRuntimeDownloadLimit = 128 << 20

var linuxManagedXrayArtifacts = map[string]managedRuntimeArtifact{
	"amd64": {
		Version:       DefaultManagedXrayVersion,
		Name:          "Xray-linux-64.zip",
		ArchiveSHA256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
	},
	"arm64": {
		Version:       DefaultManagedXrayVersion,
		Name:          "Xray-linux-arm64-v8a.zip",
		ArchiveSHA256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
	},
}

type bootstrapLinuxDependencies struct {
	architecture string
	effectiveUID func() int
	lookPath     func(string) (string, error)
	run          func(context.Context, string, ...string) error
	client       *http.Client
	now          func() time.Time
	artifact     managedRuntimeArtifact
}

func bootstrapPlatform(ctx context.Context, options BootstrapOptions) (BootstrapResult, error) {
	artifact, ok := linuxManagedXrayArtifacts[goruntime.GOARCH]
	if !ok {
		return BootstrapResult{}, fault.New(fault.CodeRuntimeUnavailable, "select managed Xray artifact", nil)
	}
	return bootstrapLinux(ctx, options, bootstrapLinuxDependencies{
		architecture: goruntime.GOARCH,
		effectiveUID: os.Geteuid,
		lookPath:     exec.LookPath,
		run:          runBootstrapCommand,
		client:       &http.Client{Timeout: 2 * time.Minute},
		now:          func() time.Time { return time.Now().UTC() },
		artifact:     artifact,
	})
}

func bootstrapLinux(ctx context.Context, options BootstrapOptions, dependencies bootstrapLinuxDependencies) (BootstrapResult, error) {
	if dependencies.effectiveUID == nil || dependencies.lookPath == nil || dependencies.run == nil || dependencies.client == nil || dependencies.now == nil {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "initialize runtime bootstrap dependencies", nil)
	}
	if dependencies.effectiveUID() != 0 {
		return BootstrapResult{}, fault.New(fault.CodeRuntimePermission, "bootstrap managed runtime", nil)
	}
	if dependencies.artifact.Version == "" || dependencies.artifact.Name == "" || len(dependencies.artifact.ArchiveSHA256) != 64 {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "select managed Xray artifact", nil)
	}
	if err := ensureLinuxSystemRuntime(ctx, options.InstallSystemPackages, dependencies); err != nil {
		return BootstrapResult{}, err
	}
	base, err := validateRuntimeReleaseBaseURL(options.ReleaseBaseURL)
	if err != nil {
		return BootstrapResult{}, err
	}
	sourceURL := strings.TrimRight(base.String(), "/") + "/" + dependencies.artifact.Version + "/" + dependencies.artifact.Name
	if existing, ok := currentManagedRuntime(options.StateDirectory, dependencies.artifact, dependencies.architecture, sourceURL); ok {
		existing.AlreadyProvisioned = true
		return existing, nil
	}
	archive, err := downloadManagedRuntime(ctx, dependencies.client, sourceURL, dependencies.artifact.ArchiveSHA256)
	if err != nil {
		return BootstrapResult{}, err
	}
	xrayBinary, err := extractXrayBinary(archive)
	if err != nil {
		return BootstrapResult{}, err
	}
	xrayDigest := sha256.Sum256(xrayBinary)
	xrayPath := managedXrayPath(options.StateDirectory)
	if err := writeManagedExecutable(xrayPath, xrayBinary); err != nil {
		return BootstrapResult{}, err
	}
	installedAt := dependencies.now().UTC()
	manifest := managedRuntimeManifest{
		SchemaVersion:     managedRuntimeSchemaVersion,
		Platform:          "linux",
		Architecture:      dependencies.architecture,
		XrayVersion:       dependencies.artifact.Version,
		XrayAsset:         dependencies.artifact.Name,
		XrayArchiveSHA256: dependencies.artifact.ArchiveSHA256,
		XrayBinarySHA256:  hex.EncodeToString(xrayDigest[:]),
		XrayPath:          xrayPath,
		SourceURL:         sourceURL,
		SystemWireGuard:   true,
		InstalledAt:       installedAt,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BootstrapResult{}, fault.New(fault.CodeStateIO, "encode managed runtime manifest", err)
	}
	if err := writeFile0600(managedRuntimeManifestPath(options.StateDirectory), append(raw, '\n')); err != nil {
		return BootstrapResult{}, err
	}
	return bootstrapResult(manifest, false), nil
}

func ensureLinuxSystemRuntime(ctx context.Context, install bool, dependencies bootstrapLinuxDependencies) error {
	required := []string{"wg", "wg-quick", "systemctl", "systemd-run"}
	if missingCommands(required, dependencies.lookPath) == 0 {
		return nil
	}
	if !install {
		return fault.New(fault.CodeRuntimeDependency, "locate Linux WireGuard/systemd runtime", nil)
	}
	aptGet, err := dependencies.lookPath("apt-get")
	if err != nil {
		return fault.New(fault.CodeRuntimeDependency, "install Linux runtime packages on unsupported distribution", nil)
	}
	if err := dependencies.run(ctx, aptGet, "update"); err != nil {
		return fault.New(fault.CodeRuntimeDependency, "update Linux package metadata", nil)
	}
	if err := dependencies.run(ctx, aptGet, "install", "-y", "--no-install-recommends", "wireguard-tools", "iproute2"); err != nil {
		return fault.New(fault.CodeRuntimeDependency, "install Linux runtime packages", nil)
	}
	if missingCommands(required, dependencies.lookPath) != 0 {
		return fault.New(fault.CodeRuntimeDependency, "verify Linux WireGuard/systemd runtime", nil)
	}
	return nil
}

func missingCommands(names []string, lookPath func(string) (string, error)) int {
	missing := 0
	for _, name := range names {
		if _, err := lookPath(name); err != nil {
			missing++
		}
	}
	return missing
}

func runBootstrapCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return command.Run()
}

func validateRuntimeReleaseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fault.New(fault.CodeInvalidInput, "validate managed runtime release base URL", err)
	}
	return parsed, nil
}

func downloadManagedRuntime(ctx context.Context, client *http.Client, sourceURL, expectedDigest string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, fault.New(fault.CodeRuntimeDependency, "create managed runtime request", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fault.New(fault.CodeRuntimeDependency, "download managed runtime", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > managedRuntimeDownloadLimit {
		return nil, fault.New(fault.CodeRuntimeDependency, "download managed runtime", nil)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, managedRuntimeDownloadLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > managedRuntimeDownloadLimit {
		return nil, fault.New(fault.CodeRuntimeDependency, "read managed runtime archive", err)
	}
	digest := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expectedDigest) {
		return nil, fault.New(fault.CodeRuntimeDependency, "verify managed runtime archive checksum", nil)
	}
	return raw, nil
}

func extractXrayBinary(archive []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fault.New(fault.CodeRuntimeDependency, "open managed Xray archive", err)
	}
	for _, entry := range reader.File {
		if !strings.EqualFold(filepath.Base(entry.Name), "xray") || entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > managedRuntimeDownloadLimit {
			return nil, fault.New(fault.CodeRuntimeDependency, "validate managed Xray binary size", nil)
		}
		file, err := entry.Open()
		if err != nil {
			return nil, fault.New(fault.CodeRuntimeDependency, "open managed Xray binary", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, managedRuntimeDownloadLimit+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > managedRuntimeDownloadLimit {
			return nil, fault.New(fault.CodeRuntimeDependency, "read managed Xray binary", errors.Join(readErr, closeErr))
		}
		return raw, nil
	}
	return nil, fault.New(fault.CodeRuntimeDependency, "locate managed Xray binary", nil)
}

func writeManagedExecutable(path string, raw []byte) error {
	if err := secureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".xconnect-managed-*")
	if err != nil {
		return fault.New(fault.CodeStateIO, "create managed runtime binary", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o700); err != nil {
		return fault.New(fault.CodeStateIO, "secure managed runtime binary", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return fault.New(fault.CodeStateIO, "write managed runtime binary", err)
	}
	if err := temporary.Sync(); err != nil {
		return fault.New(fault.CodeStateIO, "sync managed runtime binary", err)
	}
	if err := temporary.Close(); err != nil {
		return fault.New(fault.CodeStateIO, "close managed runtime binary", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fault.New(fault.CodeStateIO, "commit managed runtime binary", err)
	}
	committed = true
	return nil
}

func currentManagedRuntime(stateDirectory string, artifact managedRuntimeArtifact, architecture, sourceURL string) (BootstrapResult, bool) {
	manifest, ok := loadManagedRuntimeManifest(stateDirectory)
	if !ok {
		return BootstrapResult{}, false
	}
	if manifest.SchemaVersion != managedRuntimeSchemaVersion || manifest.Platform != "linux" ||
		manifest.Architecture != architecture || manifest.XrayVersion != artifact.Version ||
		manifest.XrayAsset != artifact.Name || !strings.EqualFold(manifest.XrayArchiveSHA256, artifact.ArchiveSHA256) ||
		filepath.Clean(manifest.XrayPath) != filepath.Clean(managedXrayPath(stateDirectory)) ||
		manifest.SourceURL != sourceURL || !manifest.SystemWireGuard || manifest.InstalledAt.IsZero() {
		return BootstrapResult{}, false
	}
	info, err := os.Lstat(manifest.XrayPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return BootstrapResult{}, false
	}
	binary, err := os.ReadFile(manifest.XrayPath)
	if err != nil {
		return BootstrapResult{}, false
	}
	digest := sha256.Sum256(binary)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.XrayBinarySHA256) {
		return BootstrapResult{}, false
	}
	return bootstrapResult(manifest, true), true
}

func bootstrapResult(manifest managedRuntimeManifest, alreadyProvisioned bool) BootstrapResult {
	return BootstrapResult{
		SchemaVersion:      manifest.SchemaVersion,
		Platform:           manifest.Platform,
		Architecture:       manifest.Architecture,
		XrayVersion:        manifest.XrayVersion,
		XrayPath:           manifest.XrayPath,
		XraySHA256:         manifest.XrayBinarySHA256,
		SystemWireGuard:    manifest.SystemWireGuard,
		InstalledAt:        manifest.InstalledAt,
		AlreadyProvisioned: alreadyProvisioned,
	}
}
