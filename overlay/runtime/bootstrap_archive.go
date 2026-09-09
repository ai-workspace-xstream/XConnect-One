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
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const managedRuntimeDownloadLimit = 128 << 20

func missingCommands(names []string, lookPath func(string) (string, error)) int {
	missing := 0
	for _, name := range names {
		if _, err := lookPath(name); err != nil {
			missing++
		}
	}
	return missing
}

func installManagedXray(ctx context.Context, options BootstrapOptions, artifact managedRuntimeArtifact, platform, architecture string, client *http.Client, now func() time.Time) (BootstrapResult, error) {
	if artifact.Version == "" || artifact.Name == "" || len(artifact.ArchiveSHA256) != 64 || platform == "" || architecture == "" {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "select managed Xray artifact", nil)
	}
	base, err := validateRuntimeReleaseBaseURL(options.ReleaseBaseURL)
	if err != nil {
		return BootstrapResult{}, err
	}
	sourceURL := strings.TrimRight(base.String(), "/") + "/" + artifact.Version + "/" + artifact.Name
	if existing, ok := currentManagedRuntime(options.StateDirectory, artifact, platform, architecture, sourceURL); ok {
		existing.AlreadyProvisioned = true
		return existing, nil
	}
	archive, err := downloadManagedRuntime(ctx, client, sourceURL, artifact.ArchiveSHA256)
	if err != nil {
		return BootstrapResult{}, err
	}
	binary, err := extractXrayBinary(archive)
	if err != nil {
		return BootstrapResult{}, err
	}
	digest := sha256.Sum256(binary)
	path := managedXrayPath(options.StateDirectory)
	if err := writeManagedExecutable(path, binary); err != nil {
		return BootstrapResult{}, err
	}
	manifest := managedRuntimeManifest{SchemaVersion: managedRuntimeSchemaVersion, Platform: platform, Architecture: architecture,
		XrayVersion: artifact.Version, XrayAsset: artifact.Name, XrayArchiveSHA256: artifact.ArchiveSHA256,
		XrayBinarySHA256: hex.EncodeToString(digest[:]), XrayPath: path, SourceURL: sourceURL,
		SystemWireGuard: true, InstalledAt: now().UTC()}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BootstrapResult{}, fault.New(fault.CodeStateIO, "encode managed runtime manifest", err)
	}
	if err := writeFile0600(managedRuntimeManifestPath(options.StateDirectory), append(raw, '\n')); err != nil {
		return BootstrapResult{}, err
	}
	return bootstrapResult(manifest, false), nil
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
		name := strings.ToLower(filepath.Base(entry.Name))
		if (name != "xray" && name != "xray.exe") || entry.FileInfo().IsDir() {
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
	if goruntime.GOOS == "windows" {
		if err := secureFilePlatform(temporaryPath); err != nil {
			return fault.New(fault.CodeStateIO, "secure managed runtime binary", err)
		}
	} else if err := temporary.Chmod(0o700); err != nil {
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
	if err := replaceRuntimeFile(temporaryPath, path); err != nil {
		return fault.New(fault.CodeStateIO, "commit managed runtime binary", err)
	}
	committed = true
	return nil
}

func currentManagedRuntime(stateDirectory string, artifact managedRuntimeArtifact, platform, architecture, sourceURL string) (BootstrapResult, bool) {
	manifest, ok := loadManagedRuntimeManifest(stateDirectory)
	if !ok || manifest.Platform != platform || manifest.Architecture != architecture || manifest.XrayVersion != artifact.Version ||
		manifest.XrayAsset != artifact.Name || !strings.EqualFold(manifest.XrayArchiveSHA256, artifact.ArchiveSHA256) ||
		filepath.Clean(manifest.XrayPath) != filepath.Clean(managedXrayPath(stateDirectory)) || manifest.SourceURL != sourceURL {
		return BootstrapResult{}, false
	}
	return bootstrapResult(manifest, true), true
}

func bootstrapResult(manifest managedRuntimeManifest, alreadyProvisioned bool) BootstrapResult {
	return BootstrapResult{SchemaVersion: manifest.SchemaVersion, Platform: manifest.Platform, Architecture: manifest.Architecture,
		XrayVersion: manifest.XrayVersion, XrayPath: manifest.XrayPath, XraySHA256: manifest.XrayBinarySHA256,
		SystemWireGuard: manifest.SystemWireGuard, InstalledAt: manifest.InstalledAt, AlreadyProvisioned: alreadyProvisioned}
}
