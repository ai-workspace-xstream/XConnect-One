//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

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
	if existing, ok := currentManagedRuntime(options.StateDirectory, dependencies.artifact, "linux", dependencies.architecture, sourceURL); ok {
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

func runBootstrapCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return command.Run()
}
