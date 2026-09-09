//go:build darwin

package runtime

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

var darwinManagedXrayArtifacts = map[string]managedRuntimeArtifact{
	"amd64": {Version: DefaultManagedXrayVersion, Name: "Xray-macos-64.zip", ArchiveSHA256: "f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203"},
	"arm64": {Version: DefaultManagedXrayVersion, Name: "Xray-macos-arm64-v8a.zip", ArchiveSHA256: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf"},
}

type bootstrapDarwinDependencies struct {
	architecture string
	effectiveUID func() int
	lookPath     func(string) (string, error)
	run          func(context.Context, string, ...string) error
	client       *http.Client
	now          func() time.Time
	artifact     managedRuntimeArtifact
}

func bootstrapPlatform(ctx context.Context, options BootstrapOptions) (BootstrapResult, error) {
	artifact, ok := darwinManagedXrayArtifacts[goruntime.GOARCH]
	if !ok {
		return BootstrapResult{}, fault.New(fault.CodeRuntimeUnavailable, "select managed Xray artifact", nil)
	}
	return bootstrapDarwin(ctx, options, bootstrapDarwinDependencies{architecture: goruntime.GOARCH, effectiveUID: os.Geteuid,
		lookPath: lookPathDarwinRuntime, run: runDarwinBootstrapCommand, client: &http.Client{Timeout: 2 * time.Minute},
		now: func() time.Time { return time.Now().UTC() }, artifact: artifact})
}

func bootstrapDarwin(ctx context.Context, options BootstrapOptions, dependencies bootstrapDarwinDependencies) (BootstrapResult, error) {
	if dependencies.effectiveUID == nil || dependencies.lookPath == nil || dependencies.run == nil || dependencies.client == nil || dependencies.now == nil {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "initialize macOS runtime bootstrap dependencies", nil)
	}
	if dependencies.effectiveUID() != 0 {
		return BootstrapResult{}, fault.New(fault.CodeRuntimePermission, "bootstrap managed runtime", nil)
	}
	if err := ensureDarwinSystemRuntime(ctx, options.InstallSystemPackages, dependencies); err != nil {
		return BootstrapResult{}, err
	}
	return installManagedXray(ctx, options, dependencies.artifact, "darwin", dependencies.architecture, dependencies.client, dependencies.now)
}

func ensureDarwinSystemRuntime(ctx context.Context, install bool, dependencies bootstrapDarwinDependencies) error {
	required := []string{"wg", "wg-quick", "wireguard-go"}
	if missingCommands(required, dependencies.lookPath) == 0 {
		return nil
	}
	if !install {
		return fault.New(fault.CodeRuntimeDependency, "locate macOS WireGuard runtime", nil)
	}
	brew, ownerUID, err := trustedDarwinBrew(dependencies.lookPath)
	if err != nil {
		return fault.New(fault.CodeRuntimeDependency, "locate user-owned Homebrew", err)
	}
	sudo, err := dependencies.lookPath("sudo")
	if err != nil {
		return fault.New(fault.CodeRuntimeDependency, "locate sudo for Homebrew", err)
	}
	if err := dependencies.run(ctx, sudo, "-H", "-u", "#"+strconv.FormatUint(uint64(ownerUID), 10), brew, "install", "wireguard-tools", "wireguard-go"); err != nil {
		return fault.New(fault.CodeRuntimeDependency, "install macOS WireGuard runtime", nil)
	}
	if missingCommands(required, dependencies.lookPath) != 0 {
		return fault.New(fault.CodeRuntimeDependency, "verify macOS WireGuard runtime", nil)
	}
	return nil
}

func trustedDarwinBrew(lookPath func(string) (string, error)) (string, uint32, error) {
	brew, err := lookPath("brew")
	if err != nil {
		for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
			if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
				brew, err = candidate, nil
				break
			}
		}
	}
	if err != nil {
		return "", 0, err
	}
	info, err := os.Stat(brew)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return "", 0, os.ErrPermission
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return "", 0, os.ErrPermission
	}
	return filepath.Clean(brew), stat.Uid, nil
}

func lookPathDarwinRuntime(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return canonicalPath(path), nil
	}
	// Standard Homebrew fallback is only needed for the privileged lifecycle;
	// keeping non-privileged PATH semantics also prevents surprising tool use.
	if os.Geteuid() != 0 {
		return "", os.ErrNotExist
	}
	for _, directory := range []string{"/opt/homebrew/bin", "/usr/local/bin"} {
		candidate := filepath.Join(directory, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return canonicalPath(candidate), nil
		}
	}
	return "", os.ErrNotExist
}

func runDarwinBootstrapCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	return command.Run()
}
