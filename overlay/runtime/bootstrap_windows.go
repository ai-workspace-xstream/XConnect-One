//go:build windows

package runtime

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"golang.org/x/sys/windows"
)

var windowsManagedXrayArtifacts = map[string]managedRuntimeArtifact{
	"amd64": {Version: DefaultManagedXrayVersion, Name: "Xray-windows-64.zip", ArchiveSHA256: "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad"},
}

type bootstrapWindowsDependencies struct {
	architecture string
	elevated     func() bool
	lookPath     func(string) (string, error)
	run          func(context.Context, string, ...string) error
	client       *http.Client
	now          func() time.Time
	artifact     managedRuntimeArtifact
}

func bootstrapPlatform(ctx context.Context, options BootstrapOptions) (BootstrapResult, error) {
	artifact, ok := windowsManagedXrayArtifacts[goruntime.GOARCH]
	if !ok {
		return BootstrapResult{}, fault.New(fault.CodeRuntimeUnavailable, "select managed Xray artifact", nil)
	}
	return bootstrapWindows(ctx, options, bootstrapWindowsDependencies{architecture: goruntime.GOARCH,
		elevated: func() bool { return windows.GetCurrentProcessToken().IsElevated() }, lookPath: lookPathWindowsRuntime,
		run: runWindowsBootstrapCommand, client: &http.Client{Timeout: 2 * time.Minute},
		now: func() time.Time { return time.Now().UTC() }, artifact: artifact})
}

func bootstrapWindows(ctx context.Context, options BootstrapOptions, dependencies bootstrapWindowsDependencies) (BootstrapResult, error) {
	if dependencies.elevated == nil || dependencies.lookPath == nil || dependencies.run == nil || dependencies.client == nil || dependencies.now == nil {
		return BootstrapResult{}, fault.New(fault.CodeInvalidInput, "initialize Windows runtime bootstrap dependencies", nil)
	}
	if !dependencies.elevated() {
		return BootstrapResult{}, fault.New(fault.CodeRuntimePermission, "bootstrap managed runtime", nil)
	}
	if err := ensureWindowsSystemRuntime(ctx, options.InstallSystemPackages, dependencies); err != nil {
		return BootstrapResult{}, err
	}
	return installManagedXray(ctx, options, dependencies.artifact, "windows", dependencies.architecture, dependencies.client, dependencies.now)
}

func ensureWindowsSystemRuntime(ctx context.Context, install bool, dependencies bootstrapWindowsDependencies) error {
	if missingCommands([]string{"wireguard.exe", "wg.exe"}, dependencies.lookPath) == 0 {
		return nil
	}
	if !install {
		return fault.New(fault.CodeRuntimeDependency, "locate WireGuard for Windows", nil)
	}
	winget, err := exec.LookPath("winget.exe")
	if err != nil {
		return fault.New(fault.CodeRuntimeDependency, "locate winget for WireGuard installation", err)
	}
	if err := dependencies.run(ctx, winget, "install", "--id", "WireGuard.WireGuard", "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements"); err != nil {
		return fault.New(fault.CodeRuntimeDependency, "install WireGuard for Windows", nil)
	}
	if missingCommands([]string{"wireguard.exe", "wg.exe"}, dependencies.lookPath) != 0 {
		return fault.New(fault.CodeRuntimeDependency, "verify WireGuard for Windows", nil)
	}
	return nil
}

func lookPathWindowsRuntime(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	candidate := filepath.Join(programFiles, "WireGuard", name)
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		return candidate, nil
	}
	return "", os.ErrNotExist
}

func runWindowsBootstrapCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	return command.Run()
}
