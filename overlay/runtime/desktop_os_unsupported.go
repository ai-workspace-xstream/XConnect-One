//go:build !linux && !darwin && !windows

package runtime

import (
	"context"
	"errors"
	"os"
)

// unsupportedDesktopBackend keeps cross-platform builds safe. Apple hosts
// must provide a Packet Tunnel host runtime and other platforms remain
// fail-closed.
type unsupportedDesktopBackend struct{}

func newOSDesktopBackend() *unsupportedDesktopBackend { return &unsupportedDesktopBackend{} }

func (b *unsupportedDesktopBackend) LookPath(string) (string, error) {
	return "", errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) Privileged() bool { return false }

// Modified for XConnect-One: fail closed on unsupported platforms.
func (b *unsupportedDesktopBackend) InterfaceIndex(string) (int, error) {
	return 0, errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) Run(context.Context, string, ...string) error {
	return errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) Start(string, []string, string, string) (processIdentity, error) {
	return processIdentity{}, errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) ProcessAlive(processIdentity) (bool, error) {
	return false, errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) Stop(processIdentity) error {
	return errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) LoopbackAvailable(string) (bool, error) {
	return false, errors.New("external desktop runtime is Linux-only")
}

func (b *unsupportedDesktopBackend) LoopbackOwned(processIdentity, string) (bool, error) {
	return false, errors.New("external desktop runtime is Linux-only")
}

func secureDirectoryPlatform(path string) error { return os.Chmod(path, 0o700) }

func secureFilePlatform(path string) error { return os.Chmod(path, 0o600) }

func replaceRuntimeFile(source, target string) error { return os.Rename(source, target) }

func privateDirectoryPlatform(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm() == 0o700
}

func privateRegularFilePlatform(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}
