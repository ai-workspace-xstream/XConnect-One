//go:build !linux

package runtime

import (
	"context"
	"errors"
)

// unsupportedDesktopBackend keeps cross-platform builds safe. The external
// command runtime is constructed only on Linux; Apple hosts must provide a
// Packet Tunnel host runtime and other platforms remain fail-closed.
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
