//go:build darwin

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// osDesktopBackend owns only the external CLI runtime. It deliberately does
// not invoke NetworkExtension or inspect XConnect APP state; the APP plugin is
// a separate optional composition mode.
type osDesktopBackend struct{}

func newOSDesktopBackend() *osDesktopBackend { return &osDesktopBackend{} }

func (b *osDesktopBackend) LookPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return canonicalPath(path), nil
}

func (b *osDesktopBackend) Privileged() bool { return os.Geteuid() == 0 }

func (b *osDesktopBackend) InterfaceIndex(name string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}
	return 0, nil
}

func (b *osDesktopBackend) Run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func (b *osDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	command := exec.Command(executable, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = detachedProcessAttributes()
	if err := command.Start(); err != nil {
		return processIdentity{}, err
	}
	identity := processIdentity{
		PID:          command.Process.Pid,
		Executable:   canonicalPath(executable),
		ConfigPath:   configArgument(args),
		ConfigSHA256: configDigest,
		Revision:     revision,
	}
	token, err := darwinProcessStartToken(identity.PID)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Process.Release()
		return processIdentity{}, err
	}
	identity.StartToken = token
	if err := command.Process.Release(); err != nil {
		_ = command.Process.Kill()
		return processIdentity{}, err
	}
	return identity, nil
}

func detachedProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func (b *osDesktopBackend) ProcessAlive(identity processIdentity) (bool, error) {
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" || identity.ConfigPath == "" {
		return false, errors.New("incomplete process identity")
	}
	commandLine, err := darwinPS(identity.PID, "command=")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fields := strings.Fields(commandLine)
	if len(fields) == 0 || canonicalPath(fields[0]) != canonicalPath(identity.Executable) {
		return false, errors.New("executable identity mismatch")
	}
	token, err := darwinProcessStartToken(identity.PID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || token != identity.StartToken {
		return false, errors.New("process start identity mismatch")
	}
	return true, nil
}

func (b *osDesktopBackend) Stop(identity processIdentity) error {
	alive, err := b.ProcessAlive(identity)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	process, err := os.FindProcess(identity.PID)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		alive, err = b.ProcessAlive(identity)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
	}
	alive, err = b.ProcessAlive(identity)
	if err != nil || !alive {
		return err
	}
	return process.Signal(syscall.SIGKILL)
}

func (b *osDesktopBackend) LoopbackAvailable(address string) (bool, error) {
	listener, err := net.ListenPacket("udp4", address)
	if err == nil {
		_ = listener.Close()
		return true, nil
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return false, nil
	}
	return false, err
}

func (b *osDesktopBackend) LoopbackOwned(identity processIdentity, address string) (bool, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return false, err
	}
	// lsof is present on supported macOS releases. Its output is discarded: it
	// can contain user paths and is only used as an ownership predicate.
	command := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(identity.PID), "-iUDP@"+address)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err == nil {
		return true, nil
	} else if _, ok := err.(*exec.ExitError); ok {
		return false, nil
	} else {
		return false, err
	}
}

func darwinProcessStartToken(pid int) (string, error) {
	started, err := darwinPS(pid, "lstart=")
	if err != nil {
		return "", err
	}
	command, err := darwinPS(pid, "command=")
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(started + "\n" + command))
	return hex.EncodeToString(digest[:]), nil
}

func darwinPS(pid int, field string) (string, error) {
	command := exec.Command("/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", field)
	raw, err := command.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", os.ErrNotExist
		}
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", os.ErrNotExist
	}
	return value, nil
}

func canonicalPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err == nil {
		path = absolute
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		path = resolved
	}
	return filepath.Clean(path)
}
