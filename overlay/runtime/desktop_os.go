//go:build linux

package runtime

import (
	"bufio"
	"context"
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

// Modified for XConnect-One: inspect identity, distinguishing absence from errors.
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
	// The CLI is commonly invoked through a short-lived SSH or sudo session.
	// A separate process group is not enough: the external runtime would still
	// belong to that login session and receive its hangup when `xconnect` exits.
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
	startToken, err := linuxProcessStartToken(identity.PID)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Process.Release()
		return processIdentity{}, err
	}
	identity.StartToken = startToken
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
	procDirectory := filepath.Join("/proc", strconv.Itoa(identity.PID))
	executable, err := os.Readlink(filepath.Join(procDirectory, "exe"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if canonicalPath(executable) != canonicalPath(identity.Executable) {
		return false, errors.New("executable identity mismatch")
	}
	startToken, err := linuxProcessStartToken(identity.PID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || startToken != identity.StartToken {
		return false, errors.New("process start identity mismatch")
	}
	cmdline, err := os.ReadFile(filepath.Join(procDirectory, "cmdline"))
	if err != nil {
		return false, err
	}
	arguments := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if !containsConfigArgument(arguments, identity.ConfigPath) {
		return false, errors.New("process config identity mismatch")
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
	_, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return false, err
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil {
		return false, err
	}
	inodes, err := processSocketInodes(identity.PID)
	if err != nil {
		return false, err
	}
	file, err := os.Open("/proc/net/udp")
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[1] == "local_address" {
			continue
		}
		addressParts := strings.Split(fields[1], ":")
		if len(addressParts) != 2 || addressParts[0] != "0100007F" {
			continue
		}
		candidatePort, parseErr := strconv.ParseUint(addressParts[1], 16, 16)
		if parseErr == nil && candidatePort == port {
			if _, ok := inodes[fields[9]]; ok {
				return true, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func processSocketInodes(pid int) (map[string]struct{}, error) {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, err
	}
	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return inodes, nil
}

func linuxProcessStartToken(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closingParenthesis := strings.LastIndexByte(string(raw), ')')
	if closingParenthesis < 0 || closingParenthesis+2 >= len(raw) {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[closingParenthesis+2:]))
	if len(fields) <= 19 {
		return "", errors.New("incomplete process stat")
	}
	return fields[19], nil
}

func containsConfigArgument(args []string, expected string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-config" && filepath.Clean(args[index+1]) == filepath.Clean(expected) {
			return true
		}
	}
	return false
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
