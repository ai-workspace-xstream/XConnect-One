//go:build windows

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsWireGuardExecutable = "wireguard.exe"
	windowsWireGuardCLI        = "wg.exe"
	windowsStillActive         = 259
	windowsWaitTimeout         = 0x00000102
	windowsAFInet              = 2
	windowsUDPTableOwnerPID    = 1
	windowsUDPRowSize          = 20
	windowsWSAEAddrInUse       = syscall.Errno(10048)
	windowsMaxUDPTableSize     = 16 << 20
	windowsPrivateRuntimeSDDL  = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
)

var iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
var procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")

// NewWindowsDesktop selects the external Xray plus WireGuard-for-Windows
// tunnel-service runtime. The implementation is available only in a native
// Windows build; the non-Windows stub keeps platform selection tests and
// Apple/mobile fail-closed behavior intact.
func NewWindowsDesktop(stateDirectory string) Interface {
	return newDesktop(stateDirectory, newOSDesktopBackend())
}

type windowsDesktopBackend struct{}

func newOSDesktopBackend() *windowsDesktopBackend { return &windowsDesktopBackend{} }

func (b *windowsDesktopBackend) LookPath(name string) (string, error) {
	tool := windowsToolName(name)
	path, err := exec.LookPath(tool)
	if err != nil && (tool == windowsWireGuardExecutable || tool == windowsWireGuardCLI) {
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		candidate := filepath.Join(programFiles, "WireGuard", tool)
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			path, err = candidate, nil
		}
	}
	if err != nil {
		return "", err
	}
	info, statErr := os.Stat(path)
	if statErr != nil || !info.Mode().IsRegular() {
		if statErr == nil {
			statErr = errors.New("runtime executable is not a regular file")
		}
		return "", statErr
	}
	return canonicalPath(path), nil
}

func windowsToolName(name string) string {
	switch strings.ToLower(name) {
	case "xray":
		return "xray.exe"
	case "wg":
		return windowsWireGuardCLI
	case "wg-quick":
		// The logical wg-quick operations are translated by Run to the
		// official WireGuard for Windows tunnel-service CLI.
		return windowsWireGuardExecutable
	default:
		return name
	}
}

func (b *windowsDesktopBackend) Privileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (b *windowsDesktopBackend) InterfaceIndex(name string) (int, error) {
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

// WireGuardServiceState checks both existence and ownership. A tunnel name
// alone is not sufficient for destructive cleanup: the service must be the
// official WireGuard tunnel service pointing at this exact executable and
// this exact XConnect-owned configuration file.
func (b *windowsDesktopBackend) WireGuardServiceState(interfaceName, executable, configPath string) (bool, bool, error) {
	tunnelName, err := validateWindowsTunnelName(interfaceName)
	if err != nil {
		return false, false, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsTunnelServiceName(tunnelName))
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		// The service may belong to another actor; a marked-for-delete
		// service cannot be inspected safely, so fail closed.
		return true, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer service.Close()
	configuration, err := service.Config()
	if err != nil {
		return true, false, err
	}
	arguments, err := windows.DecomposeCommandLine(configuration.BinaryPathName)
	if err != nil || len(arguments) != 3 {
		return true, false, nil
	}
	owned := sameWindowsPath(arguments[0], executable) &&
		strings.EqualFold(arguments[1], "/tunnelservice") &&
		sameWindowsPath(arguments[2], configPath)
	return true, owned, nil
}

func windowsTunnelServiceName(tunnelName string) string {
	return "WireGuardTunnel$" + tunnelName
}

func (b *windowsDesktopBackend) Run(ctx context.Context, name string, args ...string) error {
	if isWindowsWireGuardExecutable(name) && len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "up":
			if len(args) != 2 {
				return errors.New("invalid WireGuard tunnel start arguments")
			}
			return b.installTunnel(ctx, name, args[1])
		case "down":
			if len(args) != 2 {
				return errors.New("invalid WireGuard tunnel stop arguments")
			}
			return b.uninstallTunnel(ctx, name, args[1])
		}
	}
	return runWindowsCommand(ctx, name, args...)
}

func isWindowsWireGuardExecutable(path string) bool {
	return strings.EqualFold(filepath.Base(path), windowsWireGuardExecutable)
}

func windowsWireGuardServiceArgs(operation, configPath string) ([]string, string, error) {
	tunnelName, err := validateWindowsTunnelConfigPath(configPath)
	if err != nil {
		return nil, "", err
	}
	switch strings.ToLower(operation) {
	case "up":
		return []string{"/installtunnelservice", configPath}, tunnelName, nil
	case "down":
		return []string{"/uninstalltunnelservice", tunnelName}, tunnelName, nil
	default:
		return nil, "", errors.New("unsupported WireGuard tunnel operation")
	}
}

func validateWindowsTunnelConfigPath(configPath string) (string, error) {
	base := filepath.Base(configPath)
	if len(base) <= len(".conf") || !strings.EqualFold(filepath.Ext(base), ".conf") {
		return "", errors.New("WireGuard tunnel configuration must end in .conf")
	}
	return validateWindowsTunnelName(strings.TrimSuffix(base, filepath.Ext(base)))
}

func validateWindowsTunnelName(name string) (string, error) {
	if len(name) == 0 || len(name) > 15 {
		return "", errors.New("invalid WireGuard tunnel name")
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '=' || character == '+' || character == '-' || character == '.' {
			continue
		}
		return "", errors.New("invalid WireGuard tunnel name")
	}
	return name, nil
}

func (b *windowsDesktopBackend) installTunnel(ctx context.Context, executable, configPath string) error {
	arguments, tunnelName, err := windowsWireGuardServiceArgs("up", configPath)
	if err != nil {
		return err
	}
	if err := runWindowsCommand(ctx, executable, arguments...); err != nil {
		return err
	}
	if err := b.waitForInterface(ctx, tunnelName, true); err != nil {
		// The install command returned success, so the named service is now
		// ours. Compensate for readiness failure using the same exact name;
		// if compensation fails, the service remains for manual review.
		cleanupContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cleanupArgs := []string{"/uninstalltunnelservice", tunnelName}
		if cleanupErr := runWindowsCommand(cleanupContext, executable, cleanupArgs...); cleanupErr == nil {
			_ = b.waitForInterfaceAndServiceGone(cleanupContext, tunnelName)
		}
		return err
	}
	return nil
}

func (b *windowsDesktopBackend) uninstallTunnel(ctx context.Context, executable, configPath string) error {
	arguments, tunnelName, err := windowsWireGuardServiceArgs("down", configPath)
	if err != nil {
		return err
	}
	if err := runWindowsCommand(ctx, executable, arguments...); err != nil {
		// A concurrent cleanup may have completed between the ownership check
		// and this command. Treat that exact empty state as idempotent.
		index, indexErr := b.InterfaceIndex(tunnelName)
		serviceExists, serviceErr := b.tunnelServiceExists(tunnelName)
		if indexErr == nil && serviceErr == nil && index == 0 && !serviceExists {
			return nil
		}
		return err
	}
	return b.waitForInterfaceAndServiceGone(ctx, tunnelName)
}

func runWindowsCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return command.Run()
}

func (b *windowsDesktopBackend) waitForInterface(ctx context.Context, name string, wantUp bool) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		index, err := b.InterfaceIndex(name)
		if err != nil {
			return err
		}
		if (wantUp && index > 0) || (!wantUp && index == 0) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (b *windowsDesktopBackend) waitForInterfaceAndServiceGone(ctx context.Context, name string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		index, err := b.InterfaceIndex(name)
		if err != nil {
			return err
		}
		serviceExists, err := b.tunnelServiceExists(name)
		if err != nil {
			return err
		}
		if index == 0 && !serviceExists {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (b *windowsDesktopBackend) tunnelServiceExists(tunnelName string) (bool, error) {
	name, err := validateWindowsTunnelName(tunnelName)
	if err != nil {
		return false, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsTunnelServiceName(name))
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return true, service.Close()
}

func (b *windowsDesktopBackend) Start(executable string, args []string, revision, configDigest string) (processIdentity, error) {
	command := exec.Command(executable, args...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
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
	startToken, err := windowsProcessStartToken(identity.PID)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return processIdentity{}, err
	}
	identity.StartToken = startToken
	if err := command.Process.Release(); err != nil {
		_ = command.Process.Kill()
		return processIdentity{}, err
	}
	return identity, nil
}

func (b *windowsDesktopBackend) ProcessAlive(identity processIdentity) (bool, error) {
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" || identity.ConfigPath == "" {
		return false, errors.New("incomplete process identity")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(identity.PID))
	if isWindowsProcessGone(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)
	return windowsProcessMatches(handle, identity)
}

func isWindowsProcessGone(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND)
}

func windowsProcessMatches(handle windows.Handle, identity processIdentity) (bool, error) {
	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false, err
	}
	if exitCode != windowsStillActive {
		return false, nil
	}
	executable, err := windowsProcessExecutable(handle)
	if err != nil {
		return false, err
	}
	if !sameWindowsPath(executable, identity.Executable) {
		return false, errors.New("executable identity mismatch")
	}
	startToken, err := windowsProcessStartTokenFromHandle(handle)
	if err != nil {
		return false, err
	}
	if startToken != identity.StartToken {
		return false, errors.New("process start identity mismatch")
	}
	return true, nil
}

func windowsProcessExecutable(handle windows.Handle) (string, error) {
	bufferSize := uint32(windows.MAX_PATH)
	for {
		buffer := make([]uint16, bufferSize)
		length := bufferSize
		err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &length)
		if err == nil {
			return canonicalPath(windows.UTF16ToString(buffer[:length])), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || length <= bufferSize {
			return "", err
		}
		bufferSize = length + 1
	}
}

func windowsProcessStartToken(pid int) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	return windowsProcessStartTokenFromHandle(handle)
}

func windowsProcessStartTokenFromHandle(handle windows.Handle) (string, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x%08x", creation.HighDateTime, creation.LowDateTime), nil
}

func (b *windowsDesktopBackend) Stop(identity processIdentity) error {
	if identity.PID <= 0 || identity.StartToken == "" || identity.Executable == "" {
		return errors.New("incomplete process identity")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(identity.PID))
	if isWindowsProcessGone(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	alive, err := windowsProcessMatches(handle, identity)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	if err := windows.TerminateProcess(handle, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	result, err := windows.WaitForSingleObject(handle, 2000)
	if err != nil {
		return err
	}
	if result == windows.WAIT_OBJECT_0 {
		return nil
	}
	if result == windowsWaitTimeout {
		return errors.New("Xray process did not stop before timeout")
	}
	return errors.New("Xray process stop wait failed")
}

func (b *windowsDesktopBackend) LoopbackAvailable(address string) (bool, error) {
	listener, err := net.ListenPacket("udp4", address)
	if err == nil {
		_ = listener.Close()
		return true, nil
	}
	if errors.Is(err, windowsWSAEAddrInUse) {
		return false, nil
	}
	return false, err
}

func (b *windowsDesktopBackend) LoopbackOwned(identity processIdentity, address string) (bool, error) {
	if identity.PID <= 0 {
		return false, errors.New("invalid Xray process identity")
	}
	host, portValue, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return false, errors.New("invalid loopback address")
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil {
		return false, err
	}
	table, err := windowsUDPTable()
	if err != nil {
		return false, err
	}
	if len(table) < 4 {
		return false, errors.New("invalid UDP table")
	}
	count := binary.LittleEndian.Uint32(table[:4])
	if count > uint32((len(table)-4)/windowsUDPRowSize) {
		return false, errors.New("invalid UDP table row count")
	}
	for index := uint32(0); index < count; index++ {
		offset := 4 + int(index)*windowsUDPRowSize
		// MIB_UDPROW_OWNER_PID stores ports in network byte order and the
		// owning PID as the final DWORD.
		candidatePort := binary.BigEndian.Uint16(table[offset+4 : offset+6])
		candidatePID := binary.LittleEndian.Uint32(table[offset+16 : offset+20])
		if candidatePort == uint16(port) && candidatePID == uint32(identity.PID) {
			return true, nil
		}
	}
	return false, nil
}

func windowsUDPTable() ([]byte, error) {
	var size uint32
	result, _, _ := procGetExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, windowsAFInet, windowsUDPTableOwnerPID, 0)
	if result != 0 && result != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, syscall.Errno(result)
	}
	if size == 0 {
		return []byte{0, 0, 0, 0}, nil
	}
	if size > windowsMaxUDPTableSize {
		return nil, errors.New("UDP table is unexpectedly large")
	}
	buffer := make([]byte, size)
	result, _, _ = procGetExtendedUDPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 1, windowsAFInet, windowsUDPTableOwnerPID, 0)
	if result != 0 {
		return nil, syscall.Errno(result)
	}
	return buffer[:size], nil
}

func secureDirectoryPlatform(path string) error { return setWindowsPrivateACL(path) }

func secureFilePlatform(path string) error { return setWindowsPrivateACL(path) }

func replaceRuntimeFile(source, target string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePath, targetPath, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func privateDirectoryPlatform(path string) bool { return hasWindowsPrivateACL(path) }

func privateRegularFilePlatform(path string) bool { return hasWindowsPrivateACL(path) }

func setWindowsPrivateACL(path string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString(windowsPrivateRuntimeSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func hasWindowsPrivateACL(path string) bool {
	// Include the owner: the explicit owner ACE created from `OW` is rendered
	// as that concrete SID when Windows reads the descriptor back.
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil || securityDescriptor == nil {
		return false
	}
	control, _, err := securityDescriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	return matchesWindowsPrivateDACL(securityDescriptor.String())
}

func matchesWindowsPrivateDACL(sddl string) bool {
	// Owner and group sections normally precede `D:` in Windows SDDL.  Compare
	// the protected DACL itself, not the complete descriptor string. Windows
	// resolves the `OW` placeholder used while creating the ACL to the concrete
	// owner SID when the descriptor is read back, so that final ACE must match
	// the descriptor's actual owner rather than the literal `OW` token.
	owner := windowsSDDLOwner(sddl)
	if owner == "" {
		return false
	}
	daclOffset := strings.Index(sddl, "D:")
	if daclOffset < 0 {
		return false
	}
	body := strings.TrimPrefix(sddl[daclOffset+len("D:"):], "P")
	if body == sddl[daclOffset+len("D:"):] {
		return false
	}
	// `AI` records auto-inheritance metadata and does not add a principal.
	body = strings.TrimPrefix(body, "AI")
	for _, ace := range []string{"(A;;FA;;;SY)", "(A;;FA;;;BA)"} {
		if strings.Count(body, ace) != 1 {
			return false
		}
		body = strings.Replace(body, ace, "", 1)
	}
	// Depending on object inheritance, Windows preserves the original `OW`
	// alias or renders it as the resolved descriptor owner. Both forms grant
	// full access solely to the owner and are safe; reject every other ACE.
	return body == "(A;;FA;;;OW)" || body == "(A;;FA;;;"+owner+")"
}

func windowsSDDLOwner(sddl string) string {
	if !strings.HasPrefix(sddl, "O:") {
		return ""
	}
	end := len(sddl)
	for _, marker := range []string{"G:", "D:", "S:"} {
		if index := strings.Index(sddl[2:], marker); index >= 0 && index+2 < end {
			end = index + 2
		}
	}
	return sddl[2:end]
}

func sameWindowsPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
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
	return strings.ToLower(filepath.Clean(path))
}
