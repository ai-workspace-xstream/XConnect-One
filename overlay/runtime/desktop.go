// Modified for XConnect-One: standalone imports and interface ownership safeguards.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

const desktopManifestVersion = 1

var errRuntimeArtifactNotFound = errors.New("runtime artifact not found")

type processIdentity struct {
	PID          int    `json:"pid"`
	Executable   string `json:"executable"`
	ConfigPath   string `json:"config_path"`
	ConfigSHA256 string `json:"config_sha256"`
	Revision     string `json:"revision"`
	StartToken   string `json:"start_token"`
}

type desktopManifest struct {
	SchemaVersion   int             `json:"schema_version"`
	Revision        string          `json:"revision"`
	CoreID          string          `json:"core_id"`
	AdapterID       string          `json:"adapter_id"`
	Interface       string          `json:"interface"`
	LoopbackAddress string          `json:"loopback_address"`
	XrayConfigPath  string          `json:"xray_config_path"`
	WGConfigPath    string          `json:"wireguard_config_path"`
	WGConfigSHA256  string          `json:"wireguard_config_sha256"`
	Xray            processIdentity `json:"xray_process"`
	WireGuardUp     bool            `json:"wireguard_up"`
	InterfaceIndex  int             `json:"interface_index"`
	Stopped         bool            `json:"stopped,omitempty"`
	AppliedAt       time.Time       `json:"applied_at"`
}

type desktopBackend interface {
	LookPath(string) (string, error)
	Privileged() bool
	InterfaceIndex(string) (int, error)
	Run(context.Context, string, ...string) error
	Start(string, []string, string, string) (processIdentity, error)
	ProcessAlive(processIdentity) (bool, error)
	Stop(processIdentity) error
	LoopbackAvailable(string) (bool, error)
	LoopbackOwned(processIdentity, string) (bool, error)
}

// Desktop applies the external Xray and WireGuard desktop runtime as one
// transaction. The backend is injectable so tests never start processes or
// mutate host networking. Linux uses wg-quick; Windows maps the same logical
// operations to WireGuard for Windows tunnel services.
type Desktop struct {
	stateDirectory   string
	dir              string
	backend          desktopBackend
	commandTimeout   time.Duration
	readinessTimeout time.Duration
	mu               sync.Mutex
}

func NewLinuxDesktop(stateDirectory string) *Desktop {
	return newDesktop(stateDirectory, newOSDesktopBackend())
}

// NewMacOSDesktop runs the same controlled-client lifecycle through the
// macOS external Xray/WireGuard toolchain. It is intentionally a standalone
// CLI runtime, independent of the optional XConnect APP plugin host.
func NewMacOSDesktop(stateDirectory string) *Desktop {
	return newDesktop(stateDirectory, newOSDesktopBackend())
}

// wireGuardServiceBackend is implemented by platforms whose WireGuard
// lifecycle is represented by an OS service rather than a process/interface
// pair. The optional interface keeps the Linux backend and its contract
// unchanged while allowing Windows to refuse or remove a service that has no
// visible adapter yet.
type wireGuardServiceBackend interface {
	WireGuardServiceState(interfaceName, executable, configPath string) (exists, owned bool, err error)
}

// wireGuardInterfaceResolver is implemented by Darwin, where wg-quick keeps
// the configured logical name in the manifest but wireguard-go creates a
// kernel-visible utunN interface.
type wireGuardInterfaceResolver interface {
	WireGuardInterfaceName(string) (string, error)
}

func (r *Desktop) wireGuardServiceState(interfaceName, executable, configPath string) (bool, bool, error) {
	backend, ok := r.backend.(wireGuardServiceBackend)
	if !ok {
		return false, false, nil
	}
	return backend.WireGuardServiceState(interfaceName, executable, configPath)
}

func newDesktop(stateDirectory string, backend desktopBackend) *Desktop {
	stateDirectory = filepath.Clean(stateDirectory)
	return &Desktop{
		stateDirectory:   stateDirectory,
		dir:              filepath.Join(stateDirectory, "runtime"),
		backend:          backend,
		commandTimeout:   10 * time.Second,
		readinessTimeout: 3 * time.Second,
	}
}

func (r *Desktop) Apply(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := request.Config.Validate(); err != nil {
		return ApplyResult{}, err
	}
	if request.Config.CoreID() != model.CoreIDXray {
		return ApplyResult{}, fault.New(fault.CodeUnsupportedRuntimeCore, "apply desktop runtime", nil)
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.WireGuardPrivateKey))
	if err != nil || len(privateKey) != 32 {
		return ApplyResult{}, fault.New(fault.CodeInvalidConfig, "validate WireGuard private key", nil)
	}
	dependencies, err := r.dependencies()
	if err != nil {
		return ApplyResult{}, err
	}
	if !r.backend.Privileged() {
		return ApplyResult{}, fault.New(fault.CodeRuntimePermission, "apply desktop runtime", nil)
	}
	if err := secureDirectory(r.dir); err != nil {
		return ApplyResult{}, err
	}

	active, activeErr := r.loadManifest(r.activeManifestPath())
	if activeErr != nil && !errors.Is(activeErr, errRuntimeArtifactNotFound) {
		return ApplyResult{}, activeErr
	}
	if activeErr == nil {
		if active.Stopped && active.Revision == request.Config.Revision {
			if !r.manifestMetadataTrusted(active, dependencies) {
				return ApplyResult{}, fault.New(fault.CodeRuntimeProcessStale, "verify stopped runtime metadata ownership", nil)
			}
			activated, startErr := r.startManifest(ctx, active, dependencies)
			if startErr != nil {
				return ApplyResult{}, startErr
			}
			if err := r.saveManifest(r.activeManifestPath(), activated); err != nil {
				_ = r.stopManifest(ctx, activated, dependencies)
				return ApplyResult{}, err
			}
			return applyResult(request.Config), nil
		}
		healthy, healthErr := r.manifestHealthy(ctx, active, dependencies)
		if healthErr != nil && fault.Code(healthErr) == fault.CodeRuntimeProcessStale {
			return ApplyResult{}, healthErr
		}
		if healthy && active.Revision == request.Config.Revision {
			if err := r.cleanupRetainedRevisions(active); err != nil {
				return ApplyResult{}, err
			}
			return applyResult(request.Config), nil
		}
	}

	candidate, err := r.prepare(request, dependencies.xray)
	if err != nil {
		return ApplyResult{}, err
	}
	candidateRetained := false
	defer func() {
		if !candidateRetained {
			_ = r.removeRevision(candidate)
		}
	}()
	if err := r.run(ctx, dependencies.xray, "run", "-test", "-config", candidate.XrayConfigPath); err != nil {
		return ApplyResult{}, fault.New(fault.CodeRuntimeApplyFailed, "test Xray config", nil)
	}

	var previous *desktopManifest
	if activeErr == nil {
		previous = &active
		if !r.manifestMetadataTrusted(active, dependencies) {
			return ApplyResult{}, fault.New(fault.CodeRuntimeProcessStale, "verify runtime metadata ownership", nil)
		}
		if !active.Stopped {
			if _, err := r.processTrusted(active); err != nil {
				return ApplyResult{}, err
			}
			if err := r.stopManifest(ctx, active, dependencies); err != nil {
				return ApplyResult{}, err
			}
		}
	}

	activated, err := r.startManifest(ctx, candidate, dependencies)
	if err != nil {
		return ApplyResult{}, r.rollback(ctx, candidate, previous, dependencies, err)
	}
	if previous != nil {
		if err := r.saveManifest(r.lastKnownGoodPath(), *previous); err != nil {
			return ApplyResult{}, r.rollback(ctx, activated, previous, dependencies, err)
		}
	}
	if err := r.saveManifest(r.activeManifestPath(), activated); err != nil {
		return ApplyResult{}, r.rollback(ctx, activated, previous, dependencies, err)
	}
	candidateRetained = true
	if err := r.cleanupRetainedRevisions(activated); err != nil {
		return ApplyResult{}, err
	}
	return applyResult(request.Config), nil
}

func (r *Desktop) Status(ctx context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := Status{}
	if managed, ok := loadManagedRuntimeManifest(r.stateDirectory); ok {
		result.ManagedRuntime = true
		result.RuntimeVersion = managed.XrayVersion
	}
	dependencies, err := r.dependencies()
	if err != nil || !r.backend.Privileged() {
		return result, nil
	}
	result.Available = true
	manifest, err := r.loadManifest(r.activeManifestPath())
	if errors.Is(err, errRuntimeArtifactNotFound) {
		return result, nil
	}
	if err != nil {
		return Status{}, err
	}
	interfaceName := manifest.Interface
	if resolver, ok := r.backend.(wireGuardInterfaceResolver); ok {
		resolved, resolveErr := resolver.WireGuardInterfaceName(manifest.Interface)
		if resolveErr != nil {
			interfaceName = ""
		} else {
			interfaceName = resolved
		}
	}
	healthy, healthErr := r.manifestHealthy(ctx, manifest, dependencies)
	if healthErr != nil && fault.Code(healthErr) != fault.CodeRuntimeProcessStale {
		return Status{}, healthErr
	}
	result.Applied = healthy
	result.Revision = manifest.Revision
	result.CoreID = manifest.CoreID
	result.AdapterID = manifest.AdapterID
	result.Interface = interfaceName
	return result, nil
}

// Down stops only the process and interface described by trusted XConnect
// runtime metadata. The stopped manifest is retained so Up can recover without
// refetching configuration or acknowledging it again.
func (r *Desktop) Down(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	dependencies, err := r.dependencies()
	if err != nil {
		return err
	}
	if !r.backend.Privileged() {
		return fault.New(fault.CodeRuntimePermission, "stop desktop runtime", nil)
	}
	manifest, err := r.loadManifest(r.activeManifestPath())
	if errors.Is(err, errRuntimeArtifactNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !r.manifestMetadataTrusted(manifest, dependencies) {
		return fault.New(fault.CodeRuntimeProcessStale, "verify runtime metadata ownership", nil)
	}
	if manifest.Stopped {
		return nil
	}
	if err := r.stopManifest(ctx, manifest, dependencies); err != nil {
		return err
	}
	manifest.Stopped = true
	manifest.WireGuardUp = false
	manifest.Xray.PID = 0
	manifest.Xray.StartToken = ""
	return r.saveManifest(r.activeManifestPath(), manifest)
}

// Cleanup removes only manifests and revision directories that are proven to
// belong to this runtime. Unknown files are retained and make the parent
// directory non-empty; they are never recursively deleted.
func (r *Desktop) Cleanup(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	manifests := make([]desktopManifest, 0, 2)
	for _, path := range []string{r.activeManifestPath(), r.lastKnownGoodPath()} {
		manifest, loadErr := r.loadManifest(path)
		if errors.Is(loadErr, errRuntimeArtifactNotFound) {
			continue
		}
		if loadErr != nil {
			return loadErr
		}
		if !r.manifestMetadataTrusted(manifest, desktopDependencies{xray: manifest.Xray.Executable}) {
			return fault.New(fault.CodeRuntimeProcessStale, "verify cleanup metadata ownership", nil)
		}
		if path == r.activeManifestPath() && !manifest.Stopped {
			return fault.New(fault.CodeRuntimeApplyFailed, "cleanup active runtime", nil)
		}
		manifests = append(manifests, manifest)
	}
	for _, manifest := range manifests {
		if directory, ok := r.revisionDirectory(manifest); ok {
			for _, path := range []string{manifest.XrayConfigPath, manifest.WGConfigPath} {
				if err := removeOwnedRegularFile(path); err != nil {
					return err
				}
			}
			_ = os.Remove(directory)
		}
	}
	for _, path := range []string{r.activeManifestPath(), r.lastKnownGoodPath()} {
		if err := removeOwnedRegularFile(path); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(r.dir, "revisions"))
	_ = os.Remove(r.dir)
	return nil
}

func (r *Desktop) Diagnose(ctx context.Context) ([]Diagnostic, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	xrayPath, xrayErr := r.lookupXray()
	wgPath, wgErr := r.backend.LookPath("wg")
	_, wgQuickErr := r.backend.LookPath("wg-quick")
	diagnostics := []Diagnostic{
		{Code: "platform_runtime_available", Healthy: xrayErr == nil && wgErr == nil && wgQuickErr == nil && r.backend.Privileged()},
		{Code: "desktop_runtime_privileged", Healthy: r.backend.Privileged()},
		{Code: "xray_dependency_available", Healthy: xrayErr == nil},
		{Code: "wireguard_dependency_available", Healthy: wgErr == nil && wgQuickErr == nil},
	}
	manifest, err := r.loadManifest(r.activeManifestPath())
	if errors.Is(err, errRuntimeArtifactNotFound) {
		return append(diagnostics,
			Diagnostic{Code: "runtime_metadata_valid", Healthy: false},
			Diagnostic{Code: "xray_process_healthy", Healthy: false},
			Diagnostic{Code: "xray_loopback_port_healthy", Healthy: false},
			Diagnostic{Code: "wireguard_interface_healthy", Healthy: false},
		), nil
	}
	if err != nil {
		return nil, err
	}
	metadataHealthy := r.manifestMetadataTrusted(manifest, desktopDependencies{xray: xrayPath})
	processHealthy := false
	portHealthy := false
	wgHealthy := false
	if metadataHealthy && xrayErr == nil && filepath.Clean(manifest.Xray.Executable) == filepath.Clean(xrayPath) {
		processHealthy, _ = r.processTrusted(manifest)
		if processHealthy {
			portHealthy, _ = r.backend.LoopbackOwned(manifest.Xray, manifest.LoopbackAddress)
		}
		if wgErr == nil && !manifest.Stopped && manifest.InterfaceIndex > 0 {
			index, indexErr := r.backend.InterfaceIndex(manifest.Interface)
			wgHealthy = indexErr == nil && index == manifest.InterfaceIndex && r.run(ctx, wgPath, "show", manifest.Interface) == nil
		}
	}
	return append(diagnostics,
		Diagnostic{Code: "runtime_metadata_valid", Healthy: metadataHealthy},
		Diagnostic{Code: "xray_process_healthy", Healthy: processHealthy},
		Diagnostic{Code: "xray_loopback_port_healthy", Healthy: portHealthy},
		Diagnostic{Code: "wireguard_interface_healthy", Healthy: wgHealthy},
	), nil
}

type desktopDependencies struct {
	xray    string
	wg      string
	wgQuick string
}

func (r *Desktop) dependencies() (desktopDependencies, error) {
	xray, err := r.lookupXray()
	if err != nil {
		return desktopDependencies{}, fault.New(fault.CodeRuntimeDependency, "locate Xray runtime", nil)
	}
	wg, err := r.backend.LookPath("wg")
	if err != nil {
		return desktopDependencies{}, fault.New(fault.CodeRuntimeDependency, "locate WireGuard runtime", nil)
	}
	wgQuick, err := r.backend.LookPath("wg-quick")
	if err != nil {
		return desktopDependencies{}, fault.New(fault.CodeRuntimeDependency, "locate WireGuard runtime", nil)
	}
	return desktopDependencies{xray: xray, wg: wg, wgQuick: wgQuick}, nil
}

func (r *Desktop) lookupXray() (string, error) {
	if managed, ok := resolveManagedXray(r.stateDirectory); ok {
		return managed, nil
	}
	return r.backend.LookPath("xray")
}

func (r *Desktop) prepare(request ApplyRequest, xrayPath string) (desktopManifest, error) {
	revisionHash := sha256.Sum256([]byte(request.Config.Revision))
	revisionsDirectory := filepath.Join(r.dir, "revisions")
	if err := secureDirectory(revisionsDirectory); err != nil {
		return desktopManifest{}, err
	}
	revisionDirectory, err := os.MkdirTemp(revisionsDirectory, hex.EncodeToString(revisionHash[:8])+"-")
	if err != nil {
		return desktopManifest{}, fault.New(fault.CodeStateIO, "create runtime revision", err)
	}
	if err := secureDirectory(revisionDirectory); err != nil {
		_ = os.RemoveAll(revisionDirectory)
		return desktopManifest{}, fault.New(fault.CodeStateIO, "secure runtime revision", err)
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = os.RemoveAll(revisionDirectory)
		}
	}()
	xrayConfig, err := renderXrayConfig(request.Config)
	if err != nil {
		return desktopManifest{}, fault.New(fault.CodeInvalidConfig, "render Xray config", nil)
	}
	wgConfig := renderWireGuardConfig(request.Config, request.WireGuardPrivateKey)
	xrayConfigPath := filepath.Join(revisionDirectory, "xray.json")
	wgConfigPath := filepath.Join(revisionDirectory, request.Config.WireGuard.Interface+".conf")
	if err := writeFile0600(xrayConfigPath, xrayConfig); err != nil {
		return desktopManifest{}, err
	}
	if err := writeFile0600(wgConfigPath, []byte(wgConfig)); err != nil {
		return desktopManifest{}, err
	}
	configHash := sha256.Sum256(xrayConfig)
	wgConfigHash := sha256.Sum256([]byte(wgConfig))
	manifest := desktopManifest{
		SchemaVersion:   desktopManifestVersion,
		Revision:        request.Config.Revision,
		CoreID:          request.Config.CoreID(),
		AdapterID:       model.AdapterIDXrayCore,
		Interface:       request.Config.WireGuard.Interface,
		LoopbackAddress: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", request.Config.Transport.LocalPort)),
		XrayConfigPath:  xrayConfigPath,
		WGConfigPath:    wgConfigPath,
		WGConfigSHA256:  hex.EncodeToString(wgConfigHash[:]),
		Xray: processIdentity{
			Executable:   xrayPath,
			ConfigPath:   xrayConfigPath,
			ConfigSHA256: hex.EncodeToString(configHash[:]),
			Revision:     request.Config.Revision,
		},
	}
	prepared = true
	return manifest, nil
}

func (r *Desktop) startManifest(ctx context.Context, manifest desktopManifest, dependencies desktopDependencies) (desktopManifest, error) {
	serviceExists, serviceOwned, serviceErr := r.wireGuardServiceState(manifest.Interface, dependencies.wgQuick, manifest.WGConfigPath)
	if serviceErr != nil {
		return desktopManifest{}, fault.New(fault.CodeRuntimeProcessStale, "inspect WireGuard tunnel service", nil)
	}
	if serviceExists {
		if !serviceOwned {
			return desktopManifest{}, fault.New(fault.CodeRuntimeProcessStale, "refuse unowned WireGuard tunnel service", nil)
		}
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "WireGuard tunnel service already exists", nil)
	}
	index, err := r.backend.InterfaceIndex(manifest.Interface)
	if err != nil || index != 0 {
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "WireGuard interface already exists or cannot be inspected", nil)
	}
	available, err := r.backend.LoopbackAvailable(manifest.LoopbackAddress)
	if err != nil || !available {
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "reserve Xray loopback port", nil)
	}
	identity, err := r.backend.Start(dependencies.xray, []string{"run", "-config", manifest.XrayConfigPath}, manifest.Revision, manifest.Xray.ConfigSHA256)
	if err != nil {
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "start Xray runtime", nil)
	}
	manifest.Xray = identity
	manifest.Xray.ConfigPath = manifest.XrayConfigPath
	manifest.Xray.ConfigSHA256 = identity.ConfigSHA256
	manifest.Xray.Revision = manifest.Revision
	if err := r.waitForXrayReady(ctx, manifest); err != nil {
		_ = r.backend.Stop(manifest.Xray)
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "verify Xray runtime", nil)
	}
	if err := r.run(ctx, dependencies.wgQuick, "up", manifest.WGConfigPath); err != nil {
		// A failed up does not establish ownership. Never delete by name here.
		_ = r.backend.Stop(manifest.Xray)
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "start WireGuard runtime", nil)
	}
	index, err = r.backend.InterfaceIndex(manifest.Interface)
	if err != nil || index == 0 {
		_ = r.backend.Stop(manifest.Xray)
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "capture WireGuard interface identity", nil)
	}
	manifest.InterfaceIndex = index
	manifest.WireGuardUp = true
	if err := r.run(ctx, dependencies.wg, "show", manifest.Interface); err != nil {
		_ = r.stopManifest(ctx, manifest, dependencies)
		return desktopManifest{}, fault.New(fault.CodeRuntimeApplyFailed, "verify WireGuard runtime", nil)
	}
	manifest.AppliedAt = time.Now().UTC()
	manifest.Stopped = false
	return manifest, nil
}

func (r *Desktop) stopManifest(ctx context.Context, manifest desktopManifest, dependencies desktopDependencies) error {
	if !r.manifestMetadataTrusted(manifest, dependencies) {
		return fault.New(fault.CodeRuntimeProcessStale, "verify runtime metadata ownership", nil)
	}
	if manifest.Stopped {
		return nil
	}
	trusted, err := r.processTrusted(manifest)
	if err != nil {
		return err
	}
	serviceExists, serviceOwned, serviceErr := r.wireGuardServiceState(manifest.Interface, dependencies.wgQuick, manifest.WGConfigPath)
	if serviceErr != nil || serviceExists && !serviceOwned || serviceExists && !manifest.WireGuardUp {
		return fault.New(fault.CodeRuntimeProcessStale, "verify WireGuard tunnel service ownership", nil)
	}
	if manifest.WireGuardUp {
		index, err := r.backend.InterfaceIndex(manifest.Interface)
		if err != nil || (index != 0 && (manifest.InterfaceIndex == 0 || index != manifest.InterfaceIndex)) {
			return fault.New(fault.CodeRuntimeProcessStale, "verify WireGuard interface identity", nil)
		}
		if index != 0 || serviceExists {
			if err := r.run(ctx, dependencies.wgQuick, "down", manifest.WGConfigPath); err != nil {
				return fault.New(fault.CodeRuntimeApplyFailed, "stop WireGuard runtime", nil)
			}
		}
	}
	if trusted {
		if err := r.backend.Stop(manifest.Xray); err != nil {
			return fault.New(fault.CodeRuntimeProcessStale, "stop Xray runtime", nil)
		}
	}
	return nil
}

func (r *Desktop) rollback(ctx context.Context, candidate desktopManifest, previous *desktopManifest, dependencies desktopDependencies, applyErr error) error {
	if candidate.WireGuardUp || candidate.Xray.PID > 0 {
		if err := r.stopManifest(ctx, candidate, dependencies); err != nil {
			return fault.New(fault.CodeRuntimeRollbackFailed, "stop candidate runtime", err)
		}
	}
	if previous == nil {
		return fault.New(fault.CodeRuntimeApplyFailed, "apply desktop runtime", applyErr)
	}
	restored, err := r.startManifest(ctx, *previous, dependencies)
	if err != nil {
		return fault.New(fault.CodeRuntimeRollbackFailed, "restore last-known-good runtime", nil)
	}
	if err := r.saveManifest(r.activeManifestPath(), restored); err != nil {
		_ = r.stopManifest(ctx, restored, dependencies)
		return fault.New(fault.CodeRuntimeRollbackFailed, "restore last-known-good runtime", nil)
	}
	return fault.New(fault.CodeRuntimeApplyFailed, "apply desktop runtime", applyErr)
}

func (r *Desktop) manifestHealthy(ctx context.Context, manifest desktopManifest, dependencies desktopDependencies) (bool, error) {
	if manifest.Stopped {
		return false, nil
	}
	if !r.manifestMetadataTrusted(manifest, dependencies) {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify runtime metadata ownership", nil)
	}
	index, err := r.backend.InterfaceIndex(manifest.Interface)
	if err != nil || index == 0 || index != manifest.InterfaceIndex {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify WireGuard interface identity", nil)
	}
	trusted, err := r.processTrusted(manifest)
	if err != nil || !trusted {
		return false, err
	}
	owned, err := r.backend.LoopbackOwned(manifest.Xray, manifest.LoopbackAddress)
	if err != nil || !owned {
		return false, nil
	}
	if err := r.run(ctx, dependencies.wg, "show", manifest.Interface); err != nil {
		return false, nil
	}
	return true, nil
}

func (r *Desktop) manifestMetadataTrusted(manifest desktopManifest, dependencies desktopDependencies) bool {
	directory, ok := r.revisionDirectory(manifest)
	if !ok || manifest.SchemaVersion != desktopManifestVersion || manifest.CoreID != model.CoreIDXray || manifest.AdapterID != model.AdapterIDXrayCore {
		return false
	}
	if !filepath.IsAbs(manifest.Xray.Executable) || filepath.Clean(manifest.Xray.Executable) != filepath.Clean(dependencies.xray) {
		return false
	}
	if filepath.Clean(manifest.XrayConfigPath) != filepath.Join(directory, "xray.json") || filepath.Clean(manifest.WGConfigPath) != filepath.Join(directory, manifest.Interface+".conf") {
		return false
	}
	if !privateRegularFile(manifest.XrayConfigPath) || !privateRegularFile(manifest.WGConfigPath) {
		return false
	}
	wgConfig, err := os.ReadFile(manifest.WGConfigPath)
	if err != nil {
		return false
	}
	wgDigest := sha256.Sum256(wgConfig)
	if hex.EncodeToString(wgDigest[:]) != manifest.WGConfigSHA256 {
		return false
	}
	if !privateDirectory(directory) {
		return false
	}
	host, _, err := net.SplitHostPort(manifest.LoopbackAddress)
	return err == nil && host == "127.0.0.1"
}

func (r *Desktop) processTrusted(manifest desktopManifest) (bool, error) {
	if manifest.Xray.PID <= 0 || manifest.Xray.Executable == "" || manifest.Xray.ConfigPath != manifest.XrayConfigPath || manifest.Xray.Revision != manifest.Revision {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify Xray process identity", nil)
	}
	raw, err := os.ReadFile(manifest.XrayConfigPath)
	if err != nil {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify Xray config identity", nil)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != manifest.Xray.ConfigSHA256 {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify Xray config identity", nil)
	}
	alive, err := r.backend.ProcessAlive(manifest.Xray)
	if err != nil {
		return false, fault.New(fault.CodeRuntimeProcessStale, "verify Xray process identity", nil)
	}
	return alive, nil
}

func (r *Desktop) waitForXrayReady(ctx context.Context, manifest desktopManifest) error {
	readinessContext, cancel := context.WithTimeout(ctx, r.readinessTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		trusted, err := r.processTrusted(manifest)
		if err != nil || !trusted {
			return errors.New("Xray process exited before readiness")
		}
		owned, err := r.backend.LoopbackOwned(manifest.Xray, manifest.LoopbackAddress)
		if err != nil {
			return err
		}
		if owned {
			return nil
		}
		select {
		case <-readinessContext.Done():
			return readinessContext.Err()
		case <-ticker.C:
		}
	}
}

func (r *Desktop) run(ctx context.Context, command string, args ...string) error {
	commandContext, cancel := context.WithTimeout(ctx, r.commandTimeout)
	defer cancel()
	return r.backend.Run(commandContext, command, args...)
}

func (r *Desktop) activeManifestPath() string { return filepath.Join(r.dir, "active.json") }
func (r *Desktop) lastKnownGoodPath() string  { return filepath.Join(r.dir, "last-known-good.json") }

func (r *Desktop) loadManifest(path string) (desktopManifest, error) {
	var manifest desktopManifest
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return desktopManifest{}, errRuntimeArtifactNotFound
	}
	if statErr != nil || !info.Mode().IsRegular() || !privateRegularFile(path) {
		return desktopManifest{}, fault.New(fault.CodeStateIO, "validate runtime metadata permissions", statErr)
	}
	file, err := os.Open(path)
	if err != nil {
		return desktopManifest{}, fault.New(fault.CodeStateIO, "open runtime metadata", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return desktopManifest{}, fault.New(fault.CodeStateIO, "decode runtime metadata", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return desktopManifest{}, fault.New(fault.CodeStateIO, "decode runtime metadata", err)
	}
	return manifest, nil
}

func privateRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && privateRegularFilePlatform(path)
}

func privateDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && privateDirectoryPlatform(path)
}

func removeOwnedRegularFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || !privateRegularFile(path) {
		return fault.New(fault.CodeStateIO, "validate owned runtime file", err)
	}
	if err := os.Remove(path); err != nil {
		return fault.New(fault.CodeStateIO, "remove owned runtime file", err)
	}
	return nil
}

func (r *Desktop) saveManifest(path string, manifest desktopManifest) error {
	manifest.SchemaVersion = desktopManifestVersion
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fault.New(fault.CodeStateIO, "encode runtime metadata", err)
	}
	return writeFile0600(path, append(raw, '\n'))
}

func (r *Desktop) cleanupRetainedRevisions(active desktopManifest) error {
	keep := map[string]struct{}{}
	if directory, ok := r.revisionDirectory(active); ok {
		keep[directory] = struct{}{}
	}
	lastKnownGood, err := r.loadManifest(r.lastKnownGoodPath())
	if err == nil {
		if directory, ok := r.revisionDirectory(lastKnownGood); ok {
			keep[directory] = struct{}{}
		}
	} else if !errors.Is(err, errRuntimeArtifactNotFound) {
		return err
	}
	revisionsDirectory := filepath.Join(r.dir, "revisions")
	entries, err := os.ReadDir(revisionsDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fault.New(fault.CodeStateIO, "list runtime revisions", err)
	}
	for _, entry := range entries {
		path := filepath.Join(revisionsDirectory, entry.Name())
		if _, retained := keep[path]; retained {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return fault.New(fault.CodeStateIO, "remove obsolete runtime revision", err)
		}
	}
	return nil
}

func (r *Desktop) removeRevision(manifest desktopManifest) error {
	directory, ok := r.revisionDirectory(manifest)
	if !ok {
		return nil
	}
	if err := os.RemoveAll(directory); err != nil {
		return fault.New(fault.CodeStateIO, "remove failed runtime revision", err)
	}
	return nil
}

func (r *Desktop) revisionDirectory(manifest desktopManifest) (string, bool) {
	revisionsDirectory := filepath.Clean(filepath.Join(r.dir, "revisions"))
	directory := filepath.Clean(filepath.Dir(manifest.XrayConfigPath))
	relative, err := filepath.Rel(revisionsDirectory, directory)
	if err != nil || relative == "." || relative == "" || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || relative == ".." {
		return "", false
	}
	if filepath.Dir(relative) != "." {
		return "", false
	}
	return directory, true
}

func applyResult(config model.Config) ApplyResult {
	return ApplyResult{Revision: config.Revision, CoreID: config.CoreID(), AdapterID: model.AdapterIDXrayCore}
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fault.New(fault.CodeStateIO, "create runtime directory", err)
	}
	if err := secureDirectoryPlatform(path); err != nil {
		return fault.New(fault.CodeStateIO, "secure runtime directory", err)
	}
	return nil
}

func writeFile0600(path string, raw []byte) error {
	if err := secureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".xconnect-runtime-*")
	if err != nil {
		return fault.New(fault.CodeStateIO, "create runtime artifact", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := secureFilePlatform(temporaryPath); err != nil {
		return fault.New(fault.CodeStateIO, "secure runtime artifact", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return fault.New(fault.CodeStateIO, "write runtime artifact", err)
	}
	if err := temporary.Sync(); err != nil {
		return fault.New(fault.CodeStateIO, "sync runtime artifact", err)
	}
	if err := temporary.Close(); err != nil {
		return fault.New(fault.CodeStateIO, "close runtime artifact", err)
	}
	if err := replaceRuntimeFile(temporaryPath, path); err != nil {
		return fault.New(fault.CodeStateIO, "commit runtime artifact", err)
	}
	if err := secureFilePlatform(path); err != nil {
		return fault.New(fault.CodeStateIO, "secure runtime artifact", err)
	}
	committed = true
	return nil
}

func renderWireGuardConfig(config model.Config, privateKey string) string {
	var builder strings.Builder
	builder.WriteString("[Interface]\nPrivateKey = ")
	builder.WriteString(strings.TrimSpace(privateKey))
	builder.WriteString("\nAddress = ")
	builder.WriteString(config.WireGuard.Address)
	builder.WriteString(fmt.Sprintf("\nMTU = %d\n", config.WireGuard.MTU))
	if len(config.WireGuard.DNS) > 0 {
		builder.WriteString("DNS = ")
		builder.WriteString(strings.Join(config.WireGuard.DNS, ", "))
		builder.WriteByte('\n')
	}
	builder.WriteString("\n[Peer]\nPublicKey = ")
	builder.WriteString(config.WireGuard.PeerPublicKey)
	builder.WriteString("\nAllowedIPs = ")
	builder.WriteString(strings.Join(config.WireGuard.PeerAllowedIPs, ", "))
	builder.WriteString("\nEndpoint = ")
	builder.WriteString(config.WireGuard.PeerEndpoint)
	if config.WireGuard.PersistentKeepalive > 0 {
		builder.WriteString(fmt.Sprintf("\nPersistentKeepalive = %d", config.WireGuard.PersistentKeepalive))
	}
	builder.WriteByte('\n')
	return builder.String()
}

func renderXrayConfig(config model.Config) ([]byte, error) {
	user := map[string]any{
		"id":             config.Transport.VLESSAuthID(),
		"encryption":     "none",
		"packetEncoding": config.Transport.PacketEncoding,
	}
	if config.Transport.Flow != "" {
		user["flow"] = config.Transport.Flow
	}
	profile := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag":      "xconnect-wireguard-in",
			"listen":   "127.0.0.1",
			"port":     config.Transport.LocalPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": config.WireGuard.GatewayWireGuardIP,
				"port":    config.WireGuard.RelayTargetPort(),
				"network": "udp",
			},
		}},
		"outbounds": []any{map[string]any{
			"tag":      "xconnect-vless-out",
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": config.Transport.Server,
				"port":    config.Transport.Port,
				"users":   []any{user},
			}}},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    config.Transport.TLSServerName(),
					"allowInsecure": false,
					"fingerprint":   "chrome",
				},
			},
		}},
	}
	return json.MarshalIndent(profile, "", "  ")
}

func configArgument(args []string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-config" {
			return filepath.Clean(args[index+1])
		}
	}
	return ""
}
