// Modified for XConnect-One: standalone module imports.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

const defaultAccountsServer = "https://accounts.svc.plus"

type runtimeFactory func(stateDirectory string) overlayruntime.Interface
type credentialFactory func(stateDirectory string) credential.Store

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, http.DefaultClient); err != nil {
		fmt.Fprintf(os.Stderr, "error[%s]: %v\n", fault.Code(err), err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	return runWithFactories(ctx, args, stdout, stderr, httpClient, func(stateDirectory string) overlayruntime.Interface {
		return platformRuntime(runtime.GOOS, stateDirectory)
	}, credential.NewPlatformStore)
}

func platformRuntime(goos, stateDirectory string) overlayruntime.Interface {
	if goos == "linux" {
		return overlayruntime.NewLinuxDesktop(stateDirectory)
	}
	switch goos {
	case "darwin":
		return overlayruntime.NewMacOSDesktop(stateDirectory)
	case "windows":
		return overlayruntime.NewWindowsDesktop(stateDirectory)
	case "ios", "android":
		return overlayruntime.NewProtectedHost("mobile_protected_tunnel_host_required", nil)
	}
	return overlayruntime.NewUnavailable()
}

func runWithRuntimeFactory(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory) error {
	return runWithFactories(ctx, args, stdout, stderr, httpClient, newRuntime, func(string) credential.Store { return &credential.MemoryStore{} })
}

func runWithFactories(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	if len(args) == 0 {
		return fault.New(fault.CodeInvalidInput, "expected register, join, sync, up, down, leave, status, diagnose, runtime, credential, admin, or policy", nil)
	}
	switch args[0] {
	case "register":
		return runRegister(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "join":
		return runJoin(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "sync":
		return runSync(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "up":
		return runUp(ctx, args[1:], stdout, stderr, newRuntime)
	case "down":
		return runDown(ctx, args[1:], stdout, stderr, newRuntime)
	case "leave":
		return runLeave(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr, newRuntime, newCredentials)
	case "diagnose":
		return runDiagnose(ctx, args[1:], stdout, stderr, newRuntime, newCredentials)
	case "runtime":
		return runRuntime(ctx, args[1:], stdout, stderr)
	case "credential":
		return runCredential(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	case "admin":
		return runAdmin(ctx, args[1:], stdout, stderr, httpClient)
	case "policy":
		return runPolicy(ctx, args[1:], stdout, stderr, httpClient)
	default:
		return fault.New(fault.CodeInvalidInput, "unknown command", nil)
	}
}

func runRegister(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect register", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controller := flags.String("controller", "", "HTTPS accounts controller base URL")
	networkID := flags.String("network", "", "public overlay network ID")
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID")
	deviceName := flags.String("name", "", "device display name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse register arguments", err)
	}
	if strings.TrimSpace(*controller) == "" || strings.TrimSpace(*networkID) == "" {
		return fault.New(fault.CodeInvalidInput, "register requires controller and network", nil)
	}
	client, err := controlplane.New(*controller, "", httpClient)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	store := state.NewStore(*stateDirectory)
	registrar := usecase.NewRegistrar(client, store, newCredentials(*stateDirectory), newRuntime(*stateDirectory)).WithProgress(func(progress usecase.RegistrationProgress) {
		_, _ = fmt.Fprintf(stderr, "xconnect: registration %s; registration_id=%s device_id=%s network_id=%s expires_at=%s wireguard_public_key_fingerprint=%s; approve this device in Zero\n", progress.Status, progress.RegistrationID, progress.DeviceID, progress.NetworkID, progress.ExpiresAt.UTC().Format(time.RFC3339), progress.WireGuardPublicKeyFingerprint)
	})
	result, err := registrar.Register(ctx, usecase.RegisterRequest{
		Controller: *controller, DeviceID: *deviceID, DeviceName: *deviceName, NetworkID: *networkID, Platform: runtime.GOOS, Hostname: hostname,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runJoin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	args = moveLeadingJoinTargetAfterFlags(args)
	flags := flag.NewFlagSet("xconnect join", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID")
	deviceName := flags.String("name", "", "device display name")
	networkID := flags.String("network-id", "", "requested overlay network ID")
	nodeID := flags.String("node-id", "", "preferred gateway node ID")
	configContract := flags.String("config-contract", string(usecase.ConfigContractAuto), "config contract: auto, signed, or legacy")
	bootstrapRuntime := flags.Bool("bootstrap", false, "install or repair the approved managed runtime before joining")
	runtimeReleaseBaseURL := flags.String("runtime-release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	allowInsecureLocalhost := flags.Bool("allow-insecure-localhost", false, "allow HTTP localhost controller for invite development")
	inviteFile := flags.String("invite-file", "", "path to a protected file containing one XConnect join URI")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	if err := flags.Parse(args); err != nil {
		return fault.New(fault.CodeInvalidInput, "parse join arguments", err)
	}
	if flags.NArg() > 1 {
		return fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	targetValue := ""
	if flags.NArg() == 1 {
		targetValue = flags.Arg(0)
	}
	if strings.TrimSpace(*inviteFile) != "" {
		if targetValue != "" {
			return fault.New(fault.CodeInvalidInput, "join accepts either an invite argument or --invite-file", nil)
		}
		var err error
		targetValue, err = readJoinInvite(*inviteFile)
		if err != nil {
			return err
		}
	}
	target, err := resolveJoinTarget(targetValue, *server, *allowInsecureLocalhost)
	if err != nil {
		return err
	}
	if *bootstrapRuntime {
		if _, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
			StateDirectory:        *stateDirectory,
			ReleaseBaseURL:        *runtimeReleaseBaseURL,
			InstallSystemPackages: true,
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "xconnect: managed runtime ready")
	}
	if *networkID == "" {
		*networkID = target.NetworkID
	}
	if *nodeID == "" {
		*nodeID = target.NodeID
	}
	token := ""
	if target.JoinToken == "" {
		token, err = readToken(*tokenFile)
		if err != nil {
			return err
		}
	}
	contract, err := usecase.ParseConfigContract(*configContract)
	if err != nil {
		return err
	}
	if target.JoinToken != "" {
		if contract == usecase.ConfigContractLegacy {
			return fault.New(fault.CodeConfigDowngradeBlocked, "join invite requires signed config", nil)
		}
		contract = usecase.ConfigContractSigned
	}
	client, err := controlplane.New(target.Controller, token, httpClient)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	store := state.NewStore(*stateDirectory)
	operation, err := store.AcquireOperation(ctx, "join")
	if err != nil {
		return err
	}
	defer operation.Release()
	tunnelRuntime := newRuntime(*stateDirectory)
	result, err := usecase.NewJoiner(client, store, tunnelRuntime).WithCredentialStore(newCredentials(*stateDirectory)).WithConfigContract(contract).Join(ctx, usecase.JoinRequest{
		Server:     target.Controller,
		DeviceID:   *deviceID,
		DeviceName: *deviceName,
		Platform:   runtime.GOOS,
		Hostname:   hostname,
		NetworkID:  *networkID,
		NodeID:     *nodeID,
		JoinToken:  target.JoinToken,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runSync(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	signedConfigV2 := flags.Bool("signed-config-v2", false, "request the policy-bound SignedConfig v2 contract")
	bootstrapRuntime := flags.Bool("bootstrap", false, "install or repair the approved managed runtime before synchronizing")
	runtimeReleaseBaseURL := flags.String("runtime-release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse sync arguments", err)
	}
	credentials := newCredentials(*stateDirectory)
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return fault.New(fault.CodeCredentialMissing, "load device credential for sync", nil)
	}
	if err != nil {
		return err
	}
	if *bootstrapRuntime {
		if _, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
			StateDirectory:        *stateDirectory,
			ReleaseBaseURL:        *runtimeReleaseBaseURL,
			InstallSystemPackages: true,
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "xconnect: managed runtime ready")
	}
	client, err := controlplane.New(record.Controller, "", httpClient)
	if err != nil {
		return err
	}
	manager := usecase.NewDeviceSessionManager(client, state.NewStore(*stateDirectory), credentials, newRuntime(*stateDirectory))
	if *signedConfigV2 {
		manager.WithSignedConfigV2()
	}
	result, err := manager.Sync(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runUp(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory) error {
	flags := flag.NewFlagSet("xconnect up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse up arguments", err)
	}
	result, err := usecase.Up(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runDown(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory) error {
	flags := flag.NewFlagSet("xconnect down", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse down arguments", err)
	}
	result, err := usecase.Down(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runLeave(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect leave", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	localOnly := flags.Bool("local-only", false, "remove only local XConnect-owned state without server revocation")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse leave arguments", err)
	}
	credentials := newCredentials(*stateDirectory)
	var client *controlplane.Client
	var err error
	if !*localOnly {
		record, loadErr := credentials.Load(ctx)
		if loadErr == nil {
			client, err = controlplane.New(record.Controller, "", httpClient)
			if err != nil {
				return err
			}
		} else if !errors.Is(loadErr, credential.ErrNotFound) {
			return loadErr
		}
	}
	result, err := usecase.LeaveWithDeviceCredential(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory), credentials, client, *localOnly)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runCredential(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	if len(args) == 0 || args[0] != "rotate" {
		return fault.New(fault.CodeInvalidInput, "expected credential rotate", nil)
	}
	flags := flag.NewFlagSet("xconnect credential rotate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse credential rotate arguments", err)
	}
	credentials := newCredentials(*stateDirectory)
	record, err := credentials.Load(ctx)
	if errors.Is(err, credential.ErrNotFound) {
		return fault.New(fault.CodeCredentialMissing, "load device credential for rotation", nil)
	}
	if err != nil {
		return err
	}
	client, err := controlplane.New(record.Controller, "", httpClient)
	if err != nil {
		return err
	}
	result, err := usecase.NewDeviceSessionManager(client, state.NewStore(*stateDirectory), credentials, newRuntime(*stateDirectory)).Rotate(ctx)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	if len(args) < 2 || args[0] != "invite" || args[1] != "create" {
		return fault.New(fault.CodeInvalidInput, "expected admin invite create", nil)
	}
	flags := flag.NewFlagSet("xconnect admin invite create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	networkID := flags.String("network-id", "", "overlay network ID")
	deviceID := flags.String("device-id", "", "optional constrained device ID")
	platform := flags.String("platform", "", "optional constrained platform")
	expiresIn := flags.Int64("expires-in", 900, "one-time invite lifetime in seconds")
	output := flags.String("output", "json", "output format: json or uri")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse invite create arguments", err)
	}
	if *output != "json" && *output != "uri" {
		return fault.New(fault.CodeInvalidInput, "select invite output", nil)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := controlplane.New(*server, token, httpClient)
	if err != nil {
		return err
	}
	response, err := client.CreateJoinToken(ctx, controlplane.CreateJoinTokenRequest{NetworkID: *networkID, DeviceID: *deviceID, Platform: *platform, ExpiresInSeconds: *expiresIn})
	if err != nil {
		return err
	}
	if *output == "uri" {
		_, err = fmt.Fprintln(stdout, response.JoinToken.JoinURI)
		return err
	}
	return writeJSON(stdout, response)
}

func runPolicy(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	if len(args) < 1 || args[0] != "explain" {
		return fault.New(fault.CodeInvalidInput, "expected policy explain", nil)
	}
	flags := flag.NewFlagSet("xconnect policy explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	tokenFile := flags.String("token-file", "", "path to a file containing the accounts access token")
	networkID := flags.String("network-id", "", "overlay network ID")
	revision := flags.Uint64("revision", 0, "policy revision")
	source := flags.String("source", "", "source selector")
	destination := flags.String("destination", "", "destination selector")
	protocol := flags.String("protocol", "", "tcp, udp, or icmp")
	port := flags.Int("port", 0, "destination port; zero only for ICMP")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse policy explain arguments", err)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	client, err := controlplane.New(*server, token, httpClient)
	if err != nil {
		return err
	}
	result, err := client.ExplainPolicy(ctx, *revision, controlplane.PolicyExplainRequest{NetworkID: *networkID, Source: *source, Destination: *destination, Protocol: *protocol, Port: *port})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func moveLeadingJoinTargetAfterFlags(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	reordered := append([]string(nil), args[1:]...)
	return append(reordered, args[0])
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse status arguments", err)
	}
	store := state.NewStore(*stateDirectory)
	result, err := usecase.StatusWithCredential(ctx, store, newRuntime(*stateDirectory), newCredentials(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runDiagnose(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect diagnose", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse diagnose arguments", err)
	}
	store := state.NewStore(*stateDirectory)
	result, err := usecase.DiagnoseWithCredential(ctx, store, newRuntime(*stateDirectory), newCredentials(*stateDirectory))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runRuntime(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "bootstrap" {
		return fault.New(fault.CodeInvalidInput, "expected runtime bootstrap", nil)
	}
	flags := flag.NewFlagSet("xconnect runtime bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	releaseBaseURL := flags.String("release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	installSystemPackages := flags.Bool("install-system-packages", true, "install required WireGuard packages using the supported platform package manager")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse runtime bootstrap arguments", err)
	}
	result, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
		StateDirectory:        *stateDirectory,
		ReleaseBaseURL:        *releaseBaseURL,
		InstallSystemPackages: *installSystemPackages,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return strings.TrimSpace(os.Getenv("XCONNECT_TOKEN")), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fault.New(fault.CodeAuthenticationFailed, "read access token", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return "", fault.New(fault.CodeAuthenticationFailed, "read access token", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// readJoinInvite keeps a short-lived join URI out of the process argument
// list. Deployment automation creates this file with 0600 permissions and
// removes it immediately after a successful exchange.
func readJoinInvite(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16<<10))
	if err != nil {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fault.New(fault.CodeJoinInviteInvalid, "read join invite", nil)
	}
	return value, nil
}

type joinTarget struct {
	Controller string
	NetworkID  string
	NodeID     string
	JoinToken  string
}

func resolveJoinTarget(value, fallbackController string, allowInsecureLocalhost bool) (joinTarget, error) {
	if strings.HasPrefix(value, "xconnect:") {
		target, err := invite.Parse(value, allowInsecureLocalhost)
		if err != nil {
			return joinTarget{}, err
		}
		return joinTarget{Controller: target.Controller, JoinToken: target.JoinToken}, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return joinTarget{Controller: strings.TrimRight(strings.TrimSpace(fallbackController), "/")}, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", err)
	}
	query := parsed.Query()
	for _, sensitiveKey := range []string{"token", "access_token", "refresh_token", "private_key"} {
		if query.Has(sensitiveKey) {
			return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse invite URL", nil)
		}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	if parsed.RawQuery != "" {
		return joinTarget{}, fault.New(fault.CodeInvalidInput, "parse join target", nil)
	}
	return joinTarget{Controller: strings.TrimRight(value, "/")}, nil
}

func defaultStateDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".xconnect-one"
	}
	return filepath.Join(home, ".xconnect-one")
}

func defaultDeviceID() string {
	hostname, _ := os.Hostname()
	raw := strings.ToLower("xconnect-" + runtime.GOOS + "-" + hostname)
	var normalized strings.Builder
	for _, character := range raw {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			normalized.WriteRune(character)
		} else {
			normalized.WriteByte('-')
		}
	}
	return strings.Trim(normalized.String(), "-.")
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fault.New(fault.CodeInvalidResponse, "write command output", err)
	}
	return nil
}
