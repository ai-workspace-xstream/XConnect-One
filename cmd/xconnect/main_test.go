// Modified for XConnect-One: standalone imports and platform-aware lifecycle tests.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

const cliTestToken = "cli-secret-token"

func TestRegisterCLIRequiresHTTPSControllerAndPublicNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"register"},
		{"register", "--controller", "http://localhost:8080", "--network", "net_public"},
		{"register", "--controller", "https://accounts.example"},
	} {
		var stdout, stderr bytes.Buffer
		err := runWithRuntimeFactory(t.Context(), args, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
		if fault.Code(err) != fault.CodeInvalidInput {
			t.Fatalf("args=%v code=%q err=%v", args, fault.Code(err), err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("args=%v unexpectedly wrote stdout=%q", args, stdout.String())
		}
	}
}

func TestJoinAcceptsControllerPositionallyAndKeepsSecretsOutOfOutput(t *testing.T) {
	var ackCalls atomic.Int32
	server := newCLITestServer(t, false, &ackCalls)
	stateDirectory := t.TempDir()
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fakeRuntime := &overlayruntime.Fake{}
	newRuntime := func(string) overlayruntime.Interface { return fakeRuntime }

	err := runWithRuntimeFactory(t.Context(), []string{
		"join",
		server.URL,
		"--state-dir", stateDirectory,
		"--device-id", "dev_cli",
	}, &stdout, &stderr, server.Client(), newRuntime)
	if err != nil {
		t.Fatalf("join command: %v", err)
	}
	lastKnown, err := state.NewStore(stateDirectory).LoadLastKnown()
	if err != nil {
		t.Fatalf("load last-known state: %v", err)
	}
	for _, output := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(output, cliTestToken) || strings.Contains(output, lastKnown.WireGuardPrivateKey) {
			t.Fatalf("command output leaked a secret: %s", output)
		}
	}
	entries, err := os.ReadDir(stateDirectory)
	if err != nil {
		t.Fatalf("read state directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(stateDirectory, entry.Name()))
		if err != nil {
			t.Fatalf("read state artifact: %v", err)
		}
		if bytes.Contains(raw, []byte(cliTestToken)) {
			t.Fatalf("token persisted in %s", entry.Name())
		}
	}

	stdout.Reset()
	if err := runWithRuntimeFactory(t.Context(), []string{"status", "--state-dir", stateDirectory}, &stdout, &stderr, server.Client(), newRuntime); err != nil {
		t.Fatalf("status command: %v", err)
	}
	if strings.Contains(stdout.String(), lastKnown.WireGuardPrivateKey) {
		t.Fatal("status output leaked private key")
	}

	stdout.Reset()
	if err := runWithRuntimeFactory(t.Context(), []string{"diagnose", "--state-dir", stateDirectory}, &stdout, &stderr, server.Client(), newRuntime); err != nil {
		t.Fatalf("diagnose command: %v", err)
	}
	if strings.Contains(stdout.String(), lastKnown.WireGuardPrivateKey) {
		t.Fatal("diagnose output leaked private key")
	}
}

func TestLifecycleReadCommandsRejectUnexpectedPositionals(t *testing.T) {
	for _, command := range []string{"status", "diagnose"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		err := runWithRuntimeFactory(t.Context(), []string{command, "unexpected"}, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
		if fault.Code(err) != fault.CodeInvalidInput {
			t.Fatalf("%s code=%q err=%v", command, fault.Code(err), err)
		}
	}
}

func TestCLIInviteJoinUsesEnrollmentWithoutAccountTokenOrSecretOutput(t *testing.T) {
	server, joinToken, enrollmentToken, exchangeCalls, ackCalls := newCLIInviteServer(t)
	stateDirectory := t.TempDir()
	t.Setenv("XCONNECT_TOKEN", "account-token-must-not-be-used")
	invite := "xconnect://join/" + joinToken + "?controller=" + url.QueryEscape(server.URL)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fakeRuntime := &overlayruntime.Fake{}
	err := runWithRuntimeFactory(t.Context(), []string{
		"join", invite, "--allow-insecure-localhost", "--state-dir", stateDirectory, "--device-id", "dev_cli",
	}, &stdout, &stderr, server.Client(), func(string) overlayruntime.Interface { return fakeRuntime })
	if err != nil {
		t.Fatalf("invite join: %v", err)
	}
	if exchangeCalls.Load() != 1 || ackCalls.Load() != 1 || fakeRuntime.ApplyCalls != 1 {
		t.Fatalf("exchange=%d ack=%d apply=%d", exchangeCalls.Load(), ackCalls.Load(), fakeRuntime.ApplyCalls)
	}
	for _, output := range []string{stdout.String(), stderr.String()} {
		for _, secret := range []string{joinToken, enrollmentToken, "account-token-must-not-be-used"} {
			if strings.Contains(output, secret) {
				t.Fatalf("CLI output leaked secret: %s", output)
			}
		}
	}
	if _, err := os.Stat(state.NewStore(stateDirectory).EnrollmentSecretPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed transient secret remains: %v", err)
	}
}

func TestCLIInviteJoinReadsProtectedInviteFile(t *testing.T) {
	server, joinToken, _, exchangeCalls, ackCalls := newCLIInviteServer(t)
	stateDirectory := t.TempDir()
	invitePath := filepath.Join(t.TempDir(), "join-uri")
	invite := "xconnect://join/" + joinToken + "?controller=" + url.QueryEscape(server.URL)
	if err := os.WriteFile(invitePath, []byte(invite+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runWithRuntimeFactory(t.Context(), []string{
		"join", "--invite-file", invitePath, "--allow-insecure-localhost", "--state-dir", stateDirectory, "--device-id", "dev_cli",
	}, &stdout, &stderr, server.Client(), func(string) overlayruntime.Interface { return &overlayruntime.Fake{} }); err != nil {
		t.Fatalf("invite-file join: %v", err)
	}
	if exchangeCalls.Load() != 1 || ackCalls.Load() != 1 {
		t.Fatalf("exchange=%d ack=%d", exchangeCalls.Load(), ackCalls.Load())
	}
	if strings.Contains(stdout.String(), joinToken) || strings.Contains(stderr.String(), joinToken) {
		t.Fatal("invite-file secret leaked in command output")
	}
}

func TestProductionJoinFailsClosedWithoutPlatformRuntimeAndDoesNotAck(t *testing.T) {
	// Never depend on installed tunnel tools or allow this production-path test
	// to mutate networking when run as root on a provisioned Linux host.
	t.Setenv("PATH", t.TempDir())
	wantCode := fault.CodeRuntimeUnavailable
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		wantCode = fault.CodeRuntimeDependency
	}
	var ackCalls atomic.Int32
	server := newCLITestServer(t, false, &ackCalls)
	stateDirectory := t.TempDir()
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(t.Context(), []string{
		"join",
		server.URL,
		"--state-dir", stateDirectory,
		"--device-id", "dev_cli",
	}, &stdout, &stderr, server.Client())
	if fault.Code(err) != wantCode {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if ackCalls.Load() != 0 {
		t.Fatalf("ACK calls = %d, want 0", ackCalls.Load())
	}
	checkpoint, loadErr := state.NewStore(stateDirectory).LoadCheckpoint()
	if loadErr != nil {
		t.Fatalf("load checkpoint: %v", loadErr)
	}
	if checkpoint.Phase != state.PhaseConfigFetched || checkpoint.LastErrorCode != wantCode {
		t.Fatalf("unexpected checkpoint after unavailable runtime: %#v", checkpoint)
	}
}

func TestPlatformRuntimeSelectsControlledClientRuntime(t *testing.T) {
	linuxRuntime := platformRuntime("linux", t.TempDir())
	if _, ok := linuxRuntime.(*overlayruntime.Desktop); !ok {
		t.Fatalf("linux runtime = %T, want desktop runtime", linuxRuntime)
	}
	darwinRuntime := platformRuntime("darwin", t.TempDir())
	if _, ok := darwinRuntime.(*overlayruntime.Desktop); !ok {
		t.Fatalf("darwin runtime = %T, want desktop runtime", darwinRuntime)
	}
	if runtime.GOOS == "windows" {
		if _, ok := platformRuntime("windows", t.TempDir()).(*overlayruntime.Desktop); !ok {
			t.Fatalf("windows runtime = %T, want external desktop runtime", platformRuntime("windows", t.TempDir()))
		}
	} else {
		runtimeHost := platformRuntime("windows", t.TempDir())
		diagnostics, err := runtimeHost.Diagnose(t.Context())
		if err != nil || len(diagnostics) != 2 || diagnostics[1].Code != "windows_service_host_required" || !diagnostics[1].Healthy {
			t.Fatalf("windows diagnostics=%#v err=%v", diagnostics, err)
		}
		if _, err := runtimeHost.Apply(t.Context(), overlayruntime.ApplyRequest{}); fault.Code(err) != fault.CodeRuntimeUnavailable {
			t.Fatalf("windows apply code=%q err=%v", fault.Code(err), err)
		}
	}
	for _, test := range []struct{ goos, code string }{
		{goos: "ios", code: "mobile_protected_tunnel_host_required"},
		{goos: "android", code: "mobile_protected_tunnel_host_required"},
	} {
		runtimeHost := platformRuntime(test.goos, t.TempDir())
		diagnostics, err := runtimeHost.Diagnose(t.Context())
		if err != nil || len(diagnostics) != 2 || diagnostics[1].Code != test.code || !diagnostics[1].Healthy {
			t.Fatalf("%s diagnostics=%#v err=%v", test.goos, diagnostics, err)
		}
		if _, err := runtimeHost.Apply(t.Context(), overlayruntime.ApplyRequest{}); fault.Code(err) != fault.CodeRuntimeUnavailable {
			t.Fatalf("%s apply code=%q err=%v", test.goos, fault.Code(err), err)
		}
	}
}

func TestJoinAcceptsInviteURLControllerAndSelection(t *testing.T) {
	controller := "https://accounts.example"
	joinToken := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	invite := "xconnect://join/" + joinToken + "?controller=" + url.QueryEscape(controller)

	target, err := resolveJoinTarget(invite, "", false)
	if err != nil {
		t.Fatalf("resolve invite: %v", err)
	}
	if target.Controller != controller || target.JoinToken != joinToken || target.NetworkID != "" || target.NodeID != "" {
		t.Fatalf("unexpected invite target: %#v", target)
	}
}

func TestJoinRejectsCredentialsInInviteURL(t *testing.T) {
	joinToken := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	_, err := resolveJoinTarget("xconnect://join/"+joinToken+"?controller=https%3A%2F%2Faccounts.example&token=secret", "", false)
	if fault.Code(err) != fault.CodeJoinInviteInvalid {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
}

func TestJoinInviteParserRejectsAmbiguousOrInsecureURLs(t *testing.T) {
	joinToken := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	tests := []string{
		"xconnect://join?controller=https%3A%2F%2Faccounts.example",
		"xconnect://user@join/" + joinToken + "?controller=https%3A%2F%2Faccounts.example",
		"xconnect://join/" + joinToken + "/extra?controller=https%3A%2F%2Faccounts.example",
		"xconnect://join/%78jt_invalid?controller=https%3A%2F%2Faccounts.example",
		"xconnect://join/" + joinToken + "?controller=https%3A%2F%2Faccounts.example#fragment",
		"xconnect://join/" + joinToken + "?controller=https%3A%2F%2Fuser%40accounts.example",
		"xconnect://join/" + joinToken + "?controller=https%3A%2F%2Faccounts.example%3Fx%3D1",
		"xconnect://join/" + joinToken + "?controller=http%3A%2F%2Faccounts.example",
		"xconnect://join/" + joinToken + "?controller=http%3A%2F%2Flocalhost%3A8080",
	}
	for _, invite := range tests {
		if _, err := resolveJoinTarget(invite, "", false); fault.Code(err) != fault.CodeJoinInviteInvalid {
			t.Fatalf("invite accepted %q: %v", invite, err)
		}
	}
	invite := "xconnect://join/" + joinToken + "?controller=http%3A%2F%2Flocalhost%3A8080"
	if target, err := resolveJoinTarget(invite, "", true); err != nil || target.Controller != "http://localhost:8080" {
		t.Fatalf("explicit localhost development invite = %#v, %v", target, err)
	}
}

func TestJoinRejectsUnknownConfigContractBeforeNetworkAccess(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runWithRuntimeFactory(t.Context(), []string{
		"join", "https://accounts.example", "--config-contract", "future", "--state-dir", t.TempDir(), "--device-id", "dev_cli",
	}, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
	if fault.Code(err) != fault.CodeInvalidInput {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
}

func TestInviteJoinRejectsLegacyContractBeforeNetworkAccess(t *testing.T) {
	joinToken := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	invite := "xconnect://join/" + joinToken + "?controller=https%3A%2F%2Faccounts.example"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runWithRuntimeFactory(t.Context(), []string{
		"join", invite, "--config-contract", "legacy", "--state-dir", t.TempDir(), "--device-id", "dev_cli",
	}, &stdout, &stderr, http.DefaultClient, func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
	if fault.Code(err) != fault.CodeConfigDowngradeBlocked {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
}

func TestJoinAuthenticationErrorDoesNotExposeTokenOrResponseBody(t *testing.T) {
	var ackCalls atomic.Int32
	server := newCLITestServer(t, true, &ackCalls)
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(t.Context(), []string{
		"join",
		server.URL,
		"--state-dir", t.TempDir(),
		"--device-id", "dev_cli",
	}, &stdout, &stderr, server.Client())
	if fault.Code(err) != fault.CodeAuthenticationFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if strings.Contains(err.Error(), cliTestToken) || strings.Contains(err.Error(), "token_expired") {
		t.Fatalf("authentication error leaked details: %v", err)
	}
}

func TestCLILifecycleCommandsAreIdempotentAndLeaveRetainsUnknownFiles(t *testing.T) {
	var ackCalls atomic.Int32
	server := newCLITestServer(t, false, &ackCalls)
	stateDirectory := t.TempDir()
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	runtimeFake := &overlayruntime.Fake{}
	factory := func(string) overlayruntime.Interface { return runtimeFake }
	var stdout, stderr bytes.Buffer
	if err := runWithRuntimeFactory(t.Context(), []string{"join", server.URL, "--state-dir", stateDirectory, "--device-id", "dev_cli"}, &stdout, &stderr, server.Client(), factory); err != nil {
		t.Fatal(err)
	}
	if ackCalls.Load() != 1 {
		t.Fatalf("ACK calls=%d", ackCalls.Load())
	}
	for _, command := range [][]string{{"down", "--state-dir", stateDirectory}, {"down", "--state-dir", stateDirectory}} {
		stdout.Reset()
		if err := runWithRuntimeFactory(t.Context(), command, &stdout, &stderr, server.Client(), factory); err != nil {
			t.Fatalf("%v: %v", command, err)
		}
	}
	if err := runWithRuntimeFactory(t.Context(), []string{"up", "--state-dir", stateDirectory}, &stdout, &stderr, server.Client(), factory); fault.Code(err) != fault.CodeConfigDowngradeBlocked {
		t.Fatalf("up must require sync: %v", err)
	}
	if runtimeFake.DownCalls != 2 || runtimeFake.ApplyCalls != 1 || ackCalls.Load() != 1 {
		t.Fatalf("down=%d apply=%d ack=%d", runtimeFake.DownCalls, runtimeFake.ApplyCalls, ackCalls.Load())
	}
	unknown := filepath.Join(stateDirectory, "operator-note.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runWithRuntimeFactory(t.Context(), []string{"leave", "--state-dir", stateDirectory}, &stdout, &stderr, server.Client(), factory); fault.Code(err) != fault.CodeCredentialMissing {
		t.Fatalf("default leave code=%q err=%v", fault.Code(err), err)
	}
	stdout.Reset()
	if err := runWithRuntimeFactory(t.Context(), []string{"leave", "--local-only", "--state-dir", stateDirectory}, &stdout, &stderr, server.Client(), factory); err != nil {
		t.Fatalf("local leave: %v", err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown file removed: %v", err)
	}
	if strings.Contains(stdout.String(), cliTestToken) {
		t.Fatal("lifecycle output leaked token")
	}
}

func TestAdminInviteCreatePrintsSecretExactlyOnceAndNeverToStderr(t *testing.T) {
	secret := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		if request.URL.Path != "/api/overlay/v1/join-tokens" || request.Header.Get("Authorization") != "Bearer "+cliTestToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"join_token": map[string]any{
			"id": "join_01", "join_uri": "xconnect://join/" + secret + "?controller=" + url.QueryEscape(server.URL),
			"network_id": "net_private", "device_id": "dev_cli", "platform": "linux", "remaining_uses": 1,
			"expires_at": time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second).Format(time.RFC3339),
		}})
	}))
	t.Cleanup(server.Close)
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	var stdout, stderr bytes.Buffer
	err := runWithRuntimeFactory(t.Context(), []string{"admin", "invite", "create", "--server", server.URL, "--network-id", "net_private", "--device-id", "dev_cli", "--platform", "linux"}, &stdout, &stderr, server.Client(), func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if strings.Count(stdout.String(), secret) != 1 || strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), cliTestToken) {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	err = runWithRuntimeFactory(t.Context(), []string{"admin", "invite", "create", "--server", server.URL, "--network-id", "net_private", "--device-id", "dev_cli", "--platform", "linux", "--output", "uri"}, &stdout, &stderr, server.Client(), func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
	if err != nil || strings.Count(stdout.String(), secret) != 1 {
		t.Fatalf("URI output=%q err=%v", stdout.String(), err)
	}
}

func TestCLICredentialRotateAndDurableLeaveUseProtectedDeviceAuthorization(t *testing.T) {
	stateDirectory := t.TempDir()
	stateStore := state.NewStore(stateDirectory)
	now := time.Now().UTC().Truncate(time.Second)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signingPublicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	secret, err := credential.GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x44}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &credential.MemoryStore{}
	record := credential.Record{
		SchemaVersion: credential.SchemaVersion, Controller: "https://accounts.example", DeviceID: "dev_cli", NetworkID: "net_private", Platform: "linux",
		WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), CredentialID: secret.CredentialID, Credential: secret.Value,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * 24 * time.Hour), Scope: []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke},
		SigningKeys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519, PublicKey: signingPublicKey, Status: "current", NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)}}}},
	}
	if err := credentials.Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	lastKnown := state.LastKnown{Server: record.Controller, DeviceID: record.DeviceID, NetworkID: record.NetworkID, WireGuardPrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), WireGuardPublicKey: record.WireGuardPublicKey, Phase: state.PhaseAcknowledged, Config: cliTestConfig(), ConfigContract: "signed", SignedConfigID: "cfg_cli", SignedGeneration: 1}
	if err := stateStore.SaveLastKnown(lastKnown); err != nil {
		t.Fatal(err)
	}
	enrollmentToken := "xenr_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	syncConfig := signedconfig.Config{
		SchemaVersion: 1, ConfigID: "cfg_cli_sync", NetworkID: record.NetworkID, DeviceID: record.DeviceID, Generation: 2,
		IssuedAt: signedconfig.CanonicalTime{Time: now.Add(-time.Minute)}, ExpiresAt: signedconfig.CanonicalTime{Time: now.Add(time.Hour)}, ProxyCore: signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{Kind: signedconfig.TransportVLESS, Loopback: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830}, Remote: signedconfig.RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "gateway.example.net"}, AuthID: "11111111-1111-4111-8111-111111111111"},
		WireGuard: signedconfig.WireGuard{InterfaceName: "wg-xco", Addresses: []string{"10.77.0.20/32"}, MTU: 1280, Peers: []signedconfig.Peer{{GatewayID: "gw_cli", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.77.0.0/16"}, Endpoint: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830}, PersistentKeepaliveSeconds: 25}}},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "signing_key_01"},
	}
	payload, err := syncConfig.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	syncConfig.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		headers := http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}
		switch request.URL.Path {
		case "/api/overlay/v1/device/session":
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Device xdc_") {
				t.Fatalf("session missing device authorization")
			}
			var session controlplane.DeviceSessionRequest
			if err := json.NewDecoder(request.Body).Decode(&session); err != nil {
				t.Fatal(err)
			}
			body = `{"client_nonce":"` + session.ClientNonce + `","enrollment_token":"` + enrollmentToken + `","token_type":"Bearer","issued_at":"` + now.Format(time.RFC3339) + `","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339) + `","scope":["overlay:config:read","overlay:config:ack"],"device_id":"dev_cli","network_id":"net_private","signing_keys":[{"key_id":"signing_key_01","algorithm":"Ed25519","public_key":"` + signingPublicKey + `","status":"current","not_before":"` + now.Add(-time.Hour).Format(time.RFC3339) + `"}]}`
		case "/api/overlay/v1/enrollment/signed-config":
			if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
				t.Fatalf("config missing enrollment authorization")
			}
			raw, _ := json.Marshal(syncConfig)
			body = string(raw)
			headers.Set("Cache-Control", "private, no-store")
			headers.Set("ETag", `"cfg_cli_sync"`)
		case "/api/overlay/v1/enrollment/signed-config/2/ack":
			if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
				t.Fatalf("ack missing enrollment authorization")
			}
			body = `{"acked":true,"ack":{"device_id":"dev_cli","config_id":"cfg_cli_sync","generation":2,"applied_at":"` + now.Format(time.RFC3339) + `","received_at":"` + now.Format(time.RFC3339) + `"}}`
		case "/api/overlay/v1/device/credential/rotate":
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Device xdc_") {
				t.Fatalf("rotate missing device authorization")
			}
			var payload controlplane.DeviceCredentialRotateRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			body = `{"credential_id":"` + payload.NewCredentialID + `","replaces_credential_id":"` + record.CredentialID + `","token_type":"Device","issued_at":"` + now.Format(time.RFC3339) + `","expires_at":"` + now.Add(30*24*time.Hour).Format(time.RFC3339) + `","scope":["overlay:session:mint","overlay:credential:rotate","overlay:device:revoke"]}`
		case "/api/overlay/v1/device/revoke":
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Device xdc_") {
				t.Fatalf("revoke missing device authorization")
			}
			body = `{"revoked":true,"duplicate":false,"device":{"id":"dev_cli","user_id":"11111111-1111-4111-8111-111111111111","network_id":"net_private","name":"CLI","platform":"linux","hostname":"host","wireguard_public_key":"` + record.WireGuardPublicKey + `","wireguard_address":"10.77.0.20/32","created_at":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","updated_at":"` + now.Format(time.RFC3339) + `","last_seen_at":null,"status":"revoked","state_version":2,"key_version":1,"revoked_at":"` + now.Format(time.RFC3339) + `","revoked_reason":"explicit_leave"},"policy_generation":2,"policy_digest":"` + strings.Repeat("a", 64) + `"}`
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	httpClient := &http.Client{Transport: transport}
	runtimeFake := &overlayruntime.Fake{}
	credentialFactory := func(string) credential.Store { return credentials }
	runtimeFactory := func(string) overlayruntime.Interface { return runtimeFake }
	var stdout, stderr bytes.Buffer
	if err := runWithFactories(t.Context(), []string{"sync", "--state-dir", stateDirectory}, &stdout, &stderr, httpClient, runtimeFactory, credentialFactory); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if runtimeFake.ApplyCalls != 1 || strings.Contains(stdout.String(), record.Credential) || strings.Contains(stderr.String(), record.Credential) {
		t.Fatalf("sync apply=%d stdout=%q stderr=%q", runtimeFake.ApplyCalls, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if err := runWithFactories(t.Context(), []string{"credential", "rotate", "--state-dir", stateDirectory}, &stdout, &stderr, httpClient, runtimeFactory, credentialFactory); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated, err := credentials.Load(t.Context())
	if err != nil || rotated.CredentialID == record.CredentialID || strings.Contains(stdout.String(), rotated.Credential) || strings.Contains(stderr.String(), rotated.Credential) {
		t.Fatalf("rotated=%#v stdout=%q stderr=%q err=%v", rotated, stdout.String(), stderr.String(), err)
	}
	stdout.Reset()
	if err := runWithFactories(t.Context(), []string{"leave", "--state-dir", stateDirectory}, &stdout, &stderr, httpClient, runtimeFactory, credentialFactory); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if _, err := credentials.Load(t.Context()); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("credential remains after leave: %v", err)
	}
	if strings.Contains(stdout.String(), rotated.Credential) || strings.Contains(stderr.String(), rotated.Credential) {
		t.Fatal("leave output exposed device credential")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPolicyExplainOutputsOnlyScopedRuleAndResolvedDevices(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+cliTestToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/api/overlay/v1/policies/7":
			_, _ = writer.Write([]byte(`{"network_id":"net_private","revision":7,"name":"private","artifact_sha256":"58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c","compiler_version":"xconnect-acl-v1alpha1.1","warnings":[],"status":"active","generation":12,"created_at":"2026-08-28T12:00:00Z","validated_at":null,"activated_at":"2026-08-28T12:01:00Z"}`))
		case "/api/overlay/v1/policies/7/explain":
			_, _ = writer.Write([]byte(`{"action":"accept","rule_id":"allow-api","reason":"matched canonical rule","protected":false,"resolved_source_devices":["dev-a"],"resolved_destination_devices":["dev-b"]}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("XCONNECT_TOKEN", cliTestToken)
	var stdout, stderr bytes.Buffer
	err := runWithRuntimeFactory(t.Context(), []string{"policy", "explain", "--server", server.URL, "--network-id", "net_private", "--revision", "7", "--source", "device:dev-a", "--destination", "device:dev-b", "--protocol", "tcp", "--port", "8787"}, &stdout, &stderr, server.Client(), func(string) overlayruntime.Interface { return &overlayruntime.Fake{} })
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	for _, expected := range []string{`"generation": 12`, `"rule_id": "allow-api"`, `"dev-a"`, `"dev-b"`} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("missing %s: %s", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "@") || strings.Contains(stderr.String(), cliTestToken) {
		t.Fatalf("unsafe output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func newCLITestServer(t *testing.T, unauthorized bool, ackCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if unauthorized || request.Header.Get("Authorization") != "Bearer "+cliTestToken {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"token_expired","message":"cli-secret-token"}`))
			return
		}
		switch request.URL.Path {
		case "/api/overlay/v1/signing-keys", "/api/overlay/v1/signed-config":
			writer.WriteHeader(http.StatusNotFound)
		case "/api/overlay/v1/devices/register":
			var payload controlplane.RegisterDeviceRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("decode register request: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(controlplane.RegisterDeviceResponse{
				Device: model.Device{
					ID:                 payload.DeviceID,
					NetworkID:          "net_private",
					WireGuardPublicKey: payload.WireGuardPublicKey,
					WireGuardAddress:   "10.77.0.20/32",
				},
				Network: model.Network{ID: "net_private", DisplayName: "Private", CIDR: "10.77.0.0/16"},
			})
		case "/api/overlay/v1/config":
			_ = json.NewEncoder(writer).Encode(cliTestConfig())
		case "/api/overlay/v1/config/ack":
			ackCalls.Add(1)
			var payload controlplane.ConfigAckRequest
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("decode ack request: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(controlplane.ConfigAckResponse{
				Acked:     true,
				DeviceID:  payload.DeviceID,
				NetworkID: payload.NetworkID,
				Revision:  payload.Revision,
			})
		default:
			t.Errorf("unexpected API path %s", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
}

func cliTestConfig() model.Config {
	return model.Config{
		SchemaVersion: 1,
		Revision:      "revision-cli",
		Digest:        "digest-cli",
		Network:       model.Network{ID: "net_private", DisplayName: "Private", CIDR: "10.77.0.0/16"},
		Device:        model.Device{ID: "dev_cli", NetworkID: "net_private", WireGuardAddress: "10.77.0.20/32"},
		WireGuard: model.WireGuardConfig{
			Interface:            "wg-xco",
			Address:              "10.77.0.20/32",
			MTU:                  1280,
			PrivateKeyRef:        "local-keychain",
			LocalProxyEndpoint:   "127.0.0.1:51830",
			PeerPublicKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			PeerAllowedIPs:       []string{"10.77.0.0/16"},
			PeerEndpoint:         "127.0.0.1:51830",
			GatewayWireGuardIP:   "10.77.0.1",
			GatewayWireGuardCIDR: "10.77.0.1/32",
		},
		Transport: model.TransportConfig{
			Runtime:        model.WireRuntimeXrayCore,
			Type:           model.TransportVLESSTLS,
			Security:       model.TransportSecurityTLS,
			Server:         "gateway.example.net",
			Port:           443,
			UUID:           "11111111-1111-1111-1111-111111111111",
			PacketEncoding: model.PacketEncodingXUDP,
			LocalPort:      51830,
		},
	}
}

func newCLIInviteServer(t *testing.T) (*httptest.Server, string, string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	joinToken := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	enrollmentToken := "xenr_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	now := time.Now().UTC().Truncate(time.Second)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	notAfter := signedconfig.CanonicalTime{Time: now.Add(24 * time.Hour)}
	keys := []signedconfig.SigningKey{{
		KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Status: "current",
		NotBefore: signedconfig.CanonicalTime{Time: now.Add(-time.Hour)}, NotAfter: &notAfter,
	}}
	config := signedconfig.Config{
		SchemaVersion: 1, ConfigID: "cfg_cli_invite", NetworkID: "net_private", DeviceID: "dev_cli", Generation: 1,
		IssuedAt: signedconfig.CanonicalTime{Time: now.Add(-time.Minute)}, ExpiresAt: signedconfig.CanonicalTime{Time: now.Add(time.Hour)},
		ProxyCore: signedconfig.ProxyCoreXray,
		Transport: signedconfig.Transport{Kind: signedconfig.TransportVLESS, Loopback: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830}, Remote: signedconfig.RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "gateway.example.net"}, AuthID: "11111111-1111-1111-1111-111111111111"},
		WireGuard: signedconfig.WireGuard{InterfaceName: "wg-xco", Addresses: []string{"10.77.0.20/32"}, MTU: 1280, Peers: []signedconfig.Peer{{GatewayID: "gw_tokyo_01", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.77.0.0/16"}, Endpoint: signedconfig.Endpoint{Host: "127.0.0.1", Port: 51830}, PersistentKeepaliveSeconds: 25}}},
		Signature: signedconfig.Signature{Algorithm: signedconfig.SignatureEd25519, KeyID: "signing_key_01"},
	}
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	config.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	var exchangeCalls atomic.Int32
	var ackCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/overlay/v1/join-tokens/exchange":
			exchangeCalls.Add(1)
			if request.Header.Get("Authorization") != "" {
				t.Errorf("public exchange sent account bearer")
			}
			var exchange controlplane.JoinTokenExchangeRequest
			if err := json.NewDecoder(request.Body).Decode(&exchange); err != nil {
				t.Errorf("decode exchange: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			if exchange.JoinToken != joinToken || exchange.DeviceID != "dev_cli" {
				t.Errorf("unexpected exchange request")
			}
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(controlplane.JoinTokenExchangeResponse{
				EnrollmentToken: enrollmentToken, TokenType: "Bearer", ExpiresAt: now.Add(10 * time.Minute),
				Scope: []string{"overlay:config:read", "overlay:config:ack", "overlay:device:revoke"},
				DeviceCredential: controlplane.DeviceCredential{
					CredentialID: "xdcid_0123456789abcdef0123456789abcdef",
					Credential:   "xdc_0123456789abcdef0123456789abcdef." + strings.Repeat("A", 43),
					TokenType:    "Device", IssuedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
					Scope: []string{"overlay:session:mint", "overlay:credential:rotate", "overlay:device:revoke"},
				},
				Device:  model.Device{ID: "dev_cli", NetworkID: "net_private", Platform: runtime.GOOS, WireGuardPublicKey: exchange.WireGuardPublicKey, WireGuardAddress: "10.77.0.20/32"},
				Network: model.Network{ID: "net_private", CIDR: "10.77.0.0/16"}, SigningKeys: keys,
			})
		case "/api/overlay/v1/enrollment/signed-config":
			if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
				t.Errorf("signed config missing enrollment bearer")
			}
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("ETag", `"cfg_cli_invite"`)
			_ = json.NewEncoder(writer).Encode(config)
		case "/api/overlay/v1/enrollment/signed-config/1/ack":
			ackCalls.Add(1)
			if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
				t.Errorf("ACK missing enrollment bearer")
			}
			_ = json.NewEncoder(writer).Encode(controlplane.SignedConfigAckResponse{Acked: true, Ack: controlplane.SignedConfigAck{
				DeviceID: "dev_cli", ConfigID: "cfg_cli_invite", Generation: 1, AppliedAt: now, ReceivedAt: now.Add(time.Millisecond),
			}})
		default:
			t.Errorf("unexpected invite API path %s", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, joinToken, enrollmentToken, &exchangeCalls, &ackCalls
}
