// Modified for XConnect-One: standalone module imports.
package usecase_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

const testToken = "secret-access-token-value"

type controlPlaneFixture struct {
	t             *testing.T
	server        *httptest.Server
	mu            sync.Mutex
	registerCalls int
	configCalls   int
	ackCalls      int
	authFailure   bool
	configFailure int
	ackFailure    int
	config        model.Config
}

type externalXrayRuntime struct {
	overlayruntime.Fake
}

func (r *externalXrayRuntime) Apply(ctx context.Context, request overlayruntime.ApplyRequest) (overlayruntime.ApplyResult, error) {
	result, err := r.Fake.Apply(ctx, request)
	if err != nil {
		return result, err
	}
	result.AdapterID = model.AdapterIDXrayCore
	r.StatusResult.AdapterID = model.AdapterIDXrayCore
	return result, nil
}

func newControlPlaneFixture(t *testing.T) *controlPlaneFixture {
	t.Helper()
	fixture := &controlPlaneFixture{t: t, config: validConfig()}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *controlPlaneFixture) handle(writer http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	if f.authFailure || request.Header.Get("Authorization") != "Bearer "+testToken {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":"token_expired","message":"secret-access-token-value expired"}`))
		return
	}
	switch request.URL.Path {
	case "/api/overlay/v1/devices/register":
		f.registerCalls++
		var payload controlplane.RegisterDeviceRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			f.t.Errorf("decode register request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(controlplane.RegisterDeviceResponse{
			Device: model.Device{
				ID:                 payload.DeviceID,
				NetworkID:          "net_private",
				WireGuardPublicKey: payload.WireGuardPublicKey,
				WireGuardAddress:   "10.77.0.10/32",
			},
			Network: model.Network{ID: "net_private", DisplayName: "Private", CIDR: "10.77.0.0/16"},
		})
	case "/api/overlay/v1/config":
		f.configCalls++
		if got := request.URL.Query().Get("device_id"); got != "dev_laptop" {
			f.t.Errorf("device_id query = %q", got)
		}
		if f.configFailure > 0 {
			f.configFailure--
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("ETag", `"revision-7"`)
		_ = json.NewEncoder(writer).Encode(f.config)
	case "/api/overlay/v1/config/ack":
		f.ackCalls++
		if f.ackFailure > 0 {
			f.ackFailure--
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var payload controlplane.ConfigAckRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			f.t.Errorf("decode ack request: %v", err)
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
		f.t.Errorf("unexpected API path %s", request.URL.Path)
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (f *controlPlaneFixture) client(t *testing.T) *controlplane.Client {
	t.Helper()
	client, err := controlplane.New(f.server.URL, testToken, f.server.Client())
	if err != nil {
		t.Fatalf("create control plane client: %v", err)
	}
	return client
}

func (f *controlPlaneFixture) calls() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registerCalls, f.configCalls, f.ackCalls
}

func validConfig() model.Config {
	return model.Config{
		SchemaVersion: 1,
		Revision:      "revision-7",
		Digest:        "digest-7",
		Network:       model.Network{ID: "net_private", DisplayName: "Private", CIDR: "10.77.0.0/16"},
		Device: model.Device{
			ID:                 "dev_laptop",
			NetworkID:          "net_private",
			WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			WireGuardAddress:   "10.77.0.10/32",
		},
		WireGuard: model.WireGuardConfig{
			Interface:            "wg-xco",
			Address:              "10.77.0.10/32",
			MTU:                  1280,
			DNS:                  []string{"10.77.0.1"},
			PrivateKeyRef:        "local-keychain",
			LocalProxyEndpoint:   "127.0.0.1:51830",
			PersistentKeepalive:  25,
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

func fixedKeys() (string, string, error) {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), nil
}

func newJoiner(t *testing.T, fixture *controlPlaneFixture, tunnelRuntime overlayruntime.Interface) (*usecase.Joiner, *state.Store) {
	t.Helper()
	store := state.NewStore(t.TempDir())
	joiner := usecase.NewJoiner(fixture.client(t), store, tunnelRuntime).
		WithKeyGenerator(fixedKeys).
		WithClock(func() time.Time { return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC) })
	return joiner, store
}

func joinRequest(serverURL string) usecase.JoinRequest {
	return usecase.JoinRequest{
		Server:     serverURL,
		DeviceID:   "dev_laptop",
		DeviceName: "Laptop",
		Platform:   "linux",
		Hostname:   "laptop",
	}
}

func TestJoinSuccessUsesVersionedAPIAndPersistsSecureState(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	runtime := &overlayruntime.Fake{}
	joiner, store := newJoiner(t, fixture, runtime)

	result, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if result.DeviceID != "dev_laptop" || result.NetworkID != "net_private" || result.Revision != "revision-7" || result.AlreadyJoined {
		t.Fatalf("unexpected join result: %#v", result)
	}
	if runtime.ApplyCalls != 1 {
		t.Fatalf("runtime apply calls = %d, want 1", runtime.ApplyCalls)
	}
	registerCalls, configCalls, ackCalls := fixture.calls()
	if registerCalls != 1 || configCalls != 1 || ackCalls != 1 {
		t.Fatalf("API calls = register:%d config:%d ack:%d", registerCalls, configCalls, ackCalls)
	}
	if err := state.ValidatePermissions(store.LastKnownPath(), 0o600); err != nil {
		t.Fatalf("last-known permissions: %v", err)
	}
	if _, err := os.Stat(store.CheckpointPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint should be cleared, stat error: %v", err)
	}
}

func TestJoinAcceptsExternalXrayCoreAdapterAfterRealApply(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	tunnelRuntime := &externalXrayRuntime{}
	joiner, _ := newJoiner(t, fixture, tunnelRuntime)

	result, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
	if err != nil {
		t.Fatalf("join external Xray runtime: %v", err)
	}
	if result.Revision != fixture.config.Revision {
		t.Fatalf("unexpected join result: %#v", result)
	}
	_, _, ackCalls := fixture.calls()
	if ackCalls != 1 {
		t.Fatalf("ACK calls = %d, want 1 after external runtime apply", ackCalls)
	}
}

func TestRepeatedJoinIsIdempotent(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	runtime := &overlayruntime.Fake{}
	joiner, _ := newJoiner(t, fixture, runtime)
	request := joinRequest(fixture.server.URL)

	if _, err := joiner.Join(t.Context(), request); err != nil {
		t.Fatalf("first join: %v", err)
	}
	result, err := joiner.Join(t.Context(), request)
	if err != nil {
		t.Fatalf("second join: %v", err)
	}
	if !result.AlreadyJoined {
		t.Fatal("second join should report already_joined")
	}
	registerCalls, configCalls, ackCalls := fixture.calls()
	if registerCalls != 1 || configCalls != 1 || ackCalls != 1 || runtime.ApplyCalls != 1 {
		t.Fatalf("idempotent calls = register:%d config:%d apply:%d ack:%d", registerCalls, configCalls, runtime.ApplyCalls, ackCalls)
	}
}

func TestRepeatedJoinRecoversStoppedRuntimeWithoutRepeatingControlPlaneCalls(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	tunnelRuntime := &overlayruntime.Fake{}
	joiner, _ := newJoiner(t, fixture, tunnelRuntime)
	request := joinRequest(fixture.server.URL)
	if _, err := joiner.Join(t.Context(), request); err != nil {
		t.Fatalf("first join: %v", err)
	}
	tunnelRuntime.StatusResult.Applied = false

	result, err := joiner.Join(t.Context(), request)
	if err != nil {
		t.Fatalf("recover join: %v", err)
	}
	if !result.AlreadyJoined || tunnelRuntime.ApplyCalls != 2 {
		t.Fatalf("runtime recovery result=%#v apply calls=%d", result, tunnelRuntime.ApplyCalls)
	}
	registerCalls, configCalls, ackCalls := fixture.calls()
	if registerCalls != 1 || configCalls != 1 || ackCalls != 1 {
		t.Fatalf("recovery repeated control-plane calls: register=%d config=%d ack=%d", registerCalls, configCalls, ackCalls)
	}
}

func TestRepeatedJoinRuntimeRecoveryFailureDoesNotAckAgain(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	tunnelRuntime := &overlayruntime.Fake{}
	joiner, _ := newJoiner(t, fixture, tunnelRuntime)
	request := joinRequest(fixture.server.URL)
	if _, err := joiner.Join(t.Context(), request); err != nil {
		t.Fatalf("first join: %v", err)
	}
	tunnelRuntime.StatusResult.Applied = false
	tunnelRuntime.ApplyError = fault.New(fault.CodeRuntimeProcessStale, "stale PID", errors.New("untrusted executable"))

	_, err := joiner.Join(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeProcessStale {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	_, _, ackCalls := fixture.calls()
	if ackCalls != 1 {
		t.Fatalf("runtime recovery sent another ACK: %d", ackCalls)
	}
}

func TestJoinResumesAfterAckInterruptionWithoutReapplying(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	fixture.ackFailure = 1
	runtime := &overlayruntime.Fake{}
	joiner, store := newJoiner(t, fixture, runtime)
	request := joinRequest(fixture.server.URL)

	if _, err := joiner.Join(t.Context(), request); fault.Code(err) != fault.CodeControlPlaneUnavailable {
		t.Fatalf("first join code = %q, err=%v", fault.Code(err), err)
	}
	checkpoint, err := store.LoadCheckpoint()
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if checkpoint.Phase != state.PhaseRuntimeApplied {
		t.Fatalf("checkpoint phase = %q", checkpoint.Phase)
	}
	if _, err := joiner.Join(t.Context(), request); err != nil {
		t.Fatalf("resumed join: %v", err)
	}
	registerCalls, configCalls, ackCalls := fixture.calls()
	if registerCalls != 1 || configCalls != 1 || runtime.ApplyCalls != 1 || ackCalls != 2 {
		t.Fatalf("resume calls = register:%d config:%d apply:%d ack:%d", registerCalls, configCalls, runtime.ApplyCalls, ackCalls)
	}
}

func TestJoinMapsExpiredTokenWithoutLeakingIt(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	fixture.authFailure = true
	joiner, _ := newJoiner(t, fixture, &overlayruntime.Fake{})

	_, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
	if fault.Code(err) != fault.CodeAuthenticationFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "token_expired") {
		t.Fatalf("error leaked server authentication details: %v", err)
	}
}

func TestJoinRejectsInvalidConfigBeforeRuntimeAndAck(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*model.Config)
		wantCode string
	}{
		{
			name: "unsupported core",
			mutate: func(config *model.Config) {
				config.Transport.Runtime = "sing-box"
			},
			wantCode: fault.CodeUnsupportedRuntimeCore,
		},
		{
			name: "invalid transport",
			mutate: func(config *model.Config) {
				config.Transport.Type = "other"
			},
			wantCode: fault.CodeInvalidConfig,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newControlPlaneFixture(t)
			test.mutate(&fixture.config)
			runtime := &overlayruntime.Fake{}
			joiner, _ := newJoiner(t, fixture, runtime)

			_, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
			if fault.Code(err) != test.wantCode {
				t.Fatalf("error code = %q, want %q, err=%v", fault.Code(err), test.wantCode, err)
			}
			_, _, ackCalls := fixture.calls()
			if runtime.ApplyCalls != 0 || ackCalls != 0 {
				t.Fatalf("invalid config reached runtime/ACK: apply=%d ack=%d", runtime.ApplyCalls, ackCalls)
			}
		})
	}
}

func TestRuntimeApplyFailureDoesNotAckOrLeakSecrets(t *testing.T) {
	fixture := newControlPlaneFixture(t)
	privateKey, _, _ := fixedKeys()
	runtime := &overlayruntime.Fake{ApplyError: errors.New("runtime rejected key " + privateKey)}
	joiner, store := newJoiner(t, fixture, runtime)

	_, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
	if fault.Code(err) != fault.CodeRuntimeApplyFailed {
		t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
	}
	if strings.Contains(err.Error(), privateKey) {
		t.Fatalf("error leaked private key: %v", err)
	}
	_, _, ackCalls := fixture.calls()
	if ackCalls != 0 {
		t.Fatalf("ACK calls = %d, want 0", ackCalls)
	}
	checkpoint, loadErr := store.LoadCheckpoint()
	if loadErr != nil {
		t.Fatalf("load checkpoint: %v", loadErr)
	}
	if checkpoint.Phase != state.PhaseConfigFetched || checkpoint.LastErrorCode != fault.CodeRuntimeApplyFailed {
		t.Fatalf("unexpected failure checkpoint: %#v", checkpoint)
	}
}

func TestRuntimeSafetyGateCodesRemainStableAndNeverAck(t *testing.T) {
	for _, code := range []string{
		fault.CodeRuntimeDependency,
		fault.CodeRuntimePermission,
		fault.CodeRuntimeProcessStale,
		fault.CodeRuntimeRollbackFailed,
	} {
		t.Run(code, func(t *testing.T) {
			fixture := newControlPlaneFixture(t)
			tunnelRuntime := &overlayruntime.Fake{ApplyError: fault.New(code, "backend detail", errors.New("UUID 11111111-1111-1111-1111-111111111111"))}
			joiner, store := newJoiner(t, fixture, tunnelRuntime)

			_, err := joiner.Join(t.Context(), joinRequest(fixture.server.URL))
			if fault.Code(err) != code {
				t.Fatalf("error code = %q, want %q, err=%v", fault.Code(err), code, err)
			}
			if strings.Contains(err.Error(), "11111111-1111-1111-1111-111111111111") {
				t.Fatalf("error leaked runtime details: %v", err)
			}
			_, _, ackCalls := fixture.calls()
			if ackCalls != 0 {
				t.Fatalf("ACK calls = %d, want 0", ackCalls)
			}
			checkpoint, loadErr := store.LoadCheckpoint()
			if loadErr != nil {
				t.Fatalf("load checkpoint: %v", loadErr)
			}
			if checkpoint.Phase != state.PhaseConfigFetched || checkpoint.LastErrorCode != code {
				t.Fatalf("unexpected safety-gate checkpoint: %#v", checkpoint)
			}
		})
	}
}

func TestStatusReportsJoinedOnlyWhenAcknowledgedRuntimeIsHealthy(t *testing.T) {
	store := state.NewStore(t.TempDir())
	config := validConfig()
	if err := store.SaveLastKnown(state.LastKnown{
		Server:           "https://accounts.example",
		DeviceID:         config.Device.ID,
		NetworkID:        config.Network.ID,
		Phase:            state.PhaseAcknowledged,
		Config:           config,
		ConfigContract:   string(usecase.ConfigContractSigned),
		SignedGeneration: 42,
	}); err != nil {
		t.Fatalf("save last-known: %v", err)
	}
	if err := store.SavePolicyState(state.PolicyState{NetworkID: config.Network.ID, Generation: 17, Digest: strings.Repeat("a", 64), Revision: 7, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Hour), AcceptedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("save policy state: %v", err)
	}
	tunnelRuntime := &overlayruntime.Fake{StatusResult: overlayruntime.Status{
		Available: true,
		Applied:   false,
		Revision:  config.Revision,
		CoreID:    model.CoreIDXray,
		AdapterID: model.AdapterIDXrayCore,
	}}
	result, err := usecase.Status(t.Context(), store, tunnelRuntime)
	if err != nil {
		t.Fatalf("status while stopped: %v", err)
	}
	if result.Joined {
		t.Fatalf("stopped runtime reported joined: %#v", result)
	}
	if result.Generations.State != 42 || result.Generations.RuntimeRevision != config.Revision || result.Generations.Policy != 17 || result.Generations.PolicyExpired {
		t.Fatalf("generation status=%#v", result.Generations)
	}
	tunnelRuntime.StatusResult.Applied = true
	result, err = usecase.Status(t.Context(), store, tunnelRuntime)
	if err != nil || !result.Joined {
		t.Fatalf("healthy acknowledged runtime status=%#v err=%v", result, err)
	}
}
