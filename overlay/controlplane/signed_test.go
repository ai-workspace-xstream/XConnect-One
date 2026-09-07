// Modified for XConnect-One: standalone module imports.
package controlplane_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestGetSigningKeysUsesPrivateETagCache(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header was not sent")
		}
		if calls == 2 {
			if got := request.Header.Get("If-None-Match"); got != `"keys-1"` {
				t.Fatalf("If-None-Match = %q", got)
			}
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "private, max-age=300")
		writer.Header().Set("Vary", "Accept-Encoding, Authorization")
		writer.Header().Set("ETag", `"keys-1"`)
		_, _ = writer.Write([]byte(validSigningKeysJSON()))
	}))
	defer server.Close()
	client := newSignedClient(t, server)

	first, err := client.GetSigningKeys(t.Context(), "")
	if err != nil || first.NotModified || first.ETag != `"keys-1"` || len(first.Keys.Keys) != 1 {
		t.Fatalf("first signing keys = %#v, err=%v", first, err)
	}
	second, err := client.GetSigningKeys(t.Context(), first.ETag)
	if err != nil || !second.NotModified || second.ETag != first.ETag {
		t.Fatalf("cached signing keys = %#v, err=%v", second, err)
	}
}

func TestSignedContractRejectsMalformedAndOversizedResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "invalid content type", contentType: "text/plain", body: validSignedConfigJSON()},
		{name: "unknown field", contentType: "application/json", body: strings.Replace(validSignedConfigJSON(), `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1)},
		{name: "nested secret", contentType: "application/json", body: strings.Replace(validSignedConfigJSON(), `"mtu":1280`, `"mtu":1280,"private_key":"secret"`, 1)},
		{name: "trailing JSON", contentType: "application/json", body: validSignedConfigJSON() + `{}`},
		{name: "oversized", contentType: "application/json", body: validSignedConfigJSON() + strings.Repeat(" ", (2<<20)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.Header().Set("Cache-Control", "private, no-store")
				writer.Header().Set("ETag", `"config-1"`)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newSignedClient(t, server)
			_, err := client.GetSignedConfig(t.Context(), controlplane.SignedConfigRequest{DeviceID: "dev_laptop"})
			if fault.Code(err) != fault.CodeInvalidResponse && fault.Code(err) != fault.CodeInvalidSignedConfig {
				t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
			}
		})
	}
}

func TestSignedContractAcceptsVendorJSONAndSendsGenerationAck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.xconnect+json; charset=utf-8")
		switch request.URL.Path {
		case "/api/overlay/v1/signed-config":
			if request.URL.Query().Get("device_id") != "dev_laptop" || request.URL.Query().Get("network_id") != "net_private" {
				t.Fatalf("unexpected query: %s", request.URL.RawQuery)
			}
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("ETag", `"config-42"`)
			_, _ = writer.Write([]byte(validSignedConfigJSON()))
		case "/api/overlay/v1/signed-config/42/ack":
			var requestBody map[string]any
			if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
				t.Fatal(err)
			}
			if requestBody["config_id"] != "cfg_42" || requestBody["device_id"] != "dev_laptop" || requestBody["applied_at"] != "2026-08-27T12:00:00Z" {
				t.Fatalf("ack body = %#v", requestBody)
			}
			_, _ = writer.Write([]byte(`{"acked":true,"duplicate":false,"ack":{"device_id":"dev_laptop","config_id":"cfg_42","generation":42,"applied_at":"2026-08-27T12:00:00Z","received_at":"2026-08-27T12:00:01Z"}}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newSignedClient(t, server)

	config, err := client.GetSignedConfig(t.Context(), controlplane.SignedConfigRequest{DeviceID: "dev_laptop", NetworkID: "net_private"})
	if err != nil || config.Generation != 42 || config.ETag != `"config-42"` {
		t.Fatalf("signed config = %#v, err=%v", config, err)
	}
	response, err := client.AckSignedConfig(t.Context(), controlplane.SignedConfigAckRequest{
		Generation: 42, ConfigID: "cfg_42", DeviceID: "dev_laptop", AppliedAt: time.Date(2026, 8, 27, 12, 0, 0, 987, time.UTC),
	})
	if err != nil || !response.Acked || response.Ack.Generation != 42 {
		t.Fatalf("signed ack = %#v, err=%v", response, err)
	}
}

func TestSignedCapabilityMapsOnly404And503ToUnavailable(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(status) }))
		client := newSignedClient(t, server)
		_, err := client.GetSigningKeys(t.Context(), "")
		server.Close()
		if fault.Code(err) != fault.CodeSignedConfigUnavailable {
			t.Fatalf("status %d error code = %q, err=%v", status, fault.Code(err), err)
		}
	}
}

func newSignedClient(t *testing.T, server *httptest.Server) *controlplane.Client {
	t.Helper()
	client, err := controlplane.New(server.URL, "token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validSigningKeysJSON() string {
	return `{"keys":[{"key_id":"signing_key_01","algorithm":"Ed25519","public_key":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `","status":"current","not_before":"2026-08-01T00:00:00Z","not_after":"2026-09-01T00:00:00Z"}]}`
}

func validSignedConfigJSON() string {
	return `{"schema_version":1,"config_id":"cfg_42","network_id":"net_private","device_id":"dev_laptop","generation":42,"issued_at":"2026-08-27T12:00:00Z","expires_at":"2026-08-27T13:00:00Z","proxy_core":"xray","transport":{"kind":"vless-tls-xudp","loopback":{"host":"127.0.0.1","port":51830},"remote":{"host":"gateway.example.net","port":443,"server_name":"gateway.example.net"},"auth_id":"11111111-1111-1111-1111-111111111111"},"wireguard":{"interface_name":"wg-xco","addresses":["10.77.0.10/32"],"mtu":1280,"peers":[{"gateway_id":"gw_tokyo_01","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.77.0.0/16"],"endpoint":{"host":"127.0.0.1","port":51830},"persistent_keepalive_seconds":25}]},"signature":{"algorithm":"Ed25519","key_id":"signing_key_01","value":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}}`
}

func validSignedConfigV2JSON() string {
	digest := "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c"
	return `{"schema_version":2,"config_id":"cfg_42","network_id":"net_private","device_id":"dev_laptop","generation":42,"issued_at":"2026-08-27T12:00:00Z","expires_at":"2026-08-27T13:00:00Z","proxy_core":"xray","transport":{"kind":"vless-tls-xudp","loopback":{"host":"127.0.0.1","port":51830},"remote":{"host":"gateway.example.net","port":443,"server_name":"gateway.example.net"},"auth_id":"11111111-1111-1111-1111-111111111111"},"wireguard":{"interface_name":"wg-xco","addresses":["10.77.0.10/32"],"mtu":1280,"peers":[{"gateway_id":"gw_tokyo_01","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.77.0.0/16"],"endpoint":{"host":"127.0.0.1","port":51830},"persistent_keepalive_seconds":25}]},"policy":{"generation":9,"digest":"` + digest + `","path":"/api/overlay/v1/enrollment/policy-artifacts/9/` + digest + `","media_type":"application/vnd.xconnect.policy.v1+json"},"signature":{"algorithm":"Ed25519","key_id":"signing_key_01","value":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}}`
}
