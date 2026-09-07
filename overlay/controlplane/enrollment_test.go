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
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

func TestExchangeJoinTokenIsPublicStrictAndNoStore(t *testing.T) {
	joinToken := testOpaqueSecret("xjt_", 7)
	enrollmentToken := testOpaqueSecret("xenr_", 9)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/overlay/v1/join-tokens/exchange" || request.Header.Get("Authorization") != "" {
			t.Fatalf("exchange request path/auth = %s %q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["join_token"] != joinToken || body["wireguard_public_key"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
			t.Fatalf("exchange body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(validExchangeJSON(enrollmentToken, "dev_laptop", now.Add(10*time.Minute))))
	}))
	defer server.Close()
	client, err := controlplane.New(server.URL, "account-token-must-not-be-sent", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.ExchangeJoinToken(t.Context(), controlplane.JoinTokenExchangeRequest{
		JoinToken: joinToken, DeviceID: "dev_laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Now: now,
	})
	if err != nil || response.EnrollmentToken != enrollmentToken || response.Network.ID != "net_private" || len(response.SigningKeys) != 1 {
		t.Fatalf("exchange response=%#v err=%v", response, err)
	}
}

func TestExchangeJoinTokenRejectsCacheableMalformedOrUnboundResponse(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		cache string
		body  string
	}{
		{name: "cacheable", cache: "private, max-age=60", body: validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(10*time.Minute))},
		{name: "unknown field", cache: "no-store", body: strings.Replace(validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(10*time.Minute)), `"token_type":"Bearer"`, `"token_type":"Bearer","unexpected":true`, 1)},
		{name: "wrong device", cache: "no-store", body: validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_other", now.Add(10*time.Minute))},
		{name: "wrong scope", cache: "no-store", body: strings.Replace(validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(10*time.Minute)), `"overlay:config:ack"`, `"overlay:admin"`, 1)},
		{name: "device address is not host prefix", cache: "no-store", body: strings.Replace(validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(10*time.Minute)), `10.77.0.10/32`, `10.77.0.0/24`, 1)},
		{name: "expired", cache: "no-store", body: validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(-time.Second))},
		{name: "excessive lifetime", cache: "no-store", body: validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", now.Add(2*time.Hour))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("Cache-Control", test.cache)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newSignedClient(t, server)
			_, err := client.ExchangeJoinToken(t.Context(), controlplane.JoinTokenExchangeRequest{
				JoinToken: testOpaqueSecret("xjt_", 7), DeviceID: "dev_laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Now: now,
			})
			if fault.Code(err) != fault.CodeInvalidResponse {
				t.Fatalf("error code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}

func TestEnrollmentSignedConfigAndAckUseOnlyEnrollmentBearer(t *testing.T) {
	enrollmentToken := testOpaqueSecret("xenr_", 9)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/overlay/v1/enrollment/signed-config":
			if request.URL.Query().Get("device_id") != "dev_laptop" || request.URL.Query().Get("network_id") != "net_private" {
				t.Fatalf("query = %s", request.URL.RawQuery)
			}
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("ETag", `"cfg_42"`)
			_, _ = writer.Write([]byte(validSignedConfigJSON()))
		case "/api/overlay/v1/enrollment/signed-config/42/ack":
			_, _ = writer.Write([]byte(`{"acked":true,"duplicate":false,"ack":{"device_id":"dev_laptop","config_id":"cfg_42","generation":42,"applied_at":"2026-08-28T12:00:00Z","received_at":"2026-08-28T12:00:00.123456Z"}}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := controlplane.New(server.URL, "account-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	config, err := client.GetEnrollmentSignedConfig(t.Context(), enrollmentToken, controlplane.SignedConfigRequest{DeviceID: "dev_laptop", NetworkID: "net_private"})
	if err != nil || config.Generation != 42 {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	ack, err := client.AckEnrollmentSignedConfig(t.Context(), enrollmentToken, controlplane.SignedConfigAckRequest{Generation: 42, ConfigID: "cfg_42", DeviceID: "dev_laptop", AppliedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)})
	if err != nil || !ack.Acked || ack.Ack.ReceivedAt.Nanosecond() == 0 {
		t.Fatalf("ack=%#v err=%v", ack, err)
	}
}

func TestEnrollmentSignedConfigV2AndPolicyArtifactArePinned(t *testing.T) {
	enrollmentToken := testOpaqueSecret("xenr_", 9)
	digest := "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c"
	policyPath := "/api/overlay/v1/enrollment/policy-artifacts/9/" + digest
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+enrollmentToken {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/api/overlay/v1/enrollment/signed-config":
			if request.Header.Get("Accept") != controlplane.SignedConfigV2MediaType {
				t.Fatalf("v2 accept = %q", request.Header.Get("Accept"))
			}
			writer.Header().Set("Content-Type", controlplane.SignedConfigV2MediaType)
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("Vary", "Accept")
			writer.Header().Set("ETag", `"cfg-v2"`)
			_, _ = writer.Write([]byte(validSignedConfigV2JSON()))
		case policyPath:
			if request.Header.Get("Accept") != "application/vnd.xconnect.policy.v1+json" {
				t.Fatalf("policy accept = %q", request.Header.Get("Accept"))
			}
			writer.Header().Set("Content-Type", "application/vnd.xconnect.policy.v1+json")
			writer.Header().Set("Cache-Control", "private, no-store")
			_, _ = writer.Write([]byte(`{"schema_version":1,"compiler_version":"xconnect-acl-v1alpha1.1","network_id":"net_private","revision":7,"default_action":"deny","protected_flows":["control:controller-session","control:gateway-apply-result","control:gateway-heartbeat","control:gateway-policy-artifact","control:gateway-snapshot"],"rules":[]}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := controlplane.New(server.URL, "account-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	config, err := client.GetEnrollmentSignedConfigV2(t.Context(), enrollmentToken, controlplane.SignedConfigRequest{DeviceID: "dev_laptop", NetworkID: "net_private"})
	if err != nil || config.SchemaVersion != 2 || config.Policy == nil || config.Policy.Path != policyPath {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	if _, err := client.GetEnrollmentPolicyArtifact(t.Context(), enrollmentToken, *config.Policy); err != nil {
		t.Fatalf("fetch policy: %v", err)
	}
}

func TestEnrollmentPolicyRejectsRedirectAndBadContract(t *testing.T) {
	enrollmentToken := testOpaqueSecret("xenr_", 9)
	policy := mustPolicyReference(t)
	for _, test := range []struct {
		name        string
		redirect    bool
		contentType string
		cache       string
	}{
		{name: "redirect", redirect: true},
		{name: "wrong media type", contentType: "application/json", cache: "private, no-store"},
		{name: "cacheable", contentType: "application/vnd.xconnect.policy.v1+json", cache: "private, max-age=60"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if test.redirect {
					http.Redirect(writer, request, "https://elsewhere.example/policy", http.StatusFound)
					return
				}
				writer.Header().Set("Content-Type", test.contentType)
				writer.Header().Set("Cache-Control", test.cache)
				_, _ = writer.Write([]byte(`{}`))
			}))
			defer server.Close()
			client, err := controlplane.New(server.URL, "account-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetEnrollmentPolicyArtifact(t.Context(), enrollmentToken, policy); fault.Code(err) != fault.CodeInvalidResponse && fault.Code(err) != fault.CodeControlPlaneUnavailable {
				t.Fatalf("code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}

func mustPolicyReference(t *testing.T) signedconfig.Policy {
	t.Helper()
	return signedconfig.Policy{Generation: 9, Digest: "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c", Path: "/api/overlay/v1/enrollment/policy-artifacts/9/58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c", MediaType: signedconfig.PolicyMediaType}
}

func TestInviteAndEnrollmentErrorsAreStableAndSecretFree(t *testing.T) {
	joinToken := testOpaqueSecret("xjt_", 7)
	enrollmentToken := testOpaqueSecret("xenr_", 9)
	for _, test := range []struct {
		name string
		path string
		call func(*controlplane.Client) error
		want string
	}{
		{name: "consumed invite", path: "/api/overlay/v1/join-tokens/exchange", want: fault.CodeJoinInviteInvalid, call: func(client *controlplane.Client) error {
			_, err := client.ExchangeJoinToken(t.Context(), controlplane.JoinTokenExchangeRequest{JoinToken: joinToken, DeviceID: "dev_laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Now: time.Now()})
			return err
		}},
		{name: "expired enrollment", path: "/api/overlay/v1/enrollment/signed-config", want: fault.CodeEnrollmentExpired, call: func(client *controlplane.Client) error {
			_, err := client.GetEnrollmentSignedConfig(t.Context(), enrollmentToken, controlplane.SignedConfigRequest{DeviceID: "dev_laptop"})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"error":"invalid","message":"` + joinToken + enrollmentToken + `"}`))
			}))
			defer server.Close()
			err := test.call(newSignedClient(t, server))
			if fault.Code(err) != test.want || strings.Contains(err.Error(), joinToken) || strings.Contains(err.Error(), enrollmentToken) {
				t.Fatalf("error code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}

func testOpaqueSecret(prefix string, fill byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func validExchangeJSON(enrollmentToken, deviceID string, expiresAt time.Time) string {
	issuedAt := expiresAt.Add(-10 * time.Minute).UTC().Truncate(time.Second)
	credentialExpiresAt := issuedAt.Add(30 * 24 * time.Hour)
	return `{"enrollment_token":"` + enrollmentToken + `","token_type":"Bearer","expires_at":"` + expiresAt.UTC().Format(time.RFC3339Nano) + `","scope":["overlay:config:read","overlay:config:ack","overlay:device:revoke"],"device_credential":{"credential_id":"xdcid_0123456789abcdef0123456789abcdef","credential":"xdc_0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","token_type":"Device","issued_at":"` + issuedAt.Format(time.RFC3339) + `","expires_at":"` + credentialExpiresAt.Format(time.RFC3339) + `","scope":["overlay:session:mint","overlay:credential:rotate","overlay:device:revoke"]},"device":{"id":"` + deviceID + `","network_id":"net_private","name":"Laptop","platform":"linux","hostname":"laptop","wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","wireguard_address":"10.77.0.10/32"},"network":{"id":"net_private","display_name":"Private","cidr":"10.77.0.0/16"},"signing_keys":` + strings.TrimSuffix(strings.TrimPrefix(validSigningKeysJSON(), `{"keys":`), `}`) + `}`
}
