package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateJoinTokenRejectsCacheableOrUnknownSecretResponse(t *testing.T) {
	secret := "xjt_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	tests := []struct {
		name  string
		cache string
		extra string
	}{
		{name: "cacheable", cache: "private, max-age=60"},
		{name: "unknown secret field", cache: "no-store", extra: `,"raw_token":"` + secret + `"`},
		{name: "expiry exceeds requested lifetime", cache: "no-store"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("Cache-Control", test.cache)
				_, _ = writer.Write([]byte(`{"join_token":{"id":"join_01","join_uri":"xconnect://join/` + secret + `?controller=` + server.URL + `","network_id":"net","device_id":"","platform":"","remaining_uses":1,"expires_at":"2030-08-28T12:00:00Z"` + test.extra + `}}`))
			}))
			t.Cleanup(server.Close)
			client, err := New(server.URL, "account-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.CreateJoinToken(t.Context(), CreateJoinTokenRequest{NetworkID: "net", ExpiresInSeconds: 900})
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "account-secret") {
				t.Fatalf("unsafe error=%v", err)
			}
		})
	}
}

func TestExplainPolicyRejectsPIIAndUnknownFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/overlay/v1/policies/7":
			_, _ = writer.Write([]byte(`{"network_id":"net","revision":7,"name":"policy","artifact_sha256":"58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c","compiler_version":"xconnect-acl-v1alpha1.1","warnings":[],"status":"active","generation":3,"created_at":"2026-08-28T12:00:00Z","validated_at":null,"activated_at":null}`))
		case "/api/overlay/v1/policies/7/explain":
			_, _ = writer.Write([]byte(`{"action":"deny","reason":"default deny","protected":false,"resolved_source_devices":["person@example.com"],"tenant":"other"}`))
		}
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL, "account-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ExplainPolicy(t.Context(), 7, PolicyExplainRequest{NetworkID: "net", Source: "device:dev-a", Destination: "device:dev-b", Protocol: "tcp", Port: 443})
	if err == nil || strings.Contains(err.Error(), "person@example.com") || strings.Contains(err.Error(), "account-secret") {
		t.Fatalf("unsafe error=%v", err)
	}
}

func TestExplainPolicyRejectsUntrustedReasonText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/overlay/v1/policies/7":
			_, _ = writer.Write([]byte(`{"network_id":"net","revision":7,"name":"policy","artifact_sha256":"58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c","compiler_version":"xconnect-acl-v1alpha1.1","warnings":[],"status":"active","generation":3,"created_at":"2026-08-28T12:00:00Z","validated_at":null,"activated_at":null}`))
		case "/api/overlay/v1/policies/7/explain":
			_, _ = writer.Write([]byte(`{"action":"deny","reason":"tenant owner person@example.com","protected":false}`))
		}
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL, "account-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ExplainPolicy(t.Context(), 7, PolicyExplainRequest{NetworkID: "net", Source: "device:dev-a", Destination: "device:dev-b", Protocol: "tcp", Port: 443})
	if err == nil || strings.Contains(err.Error(), "person@example.com") {
		t.Fatalf("unsafe error=%v", err)
	}
}
