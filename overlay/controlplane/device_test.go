// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const testDeviceNonce = "12345678-1234-4123-8123-123456789abc"
const testSessionSigningKeys = `"signing_keys":[{"key_id":"signing_key_01","algorithm":"Ed25519","public_key":"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","status":"current","not_before":"2026-08-01T00:00:00Z"}]`

func TestDeviceSessionUsesDeviceAuthorizationAndValidatesNonceBinding(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	var record credential.Record
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/overlay/v1/device/session" || request.Header.Get("Authorization") != "Device "+record.Credential {
			t.Errorf("request path=%q authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "private, no-store")
		_, _ = writer.Write([]byte(`{"client_nonce":"` + testDeviceNonce + `","enrollment_token":"xenr_` + strings.Repeat("A", 43) + `","token_type":"Bearer","issued_at":"2026-08-28T12:00:00Z","expires_at":"2026-08-28T12:10:00Z","scope":["overlay:config:read","overlay:config:ack"],"device_id":"device-alpha","network_id":"network-private",` + testSessionSigningKeys + `}`))
	}))
	defer server.Close()
	record = validDeviceRecord(t, server.URL)
	client, err := New(server.URL, "unrelated-user-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.MintDeviceSession(t.Context(), record, DeviceSessionRequest{ClientNonce: testDeviceNonce, Now: now})
	if err != nil || response.ClientNonce != testDeviceNonce || len(response.Scope) != 2 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestDeviceSessionRejectsNonceMismatchUnknownFieldAndMissingNoStore(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	base := `{"client_nonce":"87654321-1234-4123-8123-123456789abc","enrollment_token":"xenr_` + strings.Repeat("A", 43) + `","token_type":"Bearer","issued_at":"2026-08-28T12:00:00Z","expires_at":"2026-08-28T12:10:00Z","scope":["overlay:config:read","overlay:config:ack"],"device_id":"device-alpha","network_id":"network-private",` + testSessionSigningKeys + `}`
	for name, fixture := range map[string][2]string{
		"nonce":   {base, "no-store"},
		"unknown": {strings.TrimSuffix(base, "}") + `,"private_key":"forbidden"}`, "no-store"},
		"cache":   {strings.Replace(base, "87654321-1234-4123-8123-123456789abc", testDeviceNonce, 1), "private"},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("Cache-Control", fixture[1])
				_, _ = writer.Write([]byte(fixture[0]))
			}))
			defer server.Close()
			client, _ := New(server.URL, "", server.Client())
			_, err := client.MintDeviceSession(t.Context(), validDeviceRecord(t, server.URL), DeviceSessionRequest{ClientNonce: testDeviceNonce, Now: now})
			if fault.Code(err) != fault.CodeDeviceSessionInvalid && fault.Code(err) != fault.CodeInvalidResponse {
				t.Fatalf("code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}

func TestDeviceSessionRejectsSigningKeyRingWithoutTrustedOverlap(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		untrusted := `"signing_keys":[{"key_id":"signing_key_other","algorithm":"Ed25519","public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","status":"current","not_before":"2026-08-01T00:00:00Z"}]`
		_, _ = writer.Write([]byte(`{"client_nonce":"` + testDeviceNonce + `","enrollment_token":"xenr_` + strings.Repeat("A", 43) + `","token_type":"Bearer","issued_at":"2026-08-28T12:00:00Z","expires_at":"2026-08-28T12:10:00Z","scope":["overlay:config:read","overlay:config:ack"],"device_id":"device-alpha","network_id":"network-private",` + untrusted + `}`))
	}))
	defer server.Close()
	client, _ := New(server.URL, "", server.Client())
	_, err := client.MintDeviceSession(t.Context(), validDeviceRecord(t, server.URL), DeviceSessionRequest{ClientNonce: testDeviceNonce, Now: now})
	if fault.Code(err) != fault.CodeDeviceSessionInvalid {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
}

func TestDeviceCredentialRotateUsesCanonicalFullTokenVerifierAndIdempotency(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	pending, err := credential.GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x22}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := credential.Verifier(pending.Value)
	if verifier == credentialIDOnlyDigest(pending.CredentialID) {
		t.Fatal("test vector did not distinguish full token hashing")
	}
	requestBody := DeviceCredentialRotateRequest{NewCredentialID: pending.CredentialID, NewCredentialSHA256: verifier}
	var record credential.Record
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var received DeviceCredentialRotateRequest
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received != requestBody {
			t.Errorf("request=%#v err=%v", received, err)
		}
		encoded, _ := json.Marshal(requestBody)
		sum := sha256.Sum256(encoded)
		if request.Header.Get("Idempotency-Key") != "sha256-"+hex.EncodeToString(sum[:]) || request.Header.Get("Authorization") != "Device "+record.Credential {
			t.Errorf("headers=%v", request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(`{"credential_id":"` + pending.CredentialID + `","replaces_credential_id":"` + record.CredentialID + `","token_type":"Device","issued_at":"2026-08-28T12:00:00Z","expires_at":"2026-09-27T12:00:00Z","scope":["overlay:session:mint","overlay:credential:rotate","overlay:device:revoke"]}`))
	}))
	defer server.Close()
	record = validDeviceRecord(t, server.URL)
	client, _ := New(server.URL, "", server.Client())
	response, err := client.RotateDeviceCredential(t.Context(), record, requestBody, now)
	if err != nil || response.CredentialID != pending.CredentialID {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestDeviceRevokeValidatesTerminalReceiptAndCanonicalNonce(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	requestBody := DeviceRevokeRequest{ClientNonce: testDeviceNonce}
	var record credential.Record
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := json.Marshal(requestBody)
		sum := sha256.Sum256(encoded)
		if request.Header.Get("Idempotency-Key") != "sha256-"+hex.EncodeToString(sum[:]) || request.Header.Get("Authorization") != "Device "+record.Credential {
			t.Errorf("headers=%v", request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(`{"revoked":true,"duplicate":false,"device":{"id":"device-alpha","user_id":"user-redacted","network_id":"network-private","name":"Laptop","platform":"linux","hostname":"host","wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","wireguard_address":"10.77.0.2/32","created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-28T12:00:00Z","last_seen_at":null,"status":"revoked","state_version":2,"key_version":1,"revoked_at":"2026-08-28T12:00:00Z","revoked_reason":"self_service_leave"},"policy_generation":12,"policy_digest":"` + strings.Repeat("a", 64) + `","policy_reconcile_pending":false}`))
	}))
	defer server.Close()
	record = validDeviceRecord(t, server.URL)
	client, _ := New(server.URL, "", server.Client())
	response, err := client.RevokeDevice(t.Context(), record, requestBody, now)
	if err != nil || !response.Revoked || response.Device.ID != record.DeviceID {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestDeviceAuthorizationRejectsHTTPAndRedactsCredential(t *testing.T) {
	record := validDeviceRecord(t, "https://accounts.example")
	client, _ := New("http://accounts.example", "", http.DefaultClient)
	_, err := client.MintDeviceSession(context.Background(), record, DeviceSessionRequest{ClientNonce: testDeviceNonce, Now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)})
	if fault.Code(err) != fault.CodeInvalidInput || strings.Contains(err.Error(), record.Credential) {
		t.Fatalf("code=%q err=%v", fault.Code(err), err)
	}
}

func validDeviceRecord(t *testing.T, controller string) credential.Record {
	t.Helper()
	secret, err := credential.GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x11}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	return credential.Record{
		SchemaVersion: credential.SchemaVersion, Controller: controller, DeviceID: "device-alpha", NetworkID: "network-private", Platform: "linux",
		WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", CredentialID: secret.CredentialID, Credential: secret.Value,
		IssuedAt: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC),
		Scope:       []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke},
		SigningKeys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519, PublicKey: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", Status: "current", NotBefore: signedconfig.CanonicalTime{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}}}},
	}
}

func credentialIDOnlyDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
