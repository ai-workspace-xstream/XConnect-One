// Modified for XConnect-One: standalone module imports.
package controlplane_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestCreateRegistrationUsesExactPublicBodyAndNoOwnerBearer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/overlay/v1/registrations" || request.Header.Get("Authorization") != "" {
			t.Fatalf("request method/path/auth = %s %s %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"network_id": "net_public", "device_id": "dev_laptop", "name": "Laptop", "hostname": "laptop", "platform": "linux", "wireguard_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
		if len(body) != len(want) {
			t.Fatalf("registration body has unexpected fields: %#v", body)
		}
		for key, value := range want {
			if body[key] != value {
				t.Fatalf("body[%q]=%#v, want %#v", key, body[key], value)
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"registration_id":"xreg_test123","registration_token":"` + testOpaqueSecret("xrt_", 3) + `","status":"pending","expires_at":"` + time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339) + `","interval":5}`))
	}))
	defer server.Close()
	client, err := controlplane.New(server.URL, "owner-token-must-not-be-used", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateRegistration(t.Context(), controlplane.RegistrationCreateRequest{NetworkID: "net_public", DeviceID: "dev_laptop", Name: "Laptop", Hostname: "laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if fault.Code(err) != fault.CodeInvalidInput {
		t.Fatalf("owner credential accepted, code=%q err=%v", fault.Code(err), err)
	}
	client, err = controlplane.New(server.URL, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.CreateRegistration(t.Context(), controlplane.RegistrationCreateRequest{NetworkID: "net_public", DeviceID: "dev_laptop", Name: "Laptop", Hostname: "laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if err != nil || response.Status != "pending" || response.RegistrationID != "xreg_test123" {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if _, err := client.CreateRegistration(t.Context(), controlplane.RegistrationCreateRequest{NetworkID: "net_public", DeviceID: "dev_laptop", Platform: "linux", WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}); fault.Code(err) != fault.CodeInvalidInput {
		t.Fatalf("non-canonical public key code=%q err=%v", fault.Code(err), err)
	}
}

func TestCreateRegistrationRejectsMobilePlatformsInFirstPhase(t *testing.T) {
	client, err := controlplane.New("https://accounts.example", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"ios", "android"} {
		_, err := client.CreateRegistration(t.Context(), controlplane.RegistrationCreateRequest{
			NetworkID: "net_public", DeviceID: "dev_mobile", Platform: platform,
			WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		})
		if fault.Code(err) != fault.CodeInvalidInput {
			t.Fatalf("platform=%s code=%q err=%v", platform, fault.Code(err), err)
		}
	}
}

func TestExchangeRegistrationSupportsPendingAndExactExistingExchange(t *testing.T) {
	registrationToken := testOpaqueSecret("xrt_", 4)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/overlay/v1/registrations/xreg_test123/exchange" || request.Header.Get("Authorization") != "Bearer "+registrationToken {
			t.Fatalf("request method/path/auth = %s %s %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		if raw, err := io.ReadAll(request.Body); err != nil || len(bytes.TrimSpace(raw)) != 0 {
			t.Fatalf("exchange body=%q err=%v", raw, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		if calls.Add(1) == 1 {
			writer.WriteHeader(http.StatusAccepted)
			_, _ = writer.Write([]byte(`{"status":"pending","expires_at":"` + time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339) + `","interval":5}`))
			return
		}
		_, _ = writer.Write([]byte(validExchangeJSON(testOpaqueSecret("xenr_", 9), "dev_laptop", time.Now().UTC().Add(10*time.Minute))))
	}))
	defer server.Close()
	client, err := controlplane.New(server.URL, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	// The test server uses one fixed pending expiry; this call verifies the
	// parser contract without requiring a real approval delay.
	pending, err := client.ExchangeRegistration(t.Context(), "xreg_test123", registrationToken)
	if err != nil || pending.Pending == nil || pending.Pending.Status != "pending" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	approved, err := client.ExchangeRegistration(t.Context(), "xreg_test123", registrationToken)
	if err != nil || approved.Exchange == nil || approved.Exchange.Device.ID != "dev_laptop" {
		t.Fatalf("approved=%#v err=%v", approved, err)
	}
}

func TestExchangeRegistrationMapsConsumedAndExpiredWithoutLeakingToken(t *testing.T) {
	registrationToken := testOpaqueSecret("xrt_", 5)
	for _, test := range []struct {
		status int
		body   string
		want   string
	}{
		{status: http.StatusConflict, body: `{"code":"registration_consumed"}`, want: fault.CodeRegistrationConsumed},
		{status: http.StatusGone, body: `{"code":"registration_expired"}`, want: fault.CodeRegistrationExpired},
		{status: http.StatusUnauthorized, body: `{"code":"invalid_registration_token","token":"` + registrationToken + `"}`, want: fault.CodeRegistrationTokenInvalid},
	} {
		t.Run(test.want, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := controlplane.New(server.URL, "", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ExchangeRegistration(t.Context(), "xreg_test123", registrationToken)
			if fault.Code(err) != test.want || strings.Contains(err.Error(), registrationToken) {
				t.Fatalf("code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}
