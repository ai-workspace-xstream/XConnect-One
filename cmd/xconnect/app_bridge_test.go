package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestAppBridgeNegotiationAndSchema(t *testing.T) {
	rawSchema, err := os.ReadFile(filepath.Join("..", "..", "docs", "integrations", "xconnect-app-bridge-v1.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["title"] != "XConnect One App Bridge v1" {
		t.Fatalf("unexpected schema identity: %#v", schema)
	}

	response := handleAppBridgeRequest(t.Context(), []byte(`{"protocol_version":"1","request_id":"cap-1","method":"negotiate","params":{"protocol_versions":["1"]}}`), nil)
	if response.Error != nil {
		t.Fatalf("negotiate error: %#v", response.Error)
	}
	var result map[string]any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("parse negotiation result: %v", err)
	}
	if result["transport"] != "stdio-jsonl" || result["state_dir_required"] != true || !reflect.DeepEqual(result["sensitive_input_fields"], []any{"join.invite"}) {
		t.Fatalf("unexpected negotiation result: %#v", result)
	}
}

func TestAppBridgeRejectsUnknownFieldsAndUnsupportedVersions(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code string
	}{
		{"top level field", `{"protocol_version":"1","request_id":"x","method":"status","params":{"state_dir":"/private/xconnect"},"secret":"no"}`, bridgeCodeInvalidRequest},
		{"parameter field", `{"protocol_version":"1","request_id":"x","method":"status","params":{"state_dir":"/private/xconnect","token":"no"}}`, bridgeCodeInvalidParams},
		{"relative state", `{"protocol_version":"1","request_id":"x","method":"status","params":{"state_dir":"relative"}}`, bridgeCodeInvalidParams},
		{"old version", `{"protocol_version":"0","request_id":"x","method":"status","params":{"state_dir":"/private/xconnect"}}`, bridgeCodeUnsupportedVersion},
		{"no compatible version", `{"protocol_version":"1","request_id":"x","method":"negotiate","params":{"protocol_versions":["2"]}}`, bridgeCodeInvalidParams},
		{"unknown method", `{"protocol_version":"1","request_id":"x","method":"down","params":{"state_dir":"/private/xconnect"}}`, bridgeCodeUnsupportedMethod},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := handleAppBridgeRequest(t.Context(), []byte(test.raw), nil)
			if response.Error == nil || response.Error.Code != test.code {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestAppBridgeMapsSupportedOperationsToExistingCLI(t *testing.T) {
	var gotArgs []string
	runner := func(_ context.Context, args []string, stdout, _ io.Writer, _ *http.Client) error {
		gotArgs = append([]string(nil), args...)
		_, _ = io.WriteString(stdout, `{"joined":true}`)
		return nil
	}
	stateDir := filepath.Join(t.TempDir(), "one")
	request, err := json.Marshal(map[string]any{
		"protocol_version": "1",
		"request_id":       "sync-1",
		"method":           "sync",
		"params": map[string]any{
			"state_dir":        stateDir,
			"signed_config_v2": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := handleAppBridgeRequest(t.Context(), request, runner)
	if response.Error != nil {
		t.Fatalf("sync error: %#v", response.Error)
	}
	want := []string{"sync", "--state-dir", stateDir, "--signed-config-v2"}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("args = %#v, want %#v", gotArgs, want)
	}
	if string(response.Result) != `{"joined":true}` {
		t.Fatalf("result = %s", response.Result)
	}
}

func TestAppBridgeRedactsRunnerErrorsAndRequestSecrets(t *testing.T) {
	secret := bridgeTestInvite()
	runner := func(_ context.Context, _ []string, _ io.Writer, _ io.Writer, _ *http.Client) error {
		return fault.New(fault.CodeControlPlaneRejected, "exchange "+secret, errors.New("authorization: bearer private-token"))
	}
	request, err := json.Marshal(map[string]any{
		"protocol_version": "1",
		"request_id":       "join-1",
		"method":           "join",
		"params": map[string]any{
			"state_dir": filepath.Join(t.TempDir(), "one"),
			"invite":    secret,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := handleAppBridgeRequest(t.Context(), request, runner)
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if response.Error == nil || response.Error.Code != fault.CodeControlPlaneRejected {
		t.Fatalf("response = %#v", response)
	}
	for _, forbidden := range []string{secret, "private-token", "exchange"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("bridge response leaked %q: %s", forbidden, raw)
		}
	}
}

func TestAppBridgeJoinRequiresSignedInvite(t *testing.T) {
	response := handleAppBridgeRequest(t.Context(), []byte(`{"protocol_version":"1","request_id":"join-1","method":"join","params":{"state_dir":"/var/lib/xconnect-app/one","invite":"https://controller.example"}}`), nil)
	if response.Error == nil || response.Error.Code != bridgeCodeInvalidParams {
		t.Fatalf("response = %#v", response)
	}
}

func TestAppBridgeRejectsNonOpaqueRunnerCode(t *testing.T) {
	secret := "do-not-return-this-secret"
	runner := func(_ context.Context, _ []string, _ io.Writer, _ io.Writer, _ *http.Client) error {
		return appBridgeTestCodedError{code: "failure-" + secret}
	}
	request, err := json.Marshal(map[string]any{
		"protocol_version": "1",
		"request_id":       "status-1",
		"method":           "status",
		"params": map[string]any{
			"state_dir": filepath.Join(t.TempDir(), "one"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := handleAppBridgeRequest(t.Context(), request, runner)
	if response.Error == nil || response.Error.Code != fault.CodeInvalidResponse {
		t.Fatalf("response = %#v", response)
	}
	if raw, _ := json.Marshal(response); strings.Contains(string(raw), secret) {
		t.Fatalf("bridge response leaked runner code: %s", raw)
	}
}

type appBridgeTestCodedError struct{ code string }

func (e appBridgeTestCodedError) Error() string { return e.code }
func (e appBridgeTestCodedError) Code() string  { return e.code }

func bridgeTestInvite() string {
	token := "xjt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	return "xconnect://join/" + token + "?controller=https%3A%2F%2Fcontroller.example"
}

func TestServeAppBridgeUsesOneResponsePerJSONLine(t *testing.T) {
	var output bytes.Buffer
	code := serveAppBridge(t.Context(), strings.NewReader("{\"protocol_version\":\"1\",\"request_id\":\"a\",\"method\":\"negotiate\",\"params\":{}}\nnot-json\n"), &output, nil)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("response lines = %q", output.String())
	}
	for _, line := range lines {
		var response appBridgeResponse
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("response is not JSON: %v", err)
		}
	}
}
