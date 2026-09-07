package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
)

// The app bridge is intentionally a separate, opt-in command. Existing CLI
// commands and their flags remain the supported standalone interface.
const (
	appBridgeCommand         = "app-bridge"
	appBridgeProtocolVersion = "1"
	appBridgeMaxLineBytes    = 64 << 10

	bridgeCodeInvalidRequest     = "bridge_invalid_request"
	bridgeCodeUnsupportedVersion = "bridge_unsupported_version"
	bridgeCodeUnsupportedMethod  = "bridge_unsupported_method"
	bridgeCodeInvalidParams      = "bridge_invalid_params"
	bridgeCodeInvalidResult      = "bridge_invalid_result"
)

var appBridgeMethods = []string{"negotiate", "join", "sync", "status", "leave", "diagnose"}

type appBridgeRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
}

type appBridgeResponse struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id,omitempty"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *appBridgeError `json:"error,omitempty"`
}

// appBridgeError deliberately contains no message, wrapped error, command
// arguments, request payload, path, or secret. The code is the complete
// cross-process error contract.
type appBridgeError struct {
	Code string `json:"code"`
}

type appBridgeRunner func(context.Context, []string, io.Writer, io.Writer, *http.Client) error

func init() {
	if len(os.Args) < 2 || os.Args[1] != appBridgeCommand {
		return
	}
	os.Exit(serveAppBridge(context.Background(), os.Stdin, os.Stdout, run))
}

// serveAppBridge implements a line-delimited JSON protocol for a host-owned
// plugin adapter. It is not a network listener: the host must provide a local,
// permission-restricted stdin/stdout channel or equivalent socket adapter.
func serveAppBridge(ctx context.Context, input io.Reader, output io.Writer, runner appBridgeRunner) int {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 4096), appBridgeMaxLineBytes)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		response := handleAppBridgeRequest(ctx, scanner.Bytes(), runner)
		if err := encoder.Encode(response); err != nil {
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		_ = encoder.Encode(appBridgeResponse{
			ProtocolVersion: appBridgeProtocolVersion,
			Error:           &appBridgeError{Code: bridgeCodeInvalidRequest},
		})
		return 1
	}
	return 0
}

func handleAppBridgeRequest(ctx context.Context, raw []byte, runner appBridgeRunner) appBridgeResponse {
	request, err := decodeAppBridgeRequest(raw)
	if err != nil {
		return appBridgeFailure("", bridgeCodeInvalidRequest)
	}
	if request.ProtocolVersion != appBridgeProtocolVersion {
		return appBridgeFailure(request.RequestID, bridgeCodeUnsupportedVersion)
	}
	if request.RequestID == "" || len(request.RequestID) > 128 || strings.ContainsAny(request.RequestID, "\r\n\x00") {
		return appBridgeFailure("", bridgeCodeInvalidRequest)
	}
	if request.Method == "negotiate" {
		var params appBridgeNegotiateParams
		if err := decodeBridgeParams(request.Params, &params); err != nil || !appBridgeSupportsVersion(params.ProtocolVersions) {
			return appBridgeFailure(request.RequestID, bridgeCodeInvalidParams)
		}
		return appBridgeSuccess(request.RequestID, appBridgeCapabilities())
	}
	args, err := appBridgeArgs(request.Method, request.Params)
	if err != nil {
		return appBridgeFailure(request.RequestID, err.Error())
	}
	var commandOutput bytes.Buffer
	// CLI diagnostics are intentionally discarded. They may contain contextual
	// paths or controller responses and are not part of this bridge contract.
	if err := runner(ctx, args, &commandOutput, io.Discard, http.DefaultClient); err != nil {
		return appBridgeFailure(request.RequestID, fault.Code(err))
	}
	result, err := decodeAppBridgeResult(commandOutput.Bytes())
	if err != nil {
		return appBridgeFailure(request.RequestID, bridgeCodeInvalidResult)
	}
	return appBridgeResponse{ProtocolVersion: appBridgeProtocolVersion, RequestID: request.RequestID, Result: result}
}

func decodeAppBridgeRequest(raw []byte) (appBridgeRequest, error) {
	var request appBridgeRequest
	if err := decodeBridgeParams(raw, &request); err != nil {
		return appBridgeRequest{}, err
	}
	if len(request.Params) == 0 || !json.Valid(request.Params) {
		return appBridgeRequest{}, fmt.Errorf("params")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(request.Params, &object); err != nil || object == nil {
		return appBridgeRequest{}, fmt.Errorf("params object")
	}
	return request, nil
}

func decodeBridgeParams(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

type appBridgeNegotiateParams struct {
	ProtocolVersions []string `json:"protocol_versions,omitempty"`
}

type appBridgeStateParams struct {
	StateDir string `json:"state_dir"`
}

type appBridgeJoinParams struct {
	StateDir  string `json:"state_dir"`
	Invite    string `json:"invite"`
	DeviceID  string `json:"device_id,omitempty"`
	Name      string `json:"name,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
}

type appBridgeSyncParams struct {
	StateDir       string `json:"state_dir"`
	SignedConfigV2 bool   `json:"signed_config_v2,omitempty"`
}

type appBridgeLeaveParams struct {
	StateDir  string `json:"state_dir"`
	LocalOnly bool   `json:"local_only,omitempty"`
}

func appBridgeArgs(method string, rawParams json.RawMessage) ([]string, error) {
	switch method {
	case "join":
		var params appBridgeJoinParams
		if err := decodeBridgeParams(rawParams, &params); err != nil || !validBridgeStateDir(params.StateDir) || !validBridgeRequiredText(params.Invite) ||
			!validBridgeOptionalText(params.DeviceID) || !validBridgeOptionalText(params.Name) || !validBridgeOptionalText(params.NetworkID) || !validBridgeOptionalText(params.NodeID) {
			return nil, fmt.Errorf(bridgeCodeInvalidParams)
		}
		if _, err := invite.Parse(params.Invite, false); err != nil {
			return nil, fmt.Errorf(bridgeCodeInvalidParams)
		}
		args := []string{"join", "--state-dir", params.StateDir}
		if params.DeviceID != "" {
			args = append(args, "--device-id", params.DeviceID)
		}
		if params.Name != "" {
			args = append(args, "--name", params.Name)
		}
		if params.NetworkID != "" {
			args = append(args, "--network-id", params.NetworkID)
		}
		if params.NodeID != "" {
			args = append(args, "--node-id", params.NodeID)
		}
		return append(args, params.Invite), nil
	case "sync":
		var params appBridgeSyncParams
		if err := decodeBridgeParams(rawParams, &params); err != nil || !validBridgeStateDir(params.StateDir) {
			return nil, fmt.Errorf(bridgeCodeInvalidParams)
		}
		args := []string{"sync", "--state-dir", params.StateDir}
		if params.SignedConfigV2 {
			args = append(args, "--signed-config-v2")
		}
		return args, nil
	case "status", "diagnose":
		var params appBridgeStateParams
		if err := decodeBridgeParams(rawParams, &params); err != nil || !validBridgeStateDir(params.StateDir) {
			return nil, fmt.Errorf(bridgeCodeInvalidParams)
		}
		return []string{method, "--state-dir", params.StateDir}, nil
	case "leave":
		var params appBridgeLeaveParams
		if err := decodeBridgeParams(rawParams, &params); err != nil || !validBridgeStateDir(params.StateDir) {
			return nil, fmt.Errorf(bridgeCodeInvalidParams)
		}
		args := []string{"leave", "--state-dir", params.StateDir}
		if params.LocalOnly {
			args = append(args, "--local-only")
		}
		return args, nil
	default:
		return nil, fmt.Errorf(bridgeCodeUnsupportedMethod)
	}
}

func validBridgeStateDir(value string) bool {
	return validBridgeRequiredText(value) && filepath.IsAbs(value)
}

func validBridgeRequiredText(value string) bool {
	return validBridgeOptionalText(value) && strings.TrimSpace(value) != ""
}

func validBridgeOptionalText(value string) bool {
	return len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00")
}

func decodeAppBridgeResult(raw []byte) (json.RawMessage, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || !json.Valid(value) {
		return nil, fmt.Errorf("result")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return nil, fmt.Errorf("result object")
	}
	return append(json.RawMessage(nil), value...), nil
}

func appBridgeFailure(requestID, code string) appBridgeResponse {
	if !validBridgeErrorCode(code) {
		code = fault.CodeInvalidResponse
	}
	return appBridgeResponse{ProtocolVersion: appBridgeProtocolVersion, RequestID: requestID, Error: &appBridgeError{Code: code}}
}

func appBridgeSuccess(requestID string, result any) appBridgeResponse {
	raw, err := json.Marshal(result)
	if err != nil {
		return appBridgeFailure(requestID, bridgeCodeInvalidResult)
	}
	return appBridgeResponse{ProtocolVersion: appBridgeProtocolVersion, RequestID: requestID, Result: raw}
}

func appBridgeCapabilities() map[string]any {
	return map[string]any{
		"protocol_versions":      []string{appBridgeProtocolVersion},
		"methods":                appBridgeMethods,
		"transport":              "stdio-jsonl",
		"state_dir_required":     true,
		"sensitive_input_fields": []string{"join.invite"},
		"secret_output_fields":   []string{},
	}
}

func appBridgeSupportsVersion(versions []string) bool {
	for _, version := range versions {
		if version == appBridgeProtocolVersion {
			return true
		}
	}
	return false
}

func validBridgeErrorCode(value string) bool {
	if value == "" || len(value) > 80 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}
