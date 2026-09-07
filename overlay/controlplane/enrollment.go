// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const maximumEnrollmentLifetime = time.Hour + time.Minute

var enrollmentDeviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type JoinTokenExchangeRequest struct {
	JoinToken          string    `json:"join_token"`
	DeviceID           string    `json:"device_id"`
	Name               string    `json:"name,omitempty"`
	Platform           string    `json:"platform"`
	Hostname           string    `json:"hostname,omitempty"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	Now                time.Time `json:"-"`
}

type JoinTokenExchangeResponse struct {
	EnrollmentToken  string                    `json:"enrollment_token"`
	TokenType        string                    `json:"token_type"`
	ExpiresAt        time.Time                 `json:"expires_at"`
	Scope            []string                  `json:"scope"`
	DeviceCredential DeviceCredential          `json:"device_credential"`
	Device           model.Device              `json:"device"`
	Network          model.Network             `json:"network"`
	SigningKeys      []signedconfig.SigningKey `json:"signing_keys"`
}

type DeviceCredential struct {
	CredentialID string    `json:"credential_id"`
	Credential   string    `json:"credential"`
	TokenType    string    `json:"token_type"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        []string  `json:"scope"`
}

func (c *Client) ExchangeJoinToken(ctx context.Context, request JoinTokenExchangeRequest) (JoinTokenExchangeResponse, error) {
	if c.baseURL.Scheme != "https" || !validOpaqueSecret(request.JoinToken, "xjt_") || !enrollmentDeviceIDPattern.MatchString(request.DeviceID) || !validEnrollmentPlatform(request.Platform) || !validWireGuardPublicKey(request.WireGuardPublicKey) || len(request.Name) > 255 || len(request.Hostname) > 255 {
		return JoinTokenExchangeResponse{}, fault.New(fault.CodeInvalidInput, "exchange join invite", nil)
	}
	now := request.Now.UTC()
	if request.Now.IsZero() {
		now = time.Now().UTC()
	}
	_, headers, raw, err := c.doContractWithBearer(ctx, http.MethodPost, apiPrefixV1+"/join-tokens/exchange", nil, request, nil, "", contractErrorInviteExchange)
	if err != nil {
		return JoinTokenExchangeResponse{}, err
	}
	if headers.Get("Cache-Control") != "no-store" {
		return JoinTokenExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate join exchange cache policy", nil)
	}
	response, err := strictContractDecode[JoinTokenExchangeResponse](raw)
	if err != nil {
		return JoinTokenExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "decode join exchange", nil)
	}
	keys := signedconfig.SigningKeys{Keys: response.SigningKeys}
	deviceSecret, deviceSecretErr := credential.Parse(response.DeviceCredential.Credential)
	if !validOpaqueSecret(response.EnrollmentToken, "xenr_") || response.TokenType != "Bearer" || !validEnrollmentScope(response.Scope) || response.ExpiresAt.Location() != time.UTC || !response.ExpiresAt.After(now) || response.ExpiresAt.Sub(now) > maximumEnrollmentLifetime || deviceSecretErr != nil || deviceSecret.CredentialID != response.DeviceCredential.CredentialID || response.DeviceCredential.TokenType != credential.TokenType || !validDeviceCredentialScope(response.DeviceCredential.Scope) || !canonicalCredentialWindow(response.DeviceCredential.IssuedAt, response.DeviceCredential.ExpiresAt, now) || response.Device.ID != request.DeviceID || response.Device.Platform != request.Platform || response.Device.WireGuardPublicKey != request.WireGuardPublicKey || response.Device.NetworkID == "" || response.Network.ID != response.Device.NetworkID || !validIPv4HostPrefix(response.Device.WireGuardAddress) || !validIPv4Prefix(response.Network.CIDR) {
		return JoinTokenExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate join exchange", nil)
	}
	if err := keys.Validate(); err != nil {
		return JoinTokenExchangeResponse{}, err
	}
	return response, nil
}

func validDeviceCredentialScope(values []string) bool {
	if len(values) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != credential.ScopeSessionMint && value != credential.ScopeRotate && value != credential.ScopeDeviceRevoke || seen[value] {
			return false
		}
		seen[value] = true
	}
	return seen[credential.ScopeSessionMint] && seen[credential.ScopeRotate] && seen[credential.ScopeDeviceRevoke]
}

func canonicalCredentialWindow(issuedAt, expiresAt, now time.Time) bool {
	return issuedAt.Location() == time.UTC && issuedAt.Nanosecond() == 0 && expiresAt.Location() == time.UTC && expiresAt.Nanosecond() == 0 && !issuedAt.After(now.Add(30*time.Second)) && expiresAt.After(now) && expiresAt.After(issuedAt) && expiresAt.Sub(issuedAt) <= 31*24*time.Hour
}

func (c *Client) GetEnrollmentSignedConfig(ctx context.Context, enrollmentToken string, request SignedConfigRequest) (signedconfig.Config, error) {
	return c.getEnrollmentSignedConfig(ctx, enrollmentToken, request, false)
}

// GetEnrollmentSignedConfigV2 uses an explicit media type to request the
// signed policy reference. It must never downgrade to v1.
func (c *Client) GetEnrollmentSignedConfigV2(ctx context.Context, enrollmentToken string, request SignedConfigRequest) (signedconfig.Config, error) {
	return c.getEnrollmentSignedConfig(ctx, enrollmentToken, request, true)
}

func (c *Client) getEnrollmentSignedConfig(ctx context.Context, enrollmentToken string, request SignedConfigRequest, v2 bool) (signedconfig.Config, error) {
	if !validOpaqueSecret(enrollmentToken, "xenr_") {
		return signedconfig.Config{}, fault.New(fault.CodeEnrollmentUnavailable, "load enrollment session", nil)
	}
	query := url.Values{}
	query.Set("device_id", request.DeviceID)
	if request.NetworkID != "" {
		query.Set("network_id", request.NetworkID)
	}
	if request.NodeID != "" {
		query.Set("node_id", request.NodeID)
	}
	headers := http.Header(nil)
	if v2 {
		headers = http.Header{"Accept": []string{SignedConfigV2MediaType}}
	}
	_, responseHeaders, raw, err := c.doContractWithBearer(ctx, http.MethodGet, apiPrefixV1+"/enrollment/signed-config", query, nil, headers, enrollmentToken, contractErrorEnrollment)
	if err != nil {
		return signedconfig.Config{}, err
	}
	if responseHeaders.Get("Cache-Control") != "private, no-store" || strings.TrimSpace(responseHeaders.Get("ETag")) == "" || v2 && !headerContainsToken(responseHeaders.Values("Vary"), "Accept") {
		return signedconfig.Config{}, fault.New(fault.CodeInvalidResponse, "validate enrollment signed-config cache headers", nil)
	}
	if v2 {
		mediaType, _, mediaErr := mime.ParseMediaType(responseHeaders.Get("Content-Type"))
		if mediaErr != nil || mediaType != SignedConfigV2MediaType {
			return signedconfig.Config{}, fault.New(fault.CodeInvalidResponse, "validate enrollment signed-config v2 media type", nil)
		}
	}
	config, err := signedconfig.DecodeConfig(raw)
	if err != nil {
		return signedconfig.Config{}, err
	}
	if v2 != (config.SchemaVersion == signedconfig.SchemaVersionV2) {
		return signedconfig.Config{}, fault.New(fault.CodeInvalidSignedConfig, "validate enrollment signed-config negotiated version", nil)
	}
	config.ETag = responseHeaders.Get("ETag")
	return config, nil
}

// GetEnrollmentPolicyArtifact obtains the only policy artifact a v2 config
// can name. The path is reconstructed from signed values before a request is
// made, so an absolute URL, userinfo, different authority, or redirect cannot
// receive the enrollment bearer.
func (c *Client) GetEnrollmentPolicyArtifact(ctx context.Context, enrollmentToken string, reference signedconfig.Policy) ([]byte, error) {
	if !validOpaqueSecret(enrollmentToken, "xenr_") || reference.Validate() != nil {
		return nil, fault.New(fault.CodeEnrollmentUnavailable, "load enrollment policy", nil)
	}
	if c.baseURL.Scheme != "https" {
		return nil, fault.New(fault.CodeInvalidInput, "create enrollment policy request", nil)
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + signedconfig.PolicyPath(reference.Generation, reference.Digest)
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fault.New(fault.CodeInvalidInput, "create enrollment policy request", err)
	}
	request.Header.Set("Accept", signedconfig.PolicyMediaType)
	request.Header.Set("Authorization", "Bearer "+enrollmentToken)
	clientCopy := *c.httpClient
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }
	response, err := clientCopy.Do(request)
	if err != nil {
		return nil, fault.New(fault.CodeControlPlaneUnavailable, "request enrollment policy", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, statusError(response.StatusCode)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != signedconfig.PolicyMediaType || response.Header.Get("Cache-Control") != "private, no-store" {
		return nil, fault.New(fault.CodeInvalidResponse, "validate enrollment policy response", nil)
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if readErr != nil || len(raw) == 0 || len(raw) > 4<<20 {
		return nil, fault.New(fault.CodeInvalidResponse, "read enrollment policy", readErr)
	}
	return raw, nil
}

func (c *Client) AckEnrollmentSignedConfig(ctx context.Context, enrollmentToken string, request SignedConfigAckRequest) (SignedConfigAckResponse, error) {
	if !validOpaqueSecret(enrollmentToken, "xenr_") || request.Generation == 0 || strings.TrimSpace(request.ConfigID) == "" || strings.TrimSpace(request.DeviceID) == "" || request.AppliedAt.IsZero() {
		return SignedConfigAckResponse{}, fault.New(fault.CodeInvalidInput, "ack enrollment signed config", nil)
	}
	payload := struct {
		ConfigID  string `json:"config_id"`
		DeviceID  string `json:"device_id"`
		AppliedAt string `json:"applied_at"`
	}{ConfigID: request.ConfigID, DeviceID: request.DeviceID, AppliedAt: request.AppliedAt.UTC().Truncate(time.Second).Format(time.RFC3339)}
	_, _, raw, err := c.doContractWithBearer(ctx, http.MethodPost, apiPrefixV1+"/enrollment/signed-config/"+strconv.FormatUint(request.Generation, 10)+"/ack", nil, payload, nil, enrollmentToken, contractErrorEnrollment)
	if err != nil {
		return SignedConfigAckResponse{}, err
	}
	response, err := strictContractDecode[SignedConfigAckResponse](raw)
	if err != nil || !response.Acked || response.Ack.Generation == 0 || strings.TrimSpace(response.Ack.ConfigID) == "" || strings.TrimSpace(response.Ack.DeviceID) == "" || response.Ack.AppliedAt.IsZero() || response.Ack.ReceivedAt.IsZero() {
		return SignedConfigAckResponse{}, fault.New(fault.CodeInvalidResponse, "decode enrollment signed-config acknowledgement", nil)
	}
	return response, nil
}

func validOpaqueSecret(value, prefix string) bool {
	if value != strings.TrimSpace(value) || !strings.HasPrefix(value, prefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(raw) == 32
}

func validWireGuardPublicKey(value string) bool {
	if value != strings.TrimSpace(value) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32
}

func validEnrollmentScope(values []string) bool {
	if len(values) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "overlay:config:read" && value != "overlay:config:ack" && value != "overlay:device:revoke" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return seen["overlay:config:read"] && seen["overlay:config:ack"] && seen["overlay:device:revoke"]
}

func validIPv4Prefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4()
}

func validIPv4HostPrefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4() && prefix.Bits() == 32
}

func validEnrollmentPlatform(value string) bool {
	switch value {
	case "darwin", "windows", "linux", "ios", "android":
		return true
	default:
		return false
	}
}
