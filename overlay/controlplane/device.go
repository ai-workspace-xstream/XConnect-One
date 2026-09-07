// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const maximumDeviceSessionLifetime = 15 * time.Minute

var (
	noncePattern              = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	deviceCredentialIDPattern = regexp.MustCompile(`^xdcid_[0-9a-f]{32}$`)
	deviceDigestPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type DeviceSessionRequest struct {
	ClientNonce string    `json:"client_nonce"`
	Now         time.Time `json:"-"`
}

type DeviceSessionResponse struct {
	ClientNonce     string                    `json:"client_nonce"`
	EnrollmentToken string                    `json:"enrollment_token"`
	TokenType       string                    `json:"token_type"`
	IssuedAt        time.Time                 `json:"issued_at"`
	ExpiresAt       time.Time                 `json:"expires_at"`
	Scope           []string                  `json:"scope"`
	DeviceID        string                    `json:"device_id"`
	NetworkID       string                    `json:"network_id"`
	SigningKeys     []signedconfig.SigningKey `json:"signing_keys"`
}

type DeviceCredentialRotateRequest struct {
	NewCredentialID     string `json:"new_credential_id"`
	NewCredentialSHA256 string `json:"new_credential_sha256"`
}

type DeviceCredentialRotateResponse struct {
	CredentialID         string    `json:"credential_id"`
	ReplacesCredentialID string    `json:"replaces_credential_id"`
	TokenType            string    `json:"token_type"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	Scope                []string  `json:"scope"`
}

type DeviceRevokeRequest struct {
	ClientNonce string `json:"client_nonce"`
}

type LifecycleDevice struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id"`
	NetworkID          string     `json:"network_id"`
	Name               string     `json:"name"`
	Platform           string     `json:"platform"`
	Hostname           string     `json:"hostname"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	WireGuardAddress   string     `json:"wireguard_address"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
	Status             string     `json:"status"`
	StateVersion       uint64     `json:"state_version"`
	KeyVersion         uint64     `json:"key_version"`
	RevokedAt          *time.Time `json:"revoked_at"`
	RevokedReason      string     `json:"revoked_reason"`
}

type DeviceRevokeResponse struct {
	Revoked                bool            `json:"revoked"`
	Duplicate              bool            `json:"duplicate"`
	Device                 LifecycleDevice `json:"device"`
	PolicyGeneration       uint64          `json:"policy_generation,omitempty"`
	PolicyDigest           string          `json:"policy_digest,omitempty"`
	PolicyReconcilePending bool            `json:"policy_reconcile_pending,omitempty"`
}

func (c *Client) MintDeviceSession(ctx context.Context, record credential.Record, request DeviceSessionRequest) (DeviceSessionResponse, error) {
	now := request.Now.UTC()
	if request.Now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateDeviceRequest(c, record, now); err != nil || !noncePattern.MatchString(request.ClientNonce) {
		return DeviceSessionResponse{}, fault.New(fault.CodeInvalidInput, "mint device session", nil)
	}
	_, headers, raw, err := c.doContractWithAuthorization(ctx, http.MethodPost, apiPrefixV1+"/device/session", nil, request, nil, credential.Authorization+" "+record.Credential, contractErrorDefault)
	if err != nil {
		return DeviceSessionResponse{}, mapDeviceAuthorizationError(err)
	}
	if !headerContainsToken(headers.Values("Cache-Control"), "no-store") {
		return DeviceSessionResponse{}, fault.New(fault.CodeInvalidResponse, "validate device session cache policy", nil)
	}
	response, decodeErr := strictContractDecode[DeviceSessionResponse](raw)
	keys := signedconfig.SigningKeys{Keys: response.SigningKeys}
	if decodeErr != nil || response.ClientNonce != request.ClientNonce || !validOpaqueSecret(response.EnrollmentToken, "xenr_") || response.TokenType != "Bearer" || !validDeviceSessionScope(response.Scope) || response.DeviceID != record.DeviceID || response.NetworkID != record.NetworkID || !canonicalSessionWindow(response.IssuedAt, response.ExpiresAt, now) || keys.Validate() != nil || !currentSigningKeyUsable(keys, now) || !signingKeyRingsOverlap(record.SigningKeys, keys, now) {
		return DeviceSessionResponse{}, fault.New(fault.CodeDeviceSessionInvalid, "validate device session", nil)
	}
	return response, nil
}

func signingKeyRingsOverlap(trusted, candidate signedconfig.SigningKeys, now time.Time) bool {
	for _, existing := range trusted.Keys {
		for _, next := range candidate.Keys {
			if existing.KeyID == next.KeyID && existing.PublicKey == next.PublicKey && signingKeyUsable(existing, now) && signingKeyUsable(next, now) {
				return true
			}
		}
	}
	return false
}

func currentSigningKeyUsable(keys signedconfig.SigningKeys, now time.Time) bool {
	for _, key := range keys.Keys {
		if key.Status == "current" {
			return signingKeyUsable(key, now)
		}
	}
	return false
}

func signingKeyUsable(key signedconfig.SigningKey, now time.Time) bool {
	now = now.UTC()
	return !key.NotBefore.Time.After(now.Add(30*time.Second)) && (key.NotAfter == nil || key.NotAfter.Time.After(now))
}

func (c *Client) RotateDeviceCredential(ctx context.Context, record credential.Record, request DeviceCredentialRotateRequest, now time.Time) (DeviceCredentialRotateResponse, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateDeviceRequest(c, record, now); err != nil || !deviceCredentialIDPattern.MatchString(request.NewCredentialID) || !deviceDigestPattern.MatchString(request.NewCredentialSHA256) || request.NewCredentialID == record.CredentialID {
		return DeviceCredentialRotateResponse{}, fault.New(fault.CodeInvalidInput, "rotate device credential", nil)
	}
	headers := canonicalIdempotencyHeaders(request)
	_, responseHeaders, raw, err := c.doContractWithAuthorization(ctx, http.MethodPost, apiPrefixV1+"/device/credential/rotate", nil, request, headers, credential.Authorization+" "+record.Credential, contractErrorDefault)
	if err != nil {
		return DeviceCredentialRotateResponse{}, mapDeviceAuthorizationError(err)
	}
	if !headerContainsToken(responseHeaders.Values("Cache-Control"), "no-store") {
		return DeviceCredentialRotateResponse{}, fault.New(fault.CodeInvalidResponse, "validate credential rotation cache policy", nil)
	}
	response, decodeErr := strictContractDecode[DeviceCredentialRotateResponse](raw)
	if decodeErr != nil || response.CredentialID != request.NewCredentialID || response.ReplacesCredentialID != record.CredentialID || response.TokenType != credential.TokenType || !validDeviceCredentialScope(response.Scope) || !canonicalCredentialWindow(response.IssuedAt, response.ExpiresAt, now.UTC()) {
		return DeviceCredentialRotateResponse{}, fault.New(fault.CodeInvalidResponse, "validate credential rotation", nil)
	}
	return response, nil
}

func (c *Client) RevokeDevice(ctx context.Context, record credential.Record, request DeviceRevokeRequest, now time.Time) (DeviceRevokeResponse, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateDeviceRequest(c, record, now); err != nil || !noncePattern.MatchString(request.ClientNonce) {
		return DeviceRevokeResponse{}, fault.New(fault.CodeInvalidInput, "revoke bound device", nil)
	}
	headers := canonicalIdempotencyHeaders(request)
	_, responseHeaders, raw, err := c.doContractWithAuthorization(ctx, http.MethodPost, apiPrefixV1+"/device/revoke", nil, request, headers, credential.Authorization+" "+record.Credential, contractErrorDefault)
	if err != nil {
		return DeviceRevokeResponse{}, mapDeviceAuthorizationError(err)
	}
	if !headerContainsToken(responseHeaders.Values("Cache-Control"), "no-store") {
		return DeviceRevokeResponse{}, fault.New(fault.CodeInvalidResponse, "validate device revoke cache policy", nil)
	}
	response, decodeErr := strictContractDecode[DeviceRevokeResponse](raw)
	if decodeErr != nil || !validDeviceRevokeResponse(response, record) {
		return DeviceRevokeResponse{}, fault.New(fault.CodeInvalidResponse, "validate device revoke receipt", nil)
	}
	return response, nil
}

func validateDeviceRequest(c *Client, record credential.Record, now time.Time) error {
	if c.baseURL.Scheme != "https" || strings.TrimRight(c.baseURL.String(), "/") != strings.TrimRight(record.Controller, "/") || record.Expired(now.UTC()) {
		return fault.New(fault.CodeCredentialExpired, "validate device authorization", nil)
	}
	return record.Validate()
}

func validDeviceSessionScope(values []string) bool {
	return len(values) == 2 && (values[0] == "overlay:config:read" && values[1] == "overlay:config:ack" || values[0] == "overlay:config:ack" && values[1] == "overlay:config:read")
}

func canonicalSessionWindow(issuedAt, expiresAt, now time.Time) bool {
	return issuedAt.Location() == time.UTC && issuedAt.Nanosecond() == 0 && expiresAt.Location() == time.UTC && expiresAt.Nanosecond() == 0 && !issuedAt.After(now.Add(30*time.Second)) && expiresAt.After(now) && expiresAt.After(issuedAt) && expiresAt.Sub(issuedAt) <= maximumDeviceSessionLifetime
}

func canonicalIdempotencyHeaders(payload any) http.Header {
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	headers := http.Header{}
	headers.Set("Idempotency-Key", "sha256-"+hex.EncodeToString(sum[:]))
	return headers
}

func validDeviceRevokeResponse(response DeviceRevokeResponse, record credential.Record) bool {
	if !response.Revoked || response.Device.ID != record.DeviceID || response.Device.NetworkID != record.NetworkID || response.Device.Status != "revoked" || response.Device.StateVersion == 0 || response.Device.KeyVersion == 0 || response.Device.RevokedAt == nil || response.Device.RevokedAt.IsZero() || response.Device.RevokedReason == "" {
		return false
	}
	if response.PolicyReconcilePending {
		return response.PolicyGeneration == 0 && response.PolicyDigest == ""
	}
	return response.PolicyGeneration > 0 && deviceDigestPattern.MatchString(response.PolicyDigest)
}

func mapDeviceAuthorizationError(err error) error {
	if fault.Code(err) == fault.CodeAuthenticationFailed || fault.Code(err) == fault.CodeAccessDenied {
		return fault.New(fault.CodeCredentialInvalid, "authorize device request", nil)
	}
	return err
}
