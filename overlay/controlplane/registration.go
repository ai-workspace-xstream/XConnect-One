// Modified for XConnect-One: standalone module imports.
package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const RegistrationPollInterval = 5 * time.Second
const RegistrationMaximumLifetime = 15 * time.Minute

var registrationIDPattern = regexp.MustCompile(`^xreg_[A-Za-z0-9_-]{1,123}$`)

type RegistrationCreateRequest struct {
	NetworkID          string `json:"network_id"`
	DeviceID           string `json:"device_id"`
	Name               string `json:"name,omitempty"`
	Hostname           string `json:"hostname,omitempty"`
	Platform           string `json:"platform"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

type RegistrationCreateResponse struct {
	RegistrationID    string    `json:"registration_id"`
	RegistrationToken string    `json:"registration_token"`
	Status            string    `json:"status"`
	ExpiresAt         time.Time `json:"expires_at"`
	Interval          int       `json:"interval"`
}

type RegistrationPendingResponse struct {
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Interval  int       `json:"interval"`
}

type RegistrationExchangeResponse struct {
	Pending  *RegistrationPendingResponse
	Exchange *JoinTokenExchangeResponse
}

func (c *Client) CreateRegistration(ctx context.Context, request RegistrationCreateRequest) (RegistrationCreateResponse, error) {
	if c.baseURL.Scheme != "https" || c.token != "" || !validRegistrationRequest(request) {
		return RegistrationCreateResponse{}, fault.New(fault.CodeInvalidInput, "create registration", nil)
	}
	status, headers, raw, err := c.doContractWithBearer(ctx, http.MethodPost, apiPrefixV1+"/registrations", nil, request, nil, "", contractErrorRegistrationCreate)
	if err != nil {
		return RegistrationCreateResponse{}, err
	}
	if status != http.StatusCreated || headers.Get("Cache-Control") != "no-store" {
		return RegistrationCreateResponse{}, fault.New(fault.CodeInvalidResponse, "validate registration response", nil)
	}
	response, decodeErr := strictContractDecode[RegistrationCreateResponse](raw)
	now := time.Now().UTC()
	if decodeErr != nil || !registrationIDPattern.MatchString(response.RegistrationID) || !validOpaqueSecret(response.RegistrationToken, "xrt_") || response.Status != "pending" || response.ExpiresAt.Location() != time.UTC || !response.ExpiresAt.After(now) || response.ExpiresAt.Sub(now) > RegistrationMaximumLifetime || response.Interval != int(RegistrationPollInterval/time.Second) {
		return RegistrationCreateResponse{}, fault.New(fault.CodeInvalidResponse, "validate registration response", nil)
	}
	return response, nil
}

func (c *Client) ExchangeRegistration(ctx context.Context, registrationID, registrationToken string) (RegistrationExchangeResponse, error) {
	if c.baseURL.Scheme != "https" || !registrationIDPattern.MatchString(registrationID) || !validOpaqueSecret(registrationToken, "xrt_") {
		return RegistrationExchangeResponse{}, fault.New(fault.CodeInvalidInput, "exchange registration", nil)
	}
	status, headers, raw, err := c.doContractWithBearer(ctx, http.MethodPost, apiPrefixV1+"/registrations/"+registrationID+"/exchange", nil, nil, nil, registrationToken, contractErrorRegistration)
	if err != nil {
		return RegistrationExchangeResponse{}, err
	}
	if headers.Get("Cache-Control") != "no-store" {
		return RegistrationExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate registration exchange cache policy", nil)
	}
	now := time.Now().UTC()
	switch status {
	case http.StatusAccepted:
		pending, decodeErr := strictContractDecode[RegistrationPendingResponse](raw)
		if decodeErr != nil || pending.Status != "pending" || pending.ExpiresAt.Location() != time.UTC || !pending.ExpiresAt.After(now) || pending.ExpiresAt.Sub(now) > RegistrationMaximumLifetime || pending.Interval != int(RegistrationPollInterval/time.Second) {
			return RegistrationExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate pending registration", nil)
		}
		return RegistrationExchangeResponse{Pending: &pending}, nil
	case http.StatusOK:
		exchange, decodeErr := strictContractDecode[JoinTokenExchangeResponse](raw)
		if decodeErr != nil || !validateEnrollmentExchangeResponse(exchange, now) {
			return RegistrationExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate approved registration", nil)
		}
		return RegistrationExchangeResponse{Exchange: &exchange}, nil
	default:
		return RegistrationExchangeResponse{}, fault.New(fault.CodeInvalidResponse, "validate registration exchange status", nil)
	}
}

func validRegistrationRequest(request RegistrationCreateRequest) bool {
	return enrollmentDeviceIDPattern.MatchString(request.DeviceID) && enrollmentDeviceIDPattern.MatchString(request.NetworkID) && validDesktopRegistrationPlatform(request.Platform) && validWireGuardPublicKey(request.WireGuardPublicKey) && validRegistrationText(request.Name) && validRegistrationText(request.Hostname)
}

func validDesktopRegistrationPlatform(value string) bool {
	switch value {
	case "linux", "darwin", "windows":
		return true
	default:
		return false
	}
}

func validRegistrationText(value string) bool {
	if len(value) > 255 {
		return false
	}
	return !strings.ContainsAny(value, "\r\n\x00")
}

func registrationError(status int, raw []byte, creating bool) error {
	switch status {
	case http.StatusUnauthorized:
		return fault.New(fault.CodeRegistrationTokenInvalid, "exchange registration", nil)
	case http.StatusConflict:
		var body struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &body)
		if body.Code == fault.CodeRegistrationConsumed || body.Error == fault.CodeRegistrationConsumed {
			return fault.New(fault.CodeRegistrationConsumed, "exchange registration", nil)
		}
		return fault.New(fault.CodeRegistrationRejected, "exchange registration", nil)
	case http.StatusGone:
		return fault.New(fault.CodeRegistrationExpired, "exchange registration", nil)
	case http.StatusTooManyRequests:
		if creating {
			return fault.New(fault.CodeRegistrationRateLimited, "create registration", nil)
		}
		return fault.New(fault.CodeControlPlaneUnavailable, "exchange registration", nil)
	default:
		return statusError(status)
	}
}

func validateEnrollmentExchangeResponse(response JoinTokenExchangeResponse, now time.Time) bool {
	keys := signedconfig.SigningKeys{Keys: response.SigningKeys}
	deviceSecret, deviceSecretErr := parseDeviceCredential(response.DeviceCredential.Credential)
	return validOpaqueSecret(response.EnrollmentToken, "xenr_") && response.TokenType == "Bearer" && validEnrollmentScope(response.Scope) && response.ExpiresAt.Location() == time.UTC && response.ExpiresAt.After(now) && response.ExpiresAt.Sub(now) <= maximumEnrollmentLifetime && deviceSecretErr == nil && deviceSecret.CredentialID == response.DeviceCredential.CredentialID && response.DeviceCredential.TokenType == credentialTokenType && validDeviceCredentialScope(response.DeviceCredential.Scope) && canonicalCredentialWindow(response.DeviceCredential.IssuedAt, response.DeviceCredential.ExpiresAt, now) && response.Device.ID != "" && response.Device.NetworkID != "" && response.Device.Platform != "" && response.Device.WireGuardPublicKey != "" && response.Network.ID == response.Device.NetworkID && validIPv4HostPrefix(response.Device.WireGuardAddress) && validIPv4Prefix(response.Network.CIDR) && keys.Validate() == nil
}

// These small aliases keep registration validation independent of the
// credential package's private parser helpers while preserving its wire rules.
const credentialTokenType = "Device"

func parseDeviceCredential(value string) (struct{ CredentialID string }, error) {
	secret, err := credential.Parse(value)
	return struct{ CredentialID string }{CredentialID: secret.CredentialID}, err
}
