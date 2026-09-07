// Modified for XConnect-One: standalone module imports.
package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

const (
	SchemaVersion     = 1
	TokenType         = "Device"
	Authorization     = "Device"
	maximumLifetime   = 31 * 24 * time.Hour
	rotationLeadTime  = 7 * 24 * time.Hour
	ScopeSessionMint  = "overlay:session:mint"
	ScopeRotate       = "overlay:credential:rotate"
	ScopeDeviceRevoke = "overlay:device:revoke"
)

var (
	ErrNotFound         = errors.New("device credential not found")
	credentialIDPattern = regexp.MustCompile(`^xdcid_[0-9a-f]{32}$`)
	credentialPattern   = regexp.MustCompile(`^xdc_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$`)
	bindingIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$`)
	platformValues      = map[string]bool{"darwin": true, "windows": true, "linux": true, "ios": true, "android": true}
)

type Secret struct {
	CredentialID string
	Value        string
}

type PendingRotation struct {
	CredentialID string    `json:"credential_id"`
	Credential   string    `json:"credential"`
	Verifier     string    `json:"secret_sha256"`
	CreatedAt    time.Time `json:"created_at"`
}

type Record struct {
	SchemaVersion      int                      `json:"schema_version"`
	Controller         string                   `json:"controller"`
	DeviceID           string                   `json:"device_id"`
	NetworkID          string                   `json:"network_id"`
	Platform           string                   `json:"platform"`
	WireGuardPublicKey string                   `json:"wireguard_public_key"`
	CredentialID       string                   `json:"credential_id"`
	Credential         string                   `json:"credential"`
	IssuedAt           time.Time                `json:"issued_at"`
	ExpiresAt          time.Time                `json:"expires_at"`
	Scope              []string                 `json:"scope"`
	SigningKeys        signedconfig.SigningKeys `json:"signing_keys"`
	Pending            *PendingRotation         `json:"pending_rotation,omitempty"`
}

func Generate() (Secret, error) { return GenerateWithReader(rand.Reader) }

func GenerateWithReader(reader io.Reader) (Secret, error) {
	identifier := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := io.ReadFull(reader, identifier); err != nil {
		return Secret{}, fault.New(fault.CodeCredentialStorage, "generate device credential id", err)
	}
	if _, err := io.ReadFull(reader, secret); err != nil {
		return Secret{}, fault.New(fault.CodeCredentialStorage, "generate device credential secret", err)
	}
	id := hex.EncodeToString(identifier)
	return Secret{
		CredentialID: "xdcid_" + id,
		Value:        "xdc_" + id + "." + base64.RawURLEncoding.EncodeToString(secret),
	}, nil
}

func Parse(value string) (Secret, error) {
	if value != strings.TrimSpace(value) {
		return Secret{}, invalid("parse device credential")
	}
	match := credentialPattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return Secret{}, invalid("parse device credential")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(match[2])
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != match[2] {
		return Secret{}, invalid("parse device credential")
	}
	return Secret{CredentialID: "xdcid_" + match[1], Value: value}, nil
}

// Verifier returns the canonical v1 verifier over the exact UTF-8 wire value.
func Verifier(value string) (string, error) {
	if _, err := Parse(value); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:]), nil
}

func (r Record) Validate() error {
	if r.SchemaVersion != SchemaVersion || !validHTTPSController(r.Controller) || !bindingIDPattern.MatchString(r.DeviceID) || !bindingIDPattern.MatchString(r.NetworkID) || !platformValues[r.Platform] || !validWireGuardPublicKey(r.WireGuardPublicKey) {
		return invalid("validate device credential binding")
	}
	secret, err := Parse(r.Credential)
	if err != nil || secret.CredentialID != r.CredentialID || !credentialIDPattern.MatchString(r.CredentialID) {
		return invalid("validate device credential identity")
	}
	if !canonicalTime(r.IssuedAt) || !canonicalTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > maximumLifetime || !validScope(r.Scope) {
		return invalid("validate device credential lifetime")
	}
	if err := r.SigningKeys.Validate(); err != nil {
		return invalid("validate device credential signing keys")
	}
	if r.Pending != nil {
		pendingSecret, parseErr := Parse(r.Pending.Credential)
		verifier, verifierErr := Verifier(r.Pending.Credential)
		if parseErr != nil || verifierErr != nil || pendingSecret.CredentialID != r.Pending.CredentialID || r.Pending.CredentialID == r.CredentialID || verifier != r.Pending.Verifier || !canonicalTime(r.Pending.CreatedAt) {
			return invalid("validate pending device credential")
		}
	}
	return nil
}

func (r Record) Expired(now time.Time) bool { return !r.ExpiresAt.After(now.UTC()) }

func (r Record) RotationDue(now time.Time) bool {
	return !r.ExpiresAt.After(now.UTC().Add(rotationLeadTime))
}

func (r Record) WithPending(secret Secret, now time.Time) (Record, error) {
	if r.Pending != nil {
		return Record{}, fault.New(fault.CodeCredentialRotationPending, "create pending device credential", nil)
	}
	verifier, err := Verifier(secret.Value)
	if err != nil || secret.CredentialID == r.CredentialID {
		return Record{}, invalid("create pending device credential")
	}
	copy := r
	copy.Pending = &PendingRotation{CredentialID: secret.CredentialID, Credential: secret.Value, Verifier: verifier, CreatedAt: now.UTC().Truncate(time.Second)}
	if err := copy.Validate(); err != nil {
		return Record{}, err
	}
	return copy, nil
}

func (r Record) PromotePending(issuedAt, expiresAt time.Time, scope []string) (Record, error) {
	if r.Pending == nil {
		return Record{}, fault.New(fault.CodeCredentialRotationPending, "promote missing device credential", nil)
	}
	copy := r
	copy.CredentialID = r.Pending.CredentialID
	copy.Credential = r.Pending.Credential
	copy.IssuedAt = issuedAt.UTC()
	copy.ExpiresAt = expiresAt.UTC()
	copy.Scope = append([]string(nil), scope...)
	copy.Pending = nil
	if err := copy.Validate(); err != nil {
		return Record{}, err
	}
	return copy, nil
}

// PendingRecord returns a probe-only view authenticated by the pending
// successor. It is never persisted as active until the server proves it can
// mint a bound device session.
func (r Record) PendingRecord() (Record, error) {
	if r.Pending == nil {
		return Record{}, fault.New(fault.CodeCredentialRotationPending, "probe missing device credential", nil)
	}
	copy := r
	copy.CredentialID = r.Pending.CredentialID
	copy.Credential = r.Pending.Credential
	copy.IssuedAt = r.Pending.CreatedAt
	// The probe recovery window is deliberately conservative because the mint
	// response does not repeat the durable credential expiry.
	copy.ExpiresAt = r.Pending.CreatedAt.Add(30 * 24 * time.Hour)
	copy.Pending = nil
	if err := copy.Validate(); err != nil {
		return Record{}, err
	}
	return copy, nil
}

func validScope(values []string) bool {
	if len(values) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != ScopeSessionMint && value != ScopeRotate && value != ScopeDeviceRevoke || seen[value] {
			return false
		}
		seen[value] = true
	}
	return seen[ScopeSessionMint] && seen[ScopeRotate] && seen[ScopeDeviceRevoke]
}

func validHTTPSController(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validWireGuardPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func invalid(operation string) error {
	return fault.New(fault.CodeCredentialInvalid, operation, nil)
}
