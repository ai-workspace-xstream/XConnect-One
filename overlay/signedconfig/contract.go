// Modified for XConnect-One: standalone module imports.
package signedconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

const (
	SchemaVersionV1  = 1
	SchemaVersionV2  = 2
	ProxyCoreXray    = "xray"
	TransportVLESS   = "vless-tls-xudp"
	SignatureEd25519 = "Ed25519"
	LoopbackHost     = "127.0.0.1"
	RelayTargetPort  = 51820
	PolicyMediaType  = "application/vnd.xconnect.policy.v1+json"
)

var (
	idPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{2,127}$`)
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)
	forbiddenFields  = map[string]struct{}{
		"private_key":           {},
		"wireguard_private_key": {},
		"refresh_token":         {},
		"vault_token":           {},
		"access_token":          {},
		"token":                 {},
	}
)

func PolicyPath(generation uint64, digest string) string {
	return fmt.Sprintf("/api/overlay/v1/enrollment/policy-artifacts/%d/%s", generation, digest)
}

// CanonicalTime preserves the SignedConfig wire requirement: UTC, whole
// seconds, and the exact RFC3339 Z representation.
type CanonicalTime struct{ time.Time }

func (t *CanonicalTime) UnmarshalJSON(raw []byte) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("contract time must be an RFC3339 string")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || value != parsed.UTC().Format(time.RFC3339) {
		return errors.New("contract time must use UTC RFC3339 whole-second precision")
	}
	t.Time = parsed.UTC()
	return nil
}

func (t CanonicalTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() || t.Location() != time.UTC || t.Nanosecond() != 0 {
		return nil, errors.New("contract time must use UTC RFC3339 whole-second precision")
	}
	return json.Marshal(t.Format(time.RFC3339))
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type RemoteEndpoint struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name"`
}

type Transport struct {
	Kind     string         `json:"kind"`
	Loopback Endpoint       `json:"loopback"`
	Remote   RemoteEndpoint `json:"remote"`
	AuthID   string         `json:"auth_id"`
}

type Peer struct {
	GatewayID                  string   `json:"gateway_id"`
	PublicKey                  string   `json:"public_key"`
	AllowedIPs                 []string `json:"allowed_ips"`
	Endpoint                   Endpoint `json:"endpoint"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds,omitempty"`
}

type WireGuard struct {
	InterfaceName string   `json:"interface_name"`
	Addresses     []string `json:"addresses"`
	MTU           int      `json:"mtu"`
	Peers         []Peer   `json:"peers"`
}

type Config struct {
	SchemaVersion int           `json:"schema_version"`
	ConfigID      string        `json:"config_id"`
	NetworkID     string        `json:"network_id"`
	DeviceID      string        `json:"device_id"`
	Generation    uint64        `json:"generation"`
	IssuedAt      CanonicalTime `json:"issued_at"`
	ExpiresAt     CanonicalTime `json:"expires_at"`
	ProxyCore     string        `json:"proxy_core"`
	Transport     Transport     `json:"transport"`
	WireGuard     WireGuard     `json:"wireguard"`
	Policy        *Policy       `json:"policy,omitempty"`
	Signature     Signature     `json:"signature"`
	ETag          string        `json:"-"`
}

// Policy is a signed, same-origin reference to the canonical local-policy
// artifact. It is deliberately a path, not a URL: callers must derive and
// compare it before making an authenticated request.
type Policy struct {
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
	Path       string `json:"path"`
	MediaType  string `json:"media_type"`
}

type SigningKey struct {
	KeyID     string         `json:"key_id"`
	Algorithm string         `json:"algorithm"`
	PublicKey string         `json:"public_key"`
	Status    string         `json:"status"`
	NotBefore CanonicalTime  `json:"not_before"`
	NotAfter  *CanonicalTime `json:"not_after,omitempty"`
}

type SigningKeys struct {
	Keys []SigningKey `json:"keys"`
	ETag string       `json:"-"`
}

func DecodeConfig(raw []byte) (Config, error) {
	if err := validateNoForbiddenFields(raw); err != nil {
		return Config{}, fault.New(fault.CodeInvalidSignedConfig, "decode signed config", nil)
	}
	config, err := strictDecode[Config](raw)
	if err != nil {
		return Config{}, fault.New(fault.CodeInvalidSignedConfig, "decode signed config", nil)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func DecodeSigningKeys(raw []byte) (SigningKeys, error) {
	if err := validateNoForbiddenFields(raw); err != nil {
		return SigningKeys{}, fault.New(fault.CodeInvalidSigningKeys, "decode signing keys", nil)
	}
	keys, err := strictDecode[SigningKeys](raw)
	if err != nil {
		return SigningKeys{}, fault.New(fault.CodeInvalidSigningKeys, "decode signing keys", nil)
	}
	if err := keys.Validate(); err != nil {
		return SigningKeys{}, err
	}
	return keys, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersionV1 && c.SchemaVersion != SchemaVersionV2 || !validID(c.ConfigID) || !validID(c.NetworkID) || !validID(c.DeviceID) || c.Generation == 0 {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config identity", nil)
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt.Time) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config lifetime", nil)
	}
	if c.ProxyCore != ProxyCoreXray {
		return fault.New(fault.CodeUnsupportedRuntimeCore, "validate signed config core", nil)
	}
	if c.Transport.Kind != TransportVLESS || c.Transport.Loopback.Host != LoopbackHost || !validPort(c.Transport.Loopback.Port) || !validHost(c.Transport.Remote.Host) || !validPort(c.Transport.Remote.Port) || !validHost(c.Transport.Remote.ServerName) || !validID(c.Transport.AuthID) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config transport", nil)
	}
	if !interfacePattern.MatchString(c.WireGuard.InterfaceName) || len(c.WireGuard.Addresses) == 0 || c.WireGuard.MTU < 576 || c.WireGuard.MTU > 1500 || len(c.WireGuard.Peers) == 0 {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config WireGuard", nil)
	}
	if !validUniqueCIDRs(c.WireGuard.Addresses) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config WireGuard addresses", nil)
	}
	gateways := make(map[string]struct{}, len(c.WireGuard.Peers))
	for _, peer := range c.WireGuard.Peers {
		if !validID(peer.GatewayID) {
			return fault.New(fault.CodeInvalidSignedConfig, "validate signed config gateway", nil)
		}
		if _, exists := gateways[peer.GatewayID]; exists {
			return fault.New(fault.CodeInvalidSignedConfig, "validate signed config gateway uniqueness", nil)
		}
		gateways[peer.GatewayID] = struct{}{}
		publicKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil || len(publicKey) != 32 || !validUniqueCIDRs(peer.AllowedIPs) || peer.Endpoint.Host != LoopbackHost || !validPort(peer.Endpoint.Port) || peer.PersistentKeepaliveSeconds < 0 || peer.PersistentKeepaliveSeconds > 65535 {
			return fault.New(fault.CodeInvalidSignedConfig, "validate signed config WireGuard peer", nil)
		}
	}
	if c.Signature.Algorithm != SignatureEd25519 || !validID(c.Signature.KeyID) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config signature metadata", nil)
	}
	signature, err := base64.StdEncoding.DecodeString(c.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config signature", nil)
	}
	if c.SchemaVersion == SchemaVersionV1 && c.Policy != nil || c.SchemaVersion == SchemaVersionV2 && (c.Policy == nil || c.Policy.Validate() != nil) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed config policy", nil)
	}
	return nil
}

func (p Policy) Validate() error {
	if p.Generation == 0 || !digestPattern.MatchString(p.Digest) || p.MediaType != PolicyMediaType || p.Path != PolicyPath(p.Generation, p.Digest) {
		return fault.New(fault.CodeInvalidSignedConfig, "validate signed policy reference", nil)
	}
	return nil
}

func (k SigningKeys) Validate() error {
	if len(k.Keys) == 0 {
		return fault.New(fault.CodeInvalidSigningKeys, "validate signing keys", nil)
	}
	seen := make(map[string]struct{}, len(k.Keys))
	current := 0
	for _, key := range k.Keys {
		if !validID(key.KeyID) || key.Algorithm != SignatureEd25519 || (key.Status != "current" && key.Status != "previous") || key.NotBefore.IsZero() {
			return fault.New(fault.CodeInvalidSigningKeys, "validate signing key metadata", nil)
		}
		if _, exists := seen[key.KeyID]; exists {
			return fault.New(fault.CodeInvalidSigningKeys, "validate signing key uniqueness", nil)
		}
		seen[key.KeyID] = struct{}{}
		publicKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return fault.New(fault.CodeInvalidSigningKeys, "validate signing key material", nil)
		}
		if key.NotAfter != nil && !key.NotAfter.After(key.NotBefore.Time) {
			return fault.New(fault.CodeInvalidSigningKeys, "validate signing key window", nil)
		}
		if key.Status == "current" {
			current++
		} else if key.NotAfter == nil {
			return fault.New(fault.CodeInvalidSigningKeys, "validate previous signing key window", nil)
		}
	}
	if current != 1 {
		return fault.New(fault.CodeInvalidSigningKeys, "validate current signing key", nil)
	}
	return nil
}

func (c Config) SigningBytes() ([]byte, error) {
	if c.SchemaVersion == SchemaVersionV2 {
		payload := struct {
			SchemaVersion int           `json:"schema_version"`
			ConfigID      string        `json:"config_id"`
			NetworkID     string        `json:"network_id"`
			DeviceID      string        `json:"device_id"`
			Generation    uint64        `json:"generation"`
			IssuedAt      CanonicalTime `json:"issued_at"`
			ExpiresAt     CanonicalTime `json:"expires_at"`
			ProxyCore     string        `json:"proxy_core"`
			Transport     Transport     `json:"transport"`
			WireGuard     WireGuard     `json:"wireguard"`
			Policy        *Policy       `json:"policy"`
		}{c.SchemaVersion, c.ConfigID, c.NetworkID, c.DeviceID, c.Generation, c.IssuedAt, c.ExpiresAt, c.ProxyCore, c.Transport, c.WireGuard, c.Policy}
		return json.Marshal(payload)
	}
	payload := struct {
		SchemaVersion int           `json:"schema_version"`
		ConfigID      string        `json:"config_id"`
		NetworkID     string        `json:"network_id"`
		DeviceID      string        `json:"device_id"`
		Generation    uint64        `json:"generation"`
		IssuedAt      CanonicalTime `json:"issued_at"`
		ExpiresAt     CanonicalTime `json:"expires_at"`
		ProxyCore     string        `json:"proxy_core"`
		Transport     Transport     `json:"transport"`
		WireGuard     WireGuard     `json:"wireguard"`
	}{
		SchemaVersion: c.SchemaVersion,
		ConfigID:      c.ConfigID,
		NetworkID:     c.NetworkID,
		DeviceID:      c.DeviceID,
		Generation:    c.Generation,
		IssuedAt:      c.IssuedAt,
		ExpiresAt:     c.ExpiresAt,
		ProxyCore:     c.ProxyCore,
		Transport:     c.Transport,
		WireGuard:     c.WireGuard,
	}
	return json.Marshal(payload)
}

func Verify(config Config, keys SigningKeys, now time.Time) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := keys.Validate(); err != nil {
		return err
	}
	now = now.UTC()
	if config.IssuedAt.After(now) {
		return fault.New(fault.CodeSignedConfigFuture, "verify signed config lifetime", nil)
	}
	if !config.ExpiresAt.After(now) {
		return fault.New(fault.CodeSignedConfigExpired, "verify signed config lifetime", nil)
	}
	var selected *SigningKey
	for index := range keys.Keys {
		if keys.Keys[index].KeyID == config.Signature.KeyID {
			selected = &keys.Keys[index]
			break
		}
	}
	if selected == nil {
		return fault.New(fault.CodeSigningKeyUnknown, "verify signed config key", nil)
	}
	if config.IssuedAt.Before(selected.NotBefore.Time) || now.Before(selected.NotBefore.Time) {
		return fault.New(fault.CodeSigningKeyWindow, "verify signed config key window", nil)
	}
	if selected.NotAfter != nil && (!config.ExpiresAt.Time.Before(selected.NotAfter.Time) && !config.ExpiresAt.Time.Equal(selected.NotAfter.Time) || !now.Before(selected.NotAfter.Time)) {
		return fault.New(fault.CodeSigningKeyWindow, "verify signed config key window", nil)
	}
	publicKey, _ := base64.StdEncoding.DecodeString(selected.PublicKey)
	signature, _ := base64.StdEncoding.DecodeString(config.Signature.Value)
	payload, err := config.SigningBytes()
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fault.New(fault.CodeInvalidSignature, "verify signed config signature", nil)
	}
	return nil
}

func Compile(config Config) (model.Config, error) {
	if err := config.Validate(); err != nil {
		return model.Config{}, err
	}
	if len(config.WireGuard.Addresses) != 1 || len(config.WireGuard.Peers) != 1 {
		return model.Config{}, fault.New(fault.CodeInvalidSignedConfig, "compile single-gateway runtime", nil)
	}
	peer := config.WireGuard.Peers[0]
	if !validUUID(config.Transport.AuthID) {
		return model.Config{}, fault.New(fault.CodeInvalidSignedConfig, "compile Xray VLESS credential", nil)
	}
	if peer.Endpoint != config.Transport.Loopback {
		return model.Config{}, fault.New(fault.CodeInvalidSignedConfig, "compile loopback endpoint", nil)
	}
	payload, err := config.SigningBytes()
	if err != nil {
		return model.Config{}, fault.New(fault.CodeInvalidSignedConfig, "compile signed config", nil)
	}
	digest := sha256.Sum256(payload)
	compiled := model.Config{
		SchemaVersion: model.SchemaVersionV1,
		Revision:      config.ConfigID,
		Digest:        hex.EncodeToString(digest[:]),
		Network:       model.Network{ID: config.NetworkID},
		Device: model.Device{
			ID:               config.DeviceID,
			NetworkID:        config.NetworkID,
			WireGuardAddress: config.WireGuard.Addresses[0],
		},
		WireGuard: model.WireGuardConfig{
			Interface:            config.WireGuard.InterfaceName,
			Address:              config.WireGuard.Addresses[0],
			MTU:                  config.WireGuard.MTU,
			PrivateKeyRef:        "local-secure-state",
			LocalProxyEndpoint:   endpointString(config.Transport.Loopback),
			PersistentKeepalive:  peer.PersistentKeepaliveSeconds,
			PeerPublicKey:        peer.PublicKey,
			PeerAllowedIPs:       append([]string(nil), peer.AllowedIPs...),
			PeerEndpoint:         endpointString(peer.Endpoint),
			GatewayWireGuardIP:   LoopbackHost,
			GatewayWireGuardPort: RelayTargetPort,
			GatewayWireGuardCIDR: LoopbackHost + "/32",
		},
		Transport: model.TransportConfig{
			Runtime:        model.WireRuntimeXrayCore,
			Type:           model.TransportVLESSTLS,
			Security:       model.TransportSecurityTLS,
			Server:         config.Transport.Remote.Host,
			ServerName:     config.Transport.Remote.ServerName,
			Port:           config.Transport.Remote.Port,
			AuthID:         config.Transport.AuthID,
			PacketEncoding: model.PacketEncodingXUDP,
			LocalPort:      config.Transport.Loopback.Port,
		},
	}
	if err := compiled.Validate(); err != nil {
		return model.Config{}, err
	}
	return compiled, nil
}

func endpointString(endpoint Endpoint) string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

func strictDecode[T any](raw []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, errors.New("contract must contain one JSON value")
	}
	return value, nil
}

func validateNoForbiddenFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	return walkForbiddenFields(document)
}

func walkForbiddenFields(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, forbidden := forbiddenFields[strings.ToLower(key)]; forbidden {
				return errors.New("forbidden secret field")
			}
			if err := walkForbiddenFields(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := walkForbiddenFields(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validID(value string) bool { return idPattern.MatchString(value) }
func validPort(port int) bool   { return port >= 1 && port <= 65535 }
func validHost(host string) bool {
	return strings.TrimSpace(host) != "" && len(host) <= 253
}

func validUniqueCIDRs(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validUUID(value string) bool {
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}
