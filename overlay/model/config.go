// Modified for XConnect-One: standalone module imports.
package model

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

const (
	SchemaVersionV1      = 1
	CoreIDXray           = "xray"
	AdapterIDLibXray     = "libXray"
	AdapterIDXrayCore    = "xray-core"
	WireRuntimeXrayCore  = "xray-core"
	TransportVLESSTLS    = "vless-tls"
	TransportSecurityTLS = "tls"
	PacketEncodingXUDP   = "xudp"
)

type Network struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CIDR        string `json:"cidr"`
}

type Device struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id,omitempty"`
	NetworkID          string     `json:"network_id"`
	Name               string     `json:"name"`
	Platform           string     `json:"platform"`
	Hostname           string     `json:"hostname"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	WireGuardAddress   string     `json:"wireguard_address"`
	CreatedAt          time.Time  `json:"created_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at,omitempty"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
}

type WireGuardConfig struct {
	Interface            string   `json:"interface"`
	Address              string   `json:"address"`
	MTU                  int      `json:"mtu"`
	DNS                  []string `json:"dns"`
	PrivateKeyRef        string   `json:"private_key_ref"`
	LocalProxyEndpoint   string   `json:"local_proxy_endpoint"`
	PersistentKeepalive  int      `json:"persistent_keepalive"`
	PeerPublicKey        string   `json:"peer_public_key"`
	PeerAllowedIPs       []string `json:"peer_allowed_ips"`
	PeerEndpoint         string   `json:"peer_endpoint"`
	GatewayWireGuardIP   string   `json:"gateway_wireguard_ip"`
	GatewayWireGuardPort int      `json:"gateway_wireguard_port,omitempty"`
	GatewayWireGuardCIDR string   `json:"gateway_wireguard_cidr"`
}

type TransportConfig struct {
	Runtime        string `json:"runtime"`
	Type           string `json:"type"`
	Security       string `json:"security"`
	Server         string `json:"server"`
	ServerName     string `json:"server_name,omitempty"`
	Port           int    `json:"port"`
	UUID           string `json:"uuid"`
	AuthID         string `json:"auth_id,omitempty"`
	Path           string `json:"path"`
	Mode           string `json:"mode"`
	Flow           string `json:"flow"`
	PacketEncoding string `json:"packet_encoding"`
	LocalPort      int    `json:"local_port"`
}

type OverlayNode struct {
	ID                 string     `json:"id"`
	NetworkID          string     `json:"network_id"`
	Name               string     `json:"name"`
	Role               string     `json:"role"`
	Region             string     `json:"region"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	WireGuardAddress   string     `json:"wireguard_address"`
	EndpointHost       string     `json:"endpoint_host"`
	EndpointPort       int        `json:"endpoint_port"`
	TransportType      string     `json:"transport_type"`
	TransportSecurity  string     `json:"transport_security"`
	TransportPath      string     `json:"transport_path"`
	TransportMode      string     `json:"transport_mode"`
	TransportUUID      string     `json:"transport_uuid,omitempty"`
	TransportUUIDSet   bool       `json:"transport_uuid_set,omitempty"`
	Healthy            bool       `json:"healthy"`
	LastHeartbeat      *time.Time `json:"last_heartbeat,omitempty"`
}

type Config struct {
	SchemaVersion int             `json:"schema_version"`
	Revision      string          `json:"revision"`
	Digest        string          `json:"digest"`
	Network       Network         `json:"network"`
	Device        Device          `json:"device"`
	WireGuard     WireGuardConfig `json:"wireguard"`
	Transport     TransportConfig `json:"transport"`
	Nodes         []OverlayNode   `json:"nodes,omitempty"`
	ETag          string          `json:"-"`
}

func (c Config) Validate() error {
	if c.Transport.Runtime != WireRuntimeXrayCore {
		return fault.New(fault.CodeUnsupportedRuntimeCore, "validate config", nil)
	}
	if c.SchemaVersion != SchemaVersionV1 || strings.TrimSpace(c.Revision) == "" || strings.TrimSpace(c.Digest) == "" {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if strings.TrimSpace(c.Network.ID) == "" || strings.TrimSpace(c.Device.ID) == "" {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if c.Transport.Type != TransportVLESSTLS || c.Transport.Security != TransportSecurityTLS || c.Transport.PacketEncoding != PacketEncodingXUDP {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if strings.TrimSpace(c.Transport.Server) == "" || !validPort(c.Transport.Port) || !validPort(c.Transport.LocalPort) || !validVLESSAuthID(c.Transport.VLESSAuthID()) {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if c.Transport.UUID != "" && c.Transport.AuthID != "" {
		return fault.New(fault.CodeInvalidConfig, "validate config credential", nil)
	}
	if !interfaceNamePattern.MatchString(c.WireGuard.Interface) || strings.TrimSpace(c.WireGuard.PrivateKeyRef) == "" || len(c.WireGuard.PeerAllowedIPs) == 0 {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if !validCIDR(c.WireGuard.Address) || !validWireGuardKey(c.WireGuard.PeerPublicKey) {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	for _, allowedIP := range c.WireGuard.PeerAllowedIPs {
		if !validCIDR(allowedIP) {
			return fault.New(fault.CodeInvalidConfig, "validate config", nil)
		}
	}
	if c.WireGuard.MTU < 576 || c.WireGuard.MTU > 1500 {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if c.WireGuard.PersistentKeepalive < 0 || c.WireGuard.PersistentKeepalive > 65535 || net.ParseIP(c.WireGuard.GatewayWireGuardIP) == nil || !validCIDR(c.WireGuard.GatewayWireGuardCIDR) || !validOptionalPort(c.WireGuard.GatewayWireGuardPort) {
		return fault.New(fault.CodeInvalidConfig, "validate config", nil)
	}
	if err := requireLoopbackEndpoint(c.WireGuard.PeerEndpoint, c.Transport.LocalPort); err != nil {
		return fault.New(fault.CodeInvalidConfig, "validate config", err)
	}
	if err := requireLoopbackEndpoint(c.WireGuard.LocalProxyEndpoint, c.Transport.LocalPort); err != nil {
		return fault.New(fault.CodeInvalidConfig, "validate config", err)
	}
	return nil
}

func (c Config) CoreID() string { return CoreIDXray }

func (c Config) AdapterID() string { return AdapterIDLibXray }

func (t TransportConfig) VLESSAuthID() string {
	if t.AuthID != "" {
		return t.AuthID
	}
	return t.UUID
}

func (t TransportConfig) TLSServerName() string {
	if strings.TrimSpace(t.ServerName) != "" {
		return t.ServerName
	}
	return t.Server
}

func (w WireGuardConfig) RelayTargetPort() int {
	if w.GatewayWireGuardPort != 0 {
		return w.GatewayWireGuardPort
	}
	return 51820
}

func SupportedAdapterID(adapterID string) bool {
	return adapterID == AdapterIDLibXray || adapterID == AdapterIDXrayCore
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validCIDR(value string) bool {
	_, err := netip.ParsePrefix(value)
	return err == nil
}

func validWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validUUID(value string) bool {
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}

func validVLESSAuthID(value string) bool { return validUUID(value) }

func validOptionalPort(port int) bool { return port == 0 || validPort(port) }

func requireLoopbackEndpoint(endpoint string, expectedPort int) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	if host != "127.0.0.1" || port != fmt.Sprintf("%d", expectedPort) {
		return errors.New("endpoint must match the configured loopback transport")
	}
	return nil
}
