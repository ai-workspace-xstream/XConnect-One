// Modified for XConnect-One: standalone module imports.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const (
	SchemaVersion   = 1
	CompilerVersion = "xconnect-acl-v1alpha1.1"
	DefaultAction   = "deny"
	MaximumBody     = 4 << 20
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	protectedFlows = []string{
		"control:controller-session",
		"control:gateway-apply-result",
		"control:gateway-heartbeat",
		"control:gateway-policy-artifact",
		"control:gateway-snapshot",
	}
)

type Rule struct {
	ID                 string   `json:"id"`
	Action             string   `json:"action"`
	SourceDevices      []string `json:"source_devices"`
	DestinationDevices []string `json:"destination_devices"`
	Protocols          []string `json:"protocols"`
	Ports              []int    `json:"ports"`
}

type Artifact struct {
	SchemaVersion   int      `json:"schema_version"`
	CompilerVersion string   `json:"compiler_version"`
	NetworkID       string   `json:"network_id"`
	Revision        uint64   `json:"revision"`
	DefaultAction   string   `json:"default_action"`
	ProtectedFlows  []string `json:"protected_flows"`
	Rules           []Rule   `json:"rules"`
}

type Floor struct {
	NetworkID  string
	Generation uint64
	Digest     string
}

type Provenance string

const (
	ProvenanceSignedConfig    Provenance = "verified_signed_config"
	ProvenanceGatewaySnapshot Provenance = "verified_gateway_snapshot"
)

// VerifiedReference is intentionally opaque. No public constructor exists in
// v1 because the current client SignedConfig has no policy reference and the
// Gateway snapshot verifier is not part of this client. A future verifier must
// create this value inside this package after checking the signed provenance;
// raw CLI flags and HTTP fields cannot satisfy Consume.
type VerifiedReference struct {
	provenance Provenance
	networkID  string
	generation uint64
	digest     string
	expiresAt  time.Time
}

// ReferenceFromVerifiedSignedConfig binds a policy artifact to data that has
// already been authenticated by the SignedConfig verifier. It intentionally
// takes no URL or expiry from HTTP headers or CLI input.
func ReferenceFromVerifiedSignedConfig(networkID string, generation uint64, digest string, expiresAt time.Time) (VerifiedReference, error) {
	return newVerifiedReference(ProvenanceSignedConfig, networkID, generation, digest, expiresAt)
}

func newVerifiedReference(provenance Provenance, networkID string, generation uint64, digest string, expiresAt time.Time) (VerifiedReference, error) {
	if provenance != ProvenanceSignedConfig && provenance != ProvenanceGatewaySnapshot || !idPattern.MatchString(networkID) || generation == 0 || !digestPattern.MatchString(digest) || expiresAt.IsZero() || expiresAt.Location() != time.UTC || expiresAt.Nanosecond() != 0 {
		return VerifiedReference{}, invalid("bind verified policy reference")
	}
	return VerifiedReference{provenance: provenance, networkID: networkID, generation: generation, digest: digest, expiresAt: expiresAt}, nil
}

type Accepted struct {
	Artifact   Artifact
	Canonical  []byte
	Digest     string
	Generation uint64
	ExpiresAt  time.Time
	Provenance Provenance
}

func Consume(raw []byte, reference VerifiedReference, floor Floor, now time.Time) (Accepted, error) {
	if len(raw) == 0 || len(raw) > MaximumBody {
		return Accepted{}, invalid("validate policy artifact size")
	}
	if reference.provenance != ProvenanceSignedConfig && reference.provenance != ProvenanceGatewaySnapshot || reference.generation == 0 || !idPattern.MatchString(reference.networkID) || !digestPattern.MatchString(reference.digest) {
		return Accepted{}, invalid("validate policy identity")
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !reference.expiresAt.After(now) {
		return Accepted{}, fault.New(fault.CodePolicyExpired, "validate policy lifetime", nil)
	}
	if floor.NetworkID != "" && floor.NetworkID != reference.networkID {
		return Accepted{}, invalid("validate policy floor ownership")
	}
	if reference.generation < floor.Generation || reference.generation == floor.Generation && floor.Digest != "" && floor.Digest != reference.digest {
		return Accepted{}, fault.New(fault.CodePolicyReplay, "validate policy generation", nil)
	}

	var artifact Artifact
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&artifact); err != nil {
		return Accepted{}, invalid("decode policy artifact")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Accepted{}, invalid("decode policy artifact")
	}
	if err := validateArtifact(artifact, reference.networkID); err != nil {
		return Accepted{}, err
	}
	canonical, err := json.Marshal(artifact)
	if err != nil {
		return Accepted{}, invalid("canonicalize policy artifact")
	}
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return Accepted{}, invalid("validate canonical policy encoding")
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	if digest != reference.digest {
		return Accepted{}, invalid("validate policy digest")
	}
	return Accepted{Artifact: artifact, Canonical: canonical, Digest: digest, Generation: reference.generation, ExpiresAt: reference.expiresAt, Provenance: reference.provenance}, nil
}

func validateArtifact(artifact Artifact, networkID string) error {
	if artifact.SchemaVersion != SchemaVersion || artifact.CompilerVersion != CompilerVersion || artifact.NetworkID != networkID || artifact.DefaultAction != DefaultAction {
		return invalid("validate policy contract")
	}
	if !exactStrings(artifact.ProtectedFlows, protectedFlows) {
		return invalid("validate protected policy flows")
	}
	ruleIDs := map[string]bool{}
	for index, rule := range artifact.Rules {
		if !idPattern.MatchString(rule.ID) || ruleIDs[rule.ID] || rule.Action != "accept" && rule.Action != "deny" {
			return invalid("validate policy rule")
		}
		ruleIDs[rule.ID] = true
		if index > 0 && !canonicalRuleOrder(artifact.Rules[index-1], rule) || len(rule.SourceDevices) == 0 || len(rule.DestinationDevices) == 0 || !validDevices(rule.SourceDevices) || !validDevices(rule.DestinationDevices) || !validProtocols(rule.Protocols) || !validPorts(rule.Protocols, rule.Ports) {
			return invalid("validate policy rule scope")
		}
	}
	return nil
}

func validDevices(values []string) bool {
	seen := map[string]bool{}
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return false
		}
		if !idPattern.MatchString(value) || strings.Contains(value, "@") || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validProtocols(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := map[string]bool{}
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return false
		}
		if value != "tcp" && value != "udp" && value != "icmp" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validPorts(protocols []string, ports []int) bool {
	icmpOnly := len(protocols) == 1 && protocols[0] == "icmp"
	if icmpOnly {
		return len(ports) == 0
	}
	if len(ports) == 0 {
		return false
	}
	seen := map[int]bool{}
	for index, port := range ports {
		if index > 0 && ports[index-1] >= port {
			return false
		}
		if port < 1 || port > 65535 || seen[port] {
			return false
		}
		seen[port] = true
	}
	return true
}

func exactStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func canonicalRuleOrder(previous, current Rule) bool {
	if previous.Action == current.Action {
		return previous.ID < current.ID
	}
	return previous.Action == "deny" && current.Action == "accept"
}

func invalid(operation string) error {
	return fault.New(fault.CodePolicyInvalid, operation, nil)
}
