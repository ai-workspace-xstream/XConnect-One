// Modified for XConnect-One: standalone module imports.
package policy

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

const goldenDigest = "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c"

func TestConsumeMatchesAccountsAndIaCGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/policy-enforcement-artifact.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	reference := verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour))
	accepted, err := Consume(raw, reference, Floor{}, now)
	if err != nil {
		t.Fatalf("consume golden: %v", err)
	}
	if accepted.Digest != goldenDigest || accepted.Generation != 9 || accepted.Artifact.Revision != 7 || strings.HasSuffix(string(accepted.Canonical), "\n") {
		t.Fatalf("accepted = %#v canonical=%q", accepted, accepted.Canonical)
	}
}

func TestOptionalCrossRepositoryGoldenMirrors(t *testing.T) {
	local, err := os.ReadFile("testdata/policy-enforcement-artifact.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, environment := range []string{"XCONNECT_ACCOUNTS_POLICY_FIXTURE", "XCONNECT_IAC_POLICY_FIXTURE"} {
		path := os.Getenv(environment)
		if path == "" {
			continue
		}
		remote, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", environment, err)
		}
		if !bytes.Equal(bytes.TrimSpace(remote), bytes.TrimSpace(local)) {
			t.Fatalf("%s differs from canonical client fixture", environment)
		}
	}
}

func TestConsumeRejectsUnsafeContracts(t *testing.T) {
	raw, err := os.ReadFile("testdata/policy-enforcement-artifact.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		raw       []byte
		reference VerifiedReference
		floor     Floor
		code      string
	}{
		{name: "unknown field", raw: []byte(strings.Replace(string(raw), `"revision":7`, `"revision":7,"users":{"a":"b"}`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "PII device", raw: []byte(strings.Replace(string(raw), `"dev-a"`, `"person@example.com"`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "not default deny", raw: []byte(strings.Replace(string(raw), `"default_action":"deny"`, `"default_action":"accept"`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "wrong digest", raw: raw, reference: verifiedReference(t, "network-golden", 9, strings.Repeat("0", 64), now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "wrong network", raw: raw, reference: verifiedReference(t, "other-network", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "expired", raw: raw, reference: verifiedReference(t, "network-golden", 9, goldenDigest, now), code: fault.CodePolicyExpired},
		{name: "replayed generation", raw: raw, reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), floor: Floor{NetworkID: "network-golden", Generation: 10, Digest: goldenDigest}, code: fault.CodePolicyReplay},
		{name: "same generation different digest", raw: raw, reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), floor: Floor{NetworkID: "network-golden", Generation: 9, Digest: strings.Repeat("0", 64)}, code: fault.CodePolicyReplay},
		{name: "protected flow reordered", raw: []byte(strings.Replace(string(raw), `"control:controller-session","control:gateway-apply-result"`, `"control:gateway-apply-result","control:controller-session"`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "accept before deny", raw: []byte(strings.Replace(string(raw), `{"id":"allow-api","action":"accept","source_devices":["dev-a"],"destination_devices":["dev-b"],"protocols":["tcp"],"ports":[8787]}`, `{"id":"allow-api","action":"accept","source_devices":["dev-a"],"destination_devices":["dev-b"],"protocols":["tcp"],"ports":[8787]},{"id":"deny-admin","action":"deny","source_devices":["dev-a"],"destination_devices":["dev-b"],"protocols":["tcp"],"ports":[22]}`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "unsorted device members", raw: []byte(strings.Replace(string(raw), `"source_devices":["dev-a"]`, `"source_devices":["dev-z","dev-a"]`, 1)), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: fault.CodePolicyInvalid},
		{name: "physical whitespace accepted", raw: append([]byte(" "), raw...), reference: verifiedReference(t, "network-golden", 9, goldenDigest, now.Add(time.Hour)), code: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Consume(test.raw, test.reference, test.floor, now)
			if test.code == "" && err == nil {
				return
			}
			if fault.Code(err) != test.code {
				t.Fatalf("code=%q err=%v", fault.Code(err), err)
			}
		})
	}
}

func verifiedReference(t *testing.T, network string, generation uint64, digest string, expiry time.Time) VerifiedReference {
	t.Helper()
	reference, err := newVerifiedReference(ProvenanceGatewaySnapshot, network, generation, digest, expiry)
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	return reference
}
