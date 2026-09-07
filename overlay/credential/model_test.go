// Modified for XConnect-One: standalone module imports.
package credential

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

func TestGenerateParseAndVerifierBindCredentialID(t *testing.T) {
	secret, err := GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x11}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	wantID := "xdcid_" + strings.Repeat("11", 16)
	if secret.CredentialID != wantID || !strings.HasPrefix(secret.Value, "xdc_"+strings.Repeat("11", 16)+".") {
		t.Fatalf("secret=%#v", secret)
	}
	parsed, err := Parse(secret.Value)
	if err != nil || parsed != secret {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	verifier, err := Verifier(secret.Value)
	if err != nil || len(verifier) != 64 {
		t.Fatalf("verifier=%q err=%v", verifier, err)
	}
}

func TestVerifierMatchesCanonicalIACFullTokenVector(t *testing.T) {
	value := "xdc_fedcba9876543210fedcba9876543210.BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
	verifier, err := Verifier(value)
	if err != nil || verifier != "00bdb1b7a7203fa88c9bd01bc87ef416cafd04d3379934ad535dda1252f0ea80" {
		t.Fatalf("verifier=%q err=%v", verifier, err)
	}
}

func TestParseRejectsAmbiguousDeviceCredential(t *testing.T) {
	valid := "xdc_" + strings.Repeat("a", 32) + "." + strings.Repeat("A", 43)
	for _, value := range []string{
		" " + valid, strings.ToUpper(valid), strings.Replace(valid, ".", "..", 1),
		"xdc_" + strings.Repeat("a", 32) + "." + strings.Repeat("A", 42) + "=",
	} {
		if _, err := Parse(value); fault.Code(err) != fault.CodeCredentialInvalid {
			t.Fatalf("accepted %q: %v", value, err)
		}
	}
}

func TestRecordValidatesHTTPSBindingScopeAndPendingRotation(t *testing.T) {
	record := validRecord(t)
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	pending, err := GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x22}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.WithPending(pending, time.Date(2026, 8, 28, 12, 1, 0, 0, time.UTC))
	if err != nil || record.Pending == nil {
		t.Fatalf("pending=%#v err=%v", record.Pending, err)
	}
	promoted, err := record.PromotePending(time.Date(2026, 8, 28, 12, 2, 0, 0, time.UTC), time.Date(2026, 9, 27, 12, 2, 0, 0, time.UTC), record.Scope)
	if err != nil || promoted.CredentialID != pending.CredentialID || promoted.Pending != nil {
		t.Fatalf("promoted=%#v err=%v", promoted, err)
	}

	unsafe := validRecord(t)
	unsafe.Controller = "http://localhost:8080"
	if fault.Code(unsafe.Validate()) != fault.CodeCredentialInvalid {
		t.Fatal("HTTP controller accepted")
	}
	unsafe = validRecord(t)
	unsafe.Scope = append(unsafe.Scope, "overlay:admin")
	if fault.Code(unsafe.Validate()) != fault.CodeCredentialInvalid {
		t.Fatal("admin scope accepted")
	}
}

func validRecord(t *testing.T) Record {
	t.Helper()
	secret, err := GenerateWithReader(bytes.NewReader(bytes.Repeat([]byte{0x11}, 48)))
	if err != nil {
		t.Fatal(err)
	}
	return Record{
		SchemaVersion: SchemaVersion, Controller: "https://accounts.example", DeviceID: "device-alpha", NetworkID: "network-private", Platform: "linux",
		WireGuardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		CredentialID:       secret.CredentialID, Credential: secret.Value,
		IssuedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
		Scope: []string{ScopeSessionMint, ScopeRotate, ScopeDeviceRevoke},
		SigningKeys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{
			KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519, PublicKey: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", Status: "current",
			NotBefore: signedconfig.CanonicalTime{Time: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)},
		}}},
	}
}
