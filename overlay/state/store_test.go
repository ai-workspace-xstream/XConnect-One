// Modified for XConnect-One: standalone module imports.
package state_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

func TestCheckpointAndLastKnownUsePrivatePermissions(t *testing.T) {
	store := state.NewStore(t.TempDir() + "/nested")
	checkpoint := state.Checkpoint{
		Server:              "https://accounts.example",
		DeviceID:            "dev_laptop",
		WireGuardPrivateKey: "private",
		WireGuardPublicKey:  "public",
		Phase:               state.PhaseStarted,
		UpdatedAt:           time.Now().UTC(),
	}
	if err := store.SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	if err := state.ValidatePermissions(store.CheckpointPath(), 0o600); err != nil {
		t.Fatalf("checkpoint permissions: %v", err)
	}
	if err := state.ValidatePermissions(store.Directory(), 0o700); err != nil {
		t.Fatalf("state directory permissions: %v", err)
	}
}

func TestEnrollmentSecretUsesSeparatePrivateBoundArtifact(t *testing.T) {
	store := state.NewStore(t.TempDir())
	secret := validEnrollmentSecret()
	if err := store.SaveEnrollmentSecret(secret); err != nil {
		t.Fatalf("save enrollment secret: %v", err)
	}
	if err := state.ValidatePermissions(store.EnrollmentSecretPath(), 0o600); err != nil {
		t.Fatalf("enrollment secret permissions: %v", err)
	}
	loaded, err := store.LoadEnrollmentSecret(secret.Controller, secret.DeviceID, secret.WireGuardPublicKey)
	if err != nil || loaded.EnrollmentToken != secret.EnrollmentToken || loaded.ExpiresAt != secret.ExpiresAt {
		t.Fatalf("loaded enrollment=%#v err=%v", loaded, err)
	}
	if _, err := store.LoadEnrollmentSecret(secret.Controller, "dev_other", secret.WireGuardPublicKey); fault.Code(err) != fault.CodeStateConflict {
		t.Fatalf("cross-device binding code=%q err=%v", fault.Code(err), err)
	}
	checkpoint := state.Checkpoint{Server: secret.Controller, DeviceID: secret.DeviceID, WireGuardPublicKey: secret.WireGuardPublicKey, WireGuardPrivateKey: "private", Phase: state.PhaseDeviceRegistered, InviteEnrollment: true, EnrollmentExpiresAt: secret.ExpiresAt, UpdatedAt: secret.CreatedAt}
	if err := store.SaveCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.CheckpointPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret.EnrollmentToken)) {
		t.Fatal("ordinary checkpoint contains enrollment bearer")
	}
	if err := store.ClearEnrollmentSecret(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.EnrollmentSecretPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transient secret was not removed: %v", err)
	}
}

func TestSignedContractFloorIsPrivateMonotonicAndDowngradeLocked(t *testing.T) {
	store := state.NewStore(t.TempDir() + "/nested")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := store.AcceptSignedConfig("https://accounts.example", "dev_laptop", "net_private", "cfg_42", digest, 42, now); err != nil {
		t.Fatalf("accept signed config: %v", err)
	}
	if err := store.AcceptSignedConfig("https://accounts.example", "dev_laptop", "net_private", "cfg_42", digest, 42, now); err != nil {
		t.Fatalf("repeat same signed config: %v", err)
	}
	locked, err := store.IsSignedLocked("https://accounts.example", "dev_laptop", "net_private")
	if err != nil || !locked {
		t.Fatal("signed config acceptance did not persist downgrade lock")
	}
	if err := state.ValidatePermissions(store.ContractStatePath(), 0o600); err != nil {
		t.Fatalf("contract floor permissions: %v", err)
	}
	for _, test := range []struct {
		name       string
		configID   string
		digest     string
		generation uint64
	}{
		{name: "older generation", configID: "cfg_41", digest: digest, generation: 41},
		{name: "same generation different config", configID: "cfg_other", digest: digest, generation: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := store.AcceptSignedConfig("https://accounts.example", "dev_laptop", "net_private", test.configID, test.digest, test.generation, now)
			if fault.Code(err) != fault.CodeConfigReplay {
				t.Fatalf("error code = %q, err=%v", fault.Code(err), err)
			}
		})
	}
	if err := store.AcceptSignedConfig("https://accounts.example", "dev_laptop", "net_private", "cfg_42", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 42, now); err != nil {
		t.Fatalf("renewed signed config: %v", err)
	}
	if err := store.ValidateSignedConfigFloor("https://accounts.example", "dev_laptop", "net_private", "cfg_42", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 42); err != nil {
		t.Fatalf("renewed signed config floor: %v", err)
	}
}

func TestSigningKeyCacheIsScopedAndPrivate(t *testing.T) {
	store := state.NewStore(t.TempDir())
	notBefore := signedconfig.CanonicalTime{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	notAfter := signedconfig.CanonicalTime{Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	cache := state.SigningKeyCache{
		Controller: "https://accounts.example",
		DeviceID:   "dev_laptop",
		ETag:       `"keys-1"`,
		FetchedAt:  time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		Keys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{
			KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519,
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Status: "current",
			NotBefore: notBefore, NotAfter: &notAfter,
		}}},
	}
	if err := store.SaveSigningKeyCache(cache); err != nil {
		t.Fatalf("save signing key cache: %v", err)
	}
	if err := state.ValidatePermissions(store.SigningKeyCachePath(), 0o600); err != nil {
		t.Fatalf("key cache permissions: %v", err)
	}
	loaded, err := store.LoadSigningKeyCache(cache.Controller, cache.DeviceID)
	if err != nil || loaded.ETag != cache.ETag || len(loaded.Keys.Keys) != 1 {
		t.Fatalf("loaded cache = %#v, err=%v", loaded, err)
	}
	if _, err := store.LoadSigningKeyCache(cache.Controller, "dev_other"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("cross-device cache err=%v", err)
	}
}

func validEnrollmentSecret() state.EnrollmentSecret {
	notBefore := signedconfig.CanonicalTime{Time: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	notAfter := signedconfig.CanonicalTime{Time: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	return state.EnrollmentSecret{
		Controller: "https://accounts.example", DeviceID: "dev_laptop", NetworkID: "net_private", Platform: "linux",
		WireGuardPublicKey: publicKey, EnrollmentToken: "xenr_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		ExpiresAt: time.Date(2026, 8, 28, 12, 10, 0, 0, time.UTC), Scope: []string{"overlay:config:read", "overlay:config:ack", "overlay:device:revoke"},
		Device:      model.Device{ID: "dev_laptop", NetworkID: "net_private", Platform: "linux", WireGuardPublicKey: publicKey, WireGuardAddress: "10.77.0.10/32"},
		Network:     model.Network{ID: "net_private", CIDR: "10.77.0.0/16"},
		SigningKeys: signedconfig.SigningKeys{Keys: []signedconfig.SigningKey{{KeyID: "signing_key_01", Algorithm: signedconfig.SignatureEd25519, PublicKey: publicKey, Status: "current", NotBefore: notBefore, NotAfter: &notAfter}}},
		CreatedAt:   time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
	}
}
