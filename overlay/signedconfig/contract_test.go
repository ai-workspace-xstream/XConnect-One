// Modified for XConnect-One: standalone module imports.
package signedconfig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

func TestAccountsGoldenVectorSigningBytesAndEd25519Verification(t *testing.T) {
	var vector struct {
		PublicKeyBase64    string `json:"public_key_base64"`
		KeyID              string `json:"key_id"`
		SigningPayloadUTF8 string `json:"signing_payload_utf8"`
		SignatureBase64    string `json:"signature_base64"`
	}
	raw, err := os.ReadFile("testdata/signed-config-ed25519-vector.json")
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("decode golden vector: %v", err)
	}
	config := goldenConfig()
	config.Signature = Signature{Algorithm: SignatureEd25519, KeyID: vector.KeyID, Value: vector.SignatureBase64}
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if string(payload) != vector.SigningPayloadUTF8 {
		t.Fatalf("canonical payload drifted\ngot:  %s\nwant: %s", payload, vector.SigningPayloadUTF8)
	}
	keys := signingKeys(vector.KeyID, vector.PublicKeyBase64, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := Verify(config, keys, time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("verify golden vector: %v", err)
	}
}

func TestAccountsV2GoldenVectorBindsPolicyInSignature(t *testing.T) {
	config := goldenConfig()
	config.SchemaVersion = SchemaVersionV2
	config.Policy = &Policy{Generation: 9, Digest: "58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c", Path: "/api/overlay/v1/enrollment/policy-artifacts/9/58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c", MediaType: PolicyMediaType}
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":2,"config_id":"cfg_01xconnect","network_id":"net_private","device_id":"dev_laptop","generation":42,"issued_at":"2026-08-27T12:00:00Z","expires_at":"2026-08-28T12:00:00Z","proxy_core":"xray","transport":{"kind":"vless-tls-xudp","loopback":{"host":"127.0.0.1","port":51830},"remote":{"host":"gateway.example.net","port":443,"server_name":"gateway.example.net"},"auth_id":"auth_device_01"},"wireguard":{"interface_name":"wg-xco","addresses":["10.77.0.10/32"],"mtu":1280,"peers":[{"gateway_id":"gw_tokyo_01","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.77.0.0/16"],"endpoint":{"host":"127.0.0.1","port":51830},"persistent_keepalive_seconds":25}]},"policy":{"generation":9,"digest":"58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c","path":"/api/overlay/v1/enrollment/policy-artifacts/9/58941760a9ab4568d2e72a6f34a2cede891d8e678346da8e886d86263e5b780c","media_type":"application/vnd.xconnect.policy.v1+json"}}`
	if string(payload) != want {
		t.Fatalf("v2 canonical payload drifted\ngot:  %s\nwant: %s", payload, want)
	}
	config.Signature = Signature{Algorithm: SignatureEd25519, KeyID: "signing_key_01", Value: "EJn9/iCIzWvbTRLXpyKkmvLpO4h9NznZzgRJE5zpxWfc7OEUZadhBzZaiZivnoDm7BWUYNYeMvX+fDUoZpG2AQ=="}
	keys := signingKeys("signing_key_01", "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := Verify(config, keys, time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("verify v2 interoperability vector: %v", err)
	}
	config.Policy.Path = "https://wrong.example/policy"
	if err := config.Validate(); fault.Code(err) != fault.CodeInvalidSignedConfig {
		t.Fatalf("absolute policy URL accepted: code=%q err=%v", fault.Code(err), err)
	}
}

func TestVerifyRejectsBadSignatureUnknownKeyAndLifetime(t *testing.T) {
	config, keys := signedRuntimeConfig(t)
	now := time.Date(2026, 8, 27, 12, 30, 0, 0, time.UTC)
	tests := []struct {
		name     string
		mutate   func(*Config, *SigningKeys)
		clock    time.Time
		wantCode string
	}{
		{name: "bad signature", mutate: func(config *Config, _ *SigningKeys) {
			config.Signature.Value = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}, clock: now, wantCode: fault.CodeInvalidSignature},
		{name: "unknown key", mutate: func(config *Config, _ *SigningKeys) { config.Signature.KeyID = "unknown_key_01" }, clock: now, wantCode: fault.CodeSigningKeyUnknown},
		{name: "expired", mutate: func(_ *Config, _ *SigningKeys) {}, clock: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), wantCode: fault.CodeSignedConfigExpired},
		{name: "issued in future", mutate: func(_ *Config, _ *SigningKeys) {}, clock: time.Date(2026, 8, 27, 11, 59, 59, 0, time.UTC), wantCode: fault.CodeSignedConfigFuture},
		{name: "key starts after issue", mutate: func(_ *Config, keys *SigningKeys) {
			keys.Keys[0].NotBefore = canonical(time.Date(2026, 8, 27, 12, 1, 0, 0, time.UTC))
		}, clock: now, wantCode: fault.CodeSigningKeyWindow},
		{name: "key ends before config", mutate: func(_ *Config, keys *SigningKeys) {
			expiry := canonical(time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC))
			keys.Keys[0].NotAfter = &expiry
		}, clock: now, wantCode: fault.CodeSigningKeyWindow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			candidateKeys := keys
			candidateKeys.Keys = append([]SigningKey(nil), keys.Keys...)
			test.mutate(&candidate, &candidateKeys)
			if err := Verify(candidate, candidateKeys, test.clock); fault.Code(err) != test.wantCode {
				t.Fatalf("error code=%q want=%q err=%v", fault.Code(err), test.wantCode, err)
			}
		})
	}
}

func TestStrictDecodeRejectsUnknownSecretsTrailingAndNonCanonicalTime(t *testing.T) {
	config, _ := signedRuntimeConfig(t)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	tests := []string{
		strings.Replace(string(raw), `"signature":`, `"unknown":true,"signature":`, 1),
		strings.Replace(string(raw), `"remote":{`, `"remote":{"private_key":"secret",`, 1),
		string(raw) + ` {}`,
		strings.Replace(string(raw), "2026-08-27T12:00:00Z", "2026-08-27T12:00:00.000Z", 1),
		strings.Replace(string(raw), "2026-08-27T12:00:00Z", "2026-08-27T20:00:00+08:00", 1),
	}
	for index, candidate := range tests {
		if _, err := DecodeConfig([]byte(candidate)); fault.Code(err) != fault.CodeInvalidSignedConfig {
			t.Fatalf("case %d error code=%q err=%v", index, fault.Code(err), err)
		}
	}
}

func TestCompileRequiresUUIDAndUsesFixedSameHostRelayTarget(t *testing.T) {
	golden := goldenConfig()
	golden.Signature = Signature{Algorithm: SignatureEd25519, KeyID: "signing_key_01", Value: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	if _, err := Compile(golden); fault.Code(err) != fault.CodeInvalidSignedConfig {
		t.Fatalf("non-UUID golden auth_id compiled: code=%q err=%v", fault.Code(err), err)
	}
	config, _ := signedRuntimeConfig(t)
	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("compile runtime config: %v", err)
	}
	if compiled.Revision != config.ConfigID || compiled.Transport.AuthID != config.Transport.AuthID || compiled.Transport.UUID != "" {
		t.Fatalf("unexpected compiled credential: %#v", compiled.Transport)
	}
	if compiled.Transport.ServerName != config.Transport.Remote.ServerName || compiled.WireGuard.GatewayWireGuardIP != LoopbackHost || compiled.WireGuard.GatewayWireGuardPort != RelayTargetPort || compiled.WireGuard.GatewayWireGuardCIDR != "127.0.0.1/32" {
		t.Fatalf("unexpected compiled relay target: %#v", compiled)
	}
}

func TestSigningKeysRejectsUnknownPreviousWithoutEndAndDuplicateCurrent(t *testing.T) {
	_, keys := signedRuntimeConfig(t)
	previous := keys.Keys[0]
	previous.KeyID = "previous_key_01"
	previous.Status = "previous"
	previous.NotAfter = nil
	keys.Keys = append(keys.Keys, previous)
	if err := keys.Validate(); fault.Code(err) != fault.CodeInvalidSigningKeys {
		t.Fatalf("previous key without end accepted: code=%q err=%v", fault.Code(err), err)
	}
	keys.Keys[1].Status = "current"
	if err := keys.Validate(); fault.Code(err) != fault.CodeInvalidSigningKeys {
		t.Fatalf("multiple current keys accepted: code=%q err=%v", fault.Code(err), err)
	}
}

func goldenConfig() Config {
	return Config{
		SchemaVersion: 1, ConfigID: "cfg_01xconnect", NetworkID: "net_private", DeviceID: "dev_laptop", Generation: 42,
		IssuedAt:  canonical(time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)),
		ExpiresAt: canonical(time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)),
		ProxyCore: "xray",
		Transport: Transport{Kind: "vless-tls-xudp", Loopback: Endpoint{Host: "127.0.0.1", Port: 51830}, Remote: RemoteEndpoint{Host: "gateway.example.net", Port: 443, ServerName: "gateway.example.net"}, AuthID: "auth_device_01"},
		WireGuard: WireGuard{InterfaceName: "wg-xco", Addresses: []string{"10.77.0.10/32"}, MTU: 1280, Peers: []Peer{{GatewayID: "gw_tokyo_01", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.77.0.0/16"}, Endpoint: Endpoint{Host: "127.0.0.1", Port: 51830}, PersistentKeepaliveSeconds: 25}}},
	}
}

func signedRuntimeConfig(t *testing.T) (Config, SigningKeys) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	config := goldenConfig()
	config.Transport.AuthID = "11111111-1111-1111-1111-111111111111"
	payload, err := config.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	config.Signature = Signature{Algorithm: SignatureEd25519, KeyID: "signing_key_01", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	keys := signingKeys("signing_key_01", base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	return config, keys
}

func signingKeys(keyID, publicKey string, notBefore, notAfter time.Time) SigningKeys {
	expires := canonical(notAfter)
	return SigningKeys{Keys: []SigningKey{{KeyID: keyID, Algorithm: SignatureEd25519, PublicKey: publicKey, Status: "current", NotBefore: canonical(notBefore), NotAfter: &expires}}}
}

func canonical(value time.Time) CanonicalTime {
	return CanonicalTime{Time: value.UTC().Truncate(time.Second)}
}
