//go:build linux || darwin

package zerolab

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cp "github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
	sc "github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

func testKey(t *testing.T) string {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func setup(t *testing.T) (*Server, *httptest.Server, Options) {
	t.Helper()
	// NewTLSServer.Client trusts only this test server certificate; no skip verification.
	var handler *Server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	seed := make([]byte, 32)
	if _, e := rand.Read(seed); e != nil {
		t.Fatal(e)
	}
	o := Options{StatePath: filepath.Join(t.TempDir(), "private", "state.json"), PublicURL: ts.URL, AdminToken: strings.Repeat("admin", 8), SigningSeed: seed, NetworkID: "net_lab", NetworkCIDR: "10.77.0.0/24", DeviceAddress: "10.77.0.2/32", GatewayPublicKey: testKey(t), GatewayHost: "gateway.lab.test", GatewayServerName: "gateway.lab.test", GatewayPort: 443, VLESSID: "11111111-2222-4333-8444-555555555555", ApplyPeer: func(context.Context, string, string) error { return nil }}
	var e error
	handler, e = New(o)
	if e != nil {
		ts.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { ts.Close(); handler.Close() })
	return handler, ts, o
}
func client(t *testing.T, ts *httptest.Server, token string) *cp.Client {
	t.Helper()
	c, e := cp.New(ts.URL, token, ts.Client())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func issue(t *testing.T, c *cp.Client) string {
	t.Helper()
	r, e := c.CreateJoinToken(t.Context(), cp.CreateJoinTokenRequest{NetworkID: "net_lab", DeviceID: "dev_lab", Platform: "linux", ExpiresInSeconds: 900})
	if e != nil {
		t.Fatal(e)
	}
	target, e := invite.Parse(r.JoinToken.JoinURI, false)
	if e != nil {
		t.Fatal(e)
	}
	return target.JoinToken
}
func exchange(t *testing.T, c *cp.Client, token string) (cp.JoinTokenExchangeRequest, cp.JoinTokenExchangeResponse) {
	t.Helper()
	q := cp.JoinTokenExchangeRequest{JoinToken: token, DeviceID: "dev_lab", Platform: "linux", WireGuardPublicKey: testKey(t)}
	r, e := c.ExchangeJoinToken(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	return q, r
}

func TestTrustedTLSJoinSyncRestartAndACK(t *testing.T) {
	s, ts, o := setup(t)
	calls := 0
	s.o.ApplyPeer = func(_ context.Context, key, address string) error {
		calls++
		if !validKey(key) || address != o.DeviceAddress {
			t.Error("bad peer binding")
		}
		return nil
	}
	admin := client(t, ts, o.AdminToken)
	c := client(t, ts, "")
	token := issue(t, admin)
	q, enrolled := exchange(t, c, token)
	if calls != 1 {
		t.Fatal("peer not installed before enrollment")
	}
	if _, e := c.ExchangeJoinToken(t.Context(), q); e == nil {
		t.Fatal("one-use invite replay succeeded")
	}
	keys, e := admin.GetSigningKeys(t.Context(), "")
	if e != nil {
		t.Fatal(e)
	}
	if next, e := admin.GetSigningKeys(t.Context(), keys.ETag); e != nil || !next.NotModified {
		t.Fatal("ETag contract failed")
	}
	cfg, e := c.GetEnrollmentSignedConfig(t.Context(), enrolled.EnrollmentToken, cp.SignedConfigRequest{DeviceID: q.DeviceID, NetworkID: o.NetworkID})
	if e != nil {
		t.Fatal(e)
	}
	if e = sc.Verify(cfg, keys.Keys, time.Now()); e != nil {
		t.Fatal(e)
	}
	compiled, e := sc.Compile(cfg)
	if e != nil || compiled.Transport.Server != o.GatewayHost || compiled.WireGuard.PeerPublicKey != o.GatewayPublicKey || compiled.WireGuard.Address != o.DeviceAddress {
		t.Fatal("real gateway binding failed")
	}
	ackQ := cp.SignedConfigAckRequest{Generation: cfg.Generation, ConfigID: cfg.ConfigID, DeviceID: q.DeviceID, AppliedAt: now()}
	if a, e := c.AckEnrollmentSignedConfig(t.Context(), enrolled.EnrollmentToken, ackQ); e != nil || !a.Acked || a.Duplicate {
		t.Fatal("first ACK failed")
	}
	if a, e := c.AckEnrollmentSignedConfig(t.Context(), enrolled.EnrollmentToken, ackQ); e != nil || !a.Duplicate {
		t.Fatal("duplicate ACK failed")
	}
	record := credential.Record{SchemaVersion: 1, Controller: ts.URL, DeviceID: q.DeviceID, NetworkID: o.NetworkID, Platform: q.Platform, WireGuardPublicKey: q.WireGuardPublicKey, CredentialID: enrolled.DeviceCredential.CredentialID, Credential: enrolled.DeviceCredential.Credential, IssuedAt: enrolled.DeviceCredential.IssuedAt, ExpiresAt: enrolled.DeviceCredential.ExpiresAt, Scope: enrolled.DeviceCredential.Scope, SigningKeys: keys.Keys}
	if e = record.Validate(); e != nil {
		t.Fatal(e)
	}
	// Keep the same TLS origin while replacing all controller state from disk.
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	restored, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	s.state = restored.state
	s.lock = restored.lock
	if _, e := c.ExchangeJoinToken(t.Context(), q); e == nil {
		t.Fatal("consumed invite replayed after restart")
	}
	sess, e := c.MintDeviceSession(t.Context(), record, cp.DeviceSessionRequest{ClientNonce: "12345678-1234-4234-8234-123456789abc"})
	if e != nil {
		t.Fatal(e)
	}
	next, e := c.GetEnrollmentSignedConfig(t.Context(), sess.EnrollmentToken, cp.SignedConfigRequest{DeviceID: q.DeviceID})
	if e != nil || next.ConfigID != cfg.ConfigID {
		t.Fatal("restart config continuity failed")
	}
	if e = sc.Verify(next, keys.Keys, time.Now()); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(o.StatePath)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{token, enrolled.EnrollmentToken, sess.EnrollmentToken, record.Credential, o.AdminToken, base64.StdEncoding.EncodeToString(o.SigningSeed)} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw auth secret leaked into state")
		}
	}
	info, e := os.Stat(o.StatePath)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state not private")
	}
	if s.state.Ack == nil {
		t.Fatal("ACK not durable")
	}
}

func TestRejectAuthBindingPeerFailureAndV2(t *testing.T) {
	s, ts, o := setup(t)
	c := client(t, ts, "")
	admin := client(t, ts, o.AdminToken)
	if _, e := c.CreateJoinToken(t.Context(), cp.CreateJoinTokenRequest{NetworkID: o.NetworkID, ExpiresInSeconds: 900}); e == nil {
		t.Fatal("unauthorized invite")
	}
	token := issue(t, admin)
	q := cp.JoinTokenExchangeRequest{JoinToken: token, DeviceID: "other_device", Platform: "linux", WireGuardPublicKey: testKey(t)}
	if _, e := c.ExchangeJoinToken(t.Context(), q); e == nil {
		t.Fatal("binding bypass")
	}
	q.DeviceID = "dev_lab"
	s.o.ApplyPeer = func(context.Context, string, string) error { return errors.New("injected failure") }
	if _, e := c.ExchangeJoinToken(t.Context(), q); e == nil {
		t.Fatal("peer failure accepted")
	}
	if s.state.Device != nil || s.state.Invite == nil {
		t.Fatal("failed peer consumed invite")
	}
	// A helper can install the peer and still fail or lose its response. The
	// durable intent must pin this address to the original key across restart.
	s.Close()
	restored, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	s.state, s.lock = restored.state, restored.lock
	other := q
	other.WireGuardPublicKey = testKey(t)
	if _, e := c.ExchangeJoinToken(t.Context(), other); e == nil {
		t.Fatal("pending peer address reassigned to another key")
	}
	s.o.ApplyPeer = o.ApplyPeer
	enrolled, e := c.ExchangeJoinToken(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := c.GetEnrollmentSignedConfig(t.Context(), enrolled.EnrollmentToken, cp.SignedConfigRequest{DeviceID: "other_device"}); e == nil {
		t.Fatal("cross-device config")
	}
	if _, e := c.GetEnrollmentSignedConfigV2(t.Context(), enrolled.EnrollmentToken, cp.SignedConfigRequest{DeviceID: q.DeviceID}); e == nil {
		t.Fatal("v2 silently downgraded")
	}
	s.state.Sessions[0].ExpiresAt = now().Add(-time.Second)
	if _, e := c.GetEnrollmentSignedConfig(t.Context(), enrolled.EnrollmentToken, cp.SignedConfigRequest{DeviceID: q.DeviceID}); e == nil {
		t.Fatal("expired session accepted")
	}
}

func TestRejectUnsafeStateAndUntrustedTLS(t *testing.T) {
	s, ts, o := setup(t)
	if _, e := http.Get(ts.URL + "/healthz"); e == nil {
		t.Fatal("untrusted CA accepted")
	}
	if _, e := New(o); e == nil {
		t.Fatal("concurrent controller accepted")
	}
	s.Close()
	if e := os.Chmod(o.StatePath, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := New(o); e == nil {
		t.Fatal("world-readable state accepted")
	}
	if e := os.Chmod(o.StatePath, 0600); e != nil {
		t.Fatal(e)
	}
	changed := o
	changed.DeviceAddress = "10.77.0.3/32"
	if _, e := New(changed); e == nil {
		t.Fatal("lease silently changed")
	}
	if e := os.Rename(o.StatePath, o.StatePath+".old"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(o.StatePath+".old", o.StatePath); e != nil {
		t.Fatal(e)
	}
	if _, e := New(o); e == nil {
		t.Fatal("symlink state accepted")
	}
}

func TestExistingGoldenSignature(t *testing.T) {
	raw, e := os.ReadFile("../../overlay/signedconfig/testdata/signed-config-ed25519-vector.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Seed      string `json:"seed_base64"`
		Payload   string `json:"signing_payload_utf8"`
		Signature string `json:"signature_base64"`
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("invalid fixture")
	}
	seed, e := base64.StdEncoding.DecodeString(v.Seed)
	if e != nil {
		t.Fatal(e)
	}
	var cfg sc.Config
	if json.Unmarshal([]byte(v.Payload), &cfg) != nil {
		t.Fatal("invalid fixture config")
	}
	payload, e := cfg.SigningBytes()
	if e != nil || string(payload) != v.Payload {
		t.Fatal("canonical bytes drift")
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload))
	if sig != v.Signature {
		t.Fatal("signature drift")
	}
}
