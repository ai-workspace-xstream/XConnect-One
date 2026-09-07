//go:build linux || darwin

// Package zerolab is an experimental, single-device integration fixture.
// Production Zero API and persistence belong in Accounts, not this package.
package zerolab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	cp "github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
	sc "github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
)

type Options struct {
	StatePath, PublicURL, AdminToken                          string
	SigningSeed                                               []byte
	NetworkID, NetworkCIDR, DeviceAddress                     string
	GatewayPublicKey, GatewayHost, GatewayServerName, VLESSID string
	GatewayPort                                               int
	// ApplyPeer must be idempotent and return only after the real gateway accepts it.
	ApplyPeer func(context.Context, string, string) error
}

type inviteState struct {
	Hash, ID, DeviceID, Platform string
	ExpiresAt                    time.Time
}
type sessionState struct {
	Hash      string
	ExpiresAt time.Time
}
type diskState struct {
	Version                                 int
	Binding                                 string
	SigningKey                              sc.SigningKey
	Invite                                  *inviteState
	Device                                  *model.Device
	PendingPeerBinding                      string
	CredentialID, CredentialHash            string
	CredentialIssuedAt, CredentialExpiresAt time.Time
	Sessions                                []sessionState
	Config                                  *sc.Config
	Ack                                     *cp.SignedConfigAck
}

type Server struct {
	mu     sync.Mutex
	o      Options
	state  diskState
	lock   *os.File
	failed bool
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
var noncePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var enrollmentScopes = []string{"overlay:config:read", "overlay:config:ack", "overlay:device:revoke"}
var deviceScopes = []string{credential.ScopeSessionMint, credential.ScopeRotate, credential.ScopeDeviceRevoke}
var errState = errors.New("lab state unavailable or unsafe")

// ReadSecret accepts only an owner-only regular file; errors never include its contents.
func ReadSecret(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !privateFile(info) {
		return "", errors.New("secret file must be owner-owned regular mode 0600")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return "", errors.New("cannot read secret file")
	}
	return strings.TrimSpace(string(raw)), nil
}
func privateFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && owned(info)
}
func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
func hash(s string) string   { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func now() time.Time         { return time.Now().UTC().Truncate(time.Second) }
func opaque(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func validKey(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s && !equal(s, base64.StdEncoding.EncodeToString(make([]byte, 32)))
}
func validPlatform(s string) bool {
	return s == "linux" || s == "darwin" || s == "windows" || s == "ios" || s == "android"
}

// CommandPeerUpdater executes a provisioned helper without a shell or secret logs.
func CommandPeerUpdater(path string) func(context.Context, string, string) error {
	return func(ctx context.Context, key, address string) error {
		if !filepath.IsAbs(path) || !validKey(key) {
			return errors.New("invalid peer helper input")
		}
		p, e := netip.ParsePrefix(address)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return errors.New("invalid peer address")
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, path, key, address).Run() != nil {
			return errors.New("gateway peer update failed")
		}
		return nil
	}
}

func New(o Options) (*Server, error) {
	u, e := url.Parse(o.PublicURL)
	n, ne := netip.ParsePrefix(o.NetworkCIDR)
	a, ae := netip.ParsePrefix(o.DeviceAddress)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || len(o.AdminToken) < 32 || len(o.SigningSeed) != 32 || !idPattern.MatchString(o.NetworkID) || ne != nil || ae != nil || !n.Addr().Is4() || n != n.Masked() || !a.Addr().Is4() || a.Bits() != 32 || !n.Contains(a.Addr()) || !validKey(o.GatewayPublicKey) || o.GatewayHost == "" || o.GatewayServerName == "" || o.GatewayPort < 1 || o.GatewayPort > 65535 || !uuidPattern.MatchString(o.VLESSID) || o.ApplyPeer == nil {
		return nil, errors.New("invalid explicit lab configuration")
	}
	dir := filepath.Dir(o.StatePath)
	if os.MkdirAll(dir, 0700) != nil {
		return nil, errState
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return nil, errState
	}
	lockPath := o.StatePath + ".lock"
	if info, e := os.Lstat(lockPath); e == nil && !privateFile(info) {
		return nil, errState
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, errState
	}
	lock, e := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, errState
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("lab state already in use")
	}
	s := &Server{o: o, lock: lock}
	// Bind immutable topology and injected secrets so restart cannot silently reassign a lease/key.
	s.state.Binding = hash(strings.Join([]string{o.PublicURL, o.NetworkID, o.NetworkCIDR, o.DeviceAddress, o.GatewayPublicKey, o.GatewayHost, fmt.Sprint(o.GatewayPort), o.GatewayServerName, o.VLESSID, base64.StdEncoding.EncodeToString(o.SigningSeed)}, "\x00"))
	binding := s.state.Binding
	if info, e := os.Lstat(o.StatePath); e == nil {
		if !privateFile(info) {
			s.Close()
			return nil, errState
		}
		raw, e := os.ReadFile(o.StatePath)
		if e != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &s.state) != nil || s.state.Version != 1 || s.state.Binding != binding {
			s.Close()
			return nil, errState
		}
	} else if errors.Is(e, os.ErrNotExist) {
		pub := ed25519.NewKeyFromSeed(o.SigningSeed).Public().(ed25519.PublicKey)
		s.state.Version = 1
		s.state.SigningKey = sc.SigningKey{KeyID: "lab_" + hash(string(pub))[:24], Algorithm: sc.SignatureEd25519, PublicKey: base64.StdEncoding.EncodeToString(pub), Status: "current", NotBefore: sc.CanonicalTime{Time: now().Add(-time.Minute)}}
		if s.save() != nil {
			s.Close()
			return nil, errState
		}
	} else {
		s.Close()
		return nil, errState
	}
	if (sc.SigningKeys{Keys: []sc.SigningKey{s.state.SigningKey}}).Validate() != nil {
		s.Close()
		return nil, errState
	}
	return s, nil
}

func (s *Server) Close() error {
	if s.lock != nil {
		e := s.lock.Close()
		s.lock = nil
		return e
	}
	return nil
}
func (s *Server) save() error {
	raw, e := json.Marshal(s.state)
	if e != nil {
		return errState
	}
	f, e := os.CreateTemp(filepath.Dir(s.o.StatePath), ".zero-state-")
	if e != nil {
		return errState
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		return errState
	}
	if f.Sync() != nil {
		return errState
	}
	if f.Close() != nil {
		return errState
	}
	if os.Rename(f.Name(), s.o.StatePath) != nil {
		return errState
	}
	dir, e := os.Open(filepath.Dir(s.o.StatePath))
	if e != nil {
		return errState
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errState
	}
	return nil
}
func (s *Server) commit(w http.ResponseWriter) bool {
	if s.save() != nil {
		s.failed = true
		fail(w, 503)
		return false
	}
	return true
}
func fail(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"lab request rejected"}`)
}
func respond(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400)
		return false
	}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil {
		fail(w, 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		fail(w, 503)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/overlay/v1")
	if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/api/overlay/v1/") {
		fail(w, 404)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/healthz":
		respond(w, map[string]string{"status": "ok", "mode": "experimental-zero-lab"})
	case r.Method == "POST" && path == "/join-tokens":
		s.createInvite(w, r)
	case r.Method == "POST" && path == "/join-tokens/exchange":
		s.exchange(w, r)
	case r.Method == "POST" && path == "/device/session":
		s.session(w, r)
	case r.Method == "GET" && path == "/enrollment/signed-config":
		s.config(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/enrollment/signed-config/") && strings.HasSuffix(path, "/ack"):
		s.ack(w, r, path)
	case r.Method == "GET" && path == "/signing-keys":
		if !equal(hash(r.Header.Get("Authorization")), hash("Bearer "+s.o.AdminToken)) && !s.authorized(r) {
			fail(w, 401)
			return
		}
		w.Header().Set("Cache-Control", "private, max-age=300")
		w.Header().Set("Vary", "Authorization")
		w.Header().Set("ETag", `"`+s.state.SigningKey.KeyID+`"`)
		if r.Header.Get("If-None-Match") == w.Header().Get("ETag") {
			w.WriteHeader(304)
			return
		}
		respond(w, sc.SigningKeys{Keys: []sc.SigningKey{s.state.SigningKey}})
	default:
		fail(w, 404)
	}
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	if !equal(hash(r.Header.Get("Authorization")), hash("Bearer "+s.o.AdminToken)) {
		fail(w, 401)
		return
	}
	var q cp.CreateJoinTokenRequest
	if !decode(w, r, &q) {
		return
	}
	if q.NetworkID != s.o.NetworkID || q.DeviceID != "" && !idPattern.MatchString(q.DeviceID) || q.Platform != "" && !validPlatform(q.Platform) || q.ExpiresInSeconds < 1 || q.ExpiresInSeconds > 86400 {
		fail(w, 400)
		return
	}
	if s.state.Device != nil || s.state.PendingPeerBinding != "" {
		fail(w, 409)
		return
	}
	token, e := opaque("xjt_")
	if e != nil {
		fail(w, 503)
		return
	}
	inv := &inviteState{Hash: hash(token), ID: "join_" + hash(token)[:24], DeviceID: q.DeviceID, Platform: q.Platform, ExpiresAt: now().Add(time.Duration(q.ExpiresInSeconds) * time.Second)}
	s.state.Invite = inv
	if !s.commit(w) {
		return
	}
	respond(w, cp.CreateJoinTokenResponse{JoinToken: cp.JoinToken{ID: inv.ID, JoinURI: "xconnect://join/" + token + "?controller=" + url.QueryEscape(s.o.PublicURL), NetworkID: s.o.NetworkID, DeviceID: q.DeviceID, Platform: q.Platform, RemainingUses: 1, ExpiresAt: inv.ExpiresAt}})
}
func (s *Server) newSession() (string, error) {
	token, e := opaque("xenr_")
	if e != nil {
		return "", e
	}
	sessions := []sessionState{}
	for _, v := range s.state.Sessions {
		if v.ExpiresAt.After(now()) {
			sessions = append(sessions, v)
		}
	}
	if len(sessions) >= 32 {
		sessions = sessions[len(sessions)-31:]
	}
	s.state.Sessions = append(sessions, sessionState{Hash: hash(token), ExpiresAt: now().Add(15 * time.Minute)})
	return token, nil
}
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	var q cp.JoinTokenExchangeRequest
	if !decode(w, r, &q) {
		return
	}
	inv := s.state.Invite
	if inv == nil || !inv.ExpiresAt.After(now()) || !equal(hash(q.JoinToken), inv.Hash) {
		fail(w, 401)
		return
	}
	if s.state.Device != nil {
		fail(w, 409)
		return
	}
	if !idPattern.MatchString(q.DeviceID) || !validPlatform(q.Platform) || !validKey(q.WireGuardPublicKey) || len(q.Name) > 255 || len(q.Hostname) > 255 || inv.DeviceID != "" && inv.DeviceID != q.DeviceID || inv.Platform != "" && inv.Platform != q.Platform {
		fail(w, 403)
		return
	}
	secret, e := credential.Generate()
	if e != nil {
		fail(w, 503)
		return
	}
	peerBinding := hash(q.DeviceID + "\x00" + q.Platform + "\x00" + q.WireGuardPublicKey)
	if s.state.PendingPeerBinding != "" && s.state.PendingPeerBinding != peerBinding {
		fail(w, 409)
		return
	}
	// Persist intent before the external update. Crash recovery cannot assign
	// this same address to a different key while an earlier peer may exist.
	s.state.PendingPeerBinding = peerBinding
	if !s.commit(w) {
		return
	}
	// Helper must be idempotent: a lost HTTP response or disk failure may require an operator retry.
	if s.o.ApplyPeer(r.Context(), q.WireGuardPublicKey, s.o.DeviceAddress) != nil {
		fail(w, 503)
		return
	}
	t := now()
	s.state.Device = &model.Device{ID: q.DeviceID, NetworkID: s.o.NetworkID, Name: q.Name, Platform: q.Platform, Hostname: q.Hostname, WireGuardPublicKey: q.WireGuardPublicKey, WireGuardAddress: s.o.DeviceAddress, CreatedAt: t, UpdatedAt: t}
	s.state.CredentialID = secret.CredentialID
	s.state.CredentialHash, _ = credential.Verifier(secret.Value)
	s.state.CredentialIssuedAt = t
	s.state.CredentialExpiresAt = t.Add(30 * 24 * time.Hour)
	s.state.Invite = nil
	s.state.PendingPeerBinding = ""
	token, e := s.newSession()
	if e != nil {
		s.failed = true
		fail(w, 503)
		return
	}
	if !s.commit(w) {
		return
	}
	respond(w, cp.JoinTokenExchangeResponse{EnrollmentToken: token, TokenType: "Bearer", ExpiresAt: t.Add(15 * time.Minute), Scope: enrollmentScopes, DeviceCredential: cp.DeviceCredential{CredentialID: secret.CredentialID, Credential: secret.Value, TokenType: credential.TokenType, IssuedAt: t, ExpiresAt: s.state.CredentialExpiresAt, Scope: deviceScopes}, Device: *s.state.Device, Network: model.Network{ID: s.o.NetworkID, DisplayName: "Experimental lab", CIDR: s.o.NetworkCIDR}, SigningKeys: []sc.SigningKey{s.state.SigningKey}})
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	value := strings.TrimPrefix(r.Header.Get("Authorization"), "Device ")
	verifier, e := credential.Verifier(value)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Device ") || e != nil || s.state.Device == nil || !s.state.CredentialExpiresAt.After(now()) || !equal(verifier, s.state.CredentialHash) {
		fail(w, 401)
		return
	}
	var q cp.DeviceSessionRequest
	if !decode(w, r, &q) {
		return
	}
	if !noncePattern.MatchString(q.ClientNonce) {
		fail(w, 400)
		return
	}
	token, e := s.newSession()
	if e != nil {
		fail(w, 503)
		return
	}
	if !s.commit(w) {
		return
	}
	respond(w, cp.DeviceSessionResponse{ClientNonce: q.ClientNonce, EnrollmentToken: token, TokenType: "Bearer", IssuedAt: now(), ExpiresAt: s.state.Sessions[len(s.state.Sessions)-1].ExpiresAt, Scope: []string{"overlay:config:read", "overlay:config:ack"}, DeviceID: s.state.Device.ID, NetworkID: s.o.NetworkID, SigningKeys: []sc.SigningKey{s.state.SigningKey}})
}
func (s *Server) authorized(r *http.Request) bool {
	if s.state.Device == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	h := hash(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	for _, v := range s.state.Sessions {
		if equal(h, v.Hash) && v.ExpiresAt.After(now()) {
			return true
		}
	}
	return false
}
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401)
		return
	}
	q := r.URL.Query()
	if q.Get("device_id") != s.state.Device.ID || q.Get("network_id") != "" && q.Get("network_id") != s.o.NetworkID || q.Get("node_id") != "" && q.Get("node_id") != "gw_lab" {
		fail(w, 403)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), cp.SignedConfigV2MediaType) {
		fail(w, 406)
		return
	}
	// Reconcile after gateway reboot before handing out usable configuration.
	if s.o.ApplyPeer(r.Context(), s.state.Device.WireGuardPublicKey, s.o.DeviceAddress) != nil {
		fail(w, 503)
		return
	}
	if s.state.Config == nil || !s.state.Config.ExpiresAt.After(now().Add(5*time.Minute)) {
		gen := uint64(1)
		if s.state.Config != nil {
			gen = s.state.Config.Generation + 1
		}
		loop := sc.Endpoint{Host: "127.0.0.1", Port: 51830}
		c := sc.Config{SchemaVersion: 1, ConfigID: fmt.Sprintf("cfg_lab_%d", gen), NetworkID: s.o.NetworkID, DeviceID: s.state.Device.ID, Generation: gen, IssuedAt: sc.CanonicalTime{Time: now()}, ExpiresAt: sc.CanonicalTime{Time: now().Add(time.Hour)}, ProxyCore: sc.ProxyCoreXray, Transport: sc.Transport{Kind: sc.TransportVLESS, Loopback: loop, Remote: sc.RemoteEndpoint{Host: s.o.GatewayHost, Port: s.o.GatewayPort, ServerName: s.o.GatewayServerName}, AuthID: s.o.VLESSID}, WireGuard: sc.WireGuard{InterfaceName: "wg-xco", Addresses: []string{s.o.DeviceAddress}, MTU: 1280, Peers: []sc.Peer{{GatewayID: "gw_lab", PublicKey: s.o.GatewayPublicKey, AllowedIPs: []string{s.o.NetworkCIDR}, Endpoint: loop, PersistentKeepaliveSeconds: 25}}}, Signature: sc.Signature{Algorithm: sc.SignatureEd25519, KeyID: s.state.SigningKey.KeyID}}
		payload, e := c.SigningBytes()
		if e != nil {
			fail(w, 503)
			return
		}
		c.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(s.o.SigningSeed), payload))
		if _, e := sc.Compile(c); e != nil {
			fail(w, 503)
			return
		}
		s.state.Config = &c
		s.state.Ack = nil
		if !s.commit(w) {
			return
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("ETag", fmt.Sprintf(`"lab-%d"`, s.state.Config.Generation))
	respond(w, s.state.Config)
}
func (s *Server) ack(w http.ResponseWriter, r *http.Request, path string) {
	if !s.authorized(r) {
		fail(w, 401)
		return
	}
	var q struct {
		ConfigID  string    `json:"config_id"`
		DeviceID  string    `json:"device_id"`
		AppliedAt time.Time `json:"applied_at"`
	}
	if !decode(w, r, &q) {
		return
	}
	c := s.state.Config
	if c == nil || path != fmt.Sprintf("/enrollment/signed-config/%d/ack", c.Generation) || q.ConfigID != c.ConfigID || q.DeviceID != s.state.Device.ID || q.AppliedAt.IsZero() || q.AppliedAt.Location() != time.UTC || q.AppliedAt.Nanosecond() != 0 || q.AppliedAt.After(now().Add(30*time.Second)) {
		fail(w, 409)
		return
	}
	duplicate := s.state.Ack != nil
	if !duplicate {
		s.state.Ack = &cp.SignedConfigAck{DeviceID: q.DeviceID, ConfigID: q.ConfigID, Generation: c.Generation, AppliedAt: q.AppliedAt, ReceivedAt: now()}
		if !s.commit(w) {
			return
		}
	}
	respond(w, cp.SignedConfigAckResponse{Acked: true, Duplicate: duplicate, Ack: *s.state.Ack})
}
