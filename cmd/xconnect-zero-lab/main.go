//go:build linux || darwin

// xconnect-zero-lab is a temporary integration fixture, not the production Zero API.
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/ai-workspace-xstream/XConnect-One/internal/zerolab"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "experimental Zero lab startup or serve failed; check protected configuration and listener")
		os.Exit(1)
	}
}
func run() error {
	var o zerolab.Options
	var listen, cert, key, admin, seed, vless, peer string
	flag.StringVar(&listen, "listen", ":8443", "HTTPS listen address")
	flag.StringVar(&o.PublicURL, "public-url", "", "externally reachable HTTPS origin")
	flag.StringVar(&o.StatePath, "state", "", "JSON state in dedicated owner-only directory")
	flag.StringVar(&cert, "tls-cert", "", "PEM server certificate signed by trusted lab CA")
	flag.StringVar(&key, "tls-key", "", "protected PEM server key")
	flag.StringVar(&admin, "admin-token-file", "", "Vault-injected 0600 bootstrap token file")
	flag.StringVar(&seed, "signing-key-file", "", "Vault-injected 0600 base64 Ed25519 seed file")
	flag.StringVar(&vless, "vless-id-file", "", "Vault-injected 0600 VLESS UUID file")
	flag.StringVar(&o.NetworkID, "network-id", "", "lab network ID")
	flag.StringVar(&o.NetworkCIDR, "network-cidr", "", "real allocated overlay IPv4 CIDR")
	flag.StringVar(&o.DeviceAddress, "device-address", "", "real allocated device IPv4 /32")
	flag.StringVar(&o.GatewayPublicKey, "gateway-public-key", "", "actual gateway WireGuard public key")
	flag.StringVar(&o.GatewayHost, "gateway-host", "", "actual Xray TLS gateway host/IP")
	flag.IntVar(&o.GatewayPort, "gateway-port", 443, "actual Xray TLS port")
	flag.StringVar(&o.GatewayServerName, "gateway-server-name", "", "gateway TLS certificate SAN")
	flag.StringVar(&peer, "peer-command", "", "absolute idempotent peer helper; arguments PUBLIC_KEY ADDRESS")
	flag.Parse()
	if o.StatePath == "" || cert == "" || key == "" || peer == "" {
		return fmt.Errorf("missing required files")
	}
	var e error
	if o.AdminToken, e = zerolab.ReadSecret(admin); e != nil {
		return e
	}
	if o.VLESSID, e = zerolab.ReadSecret(vless); e != nil {
		return e
	}
	encoded, e := zerolab.ReadSecret(seed)
	if e != nil {
		return e
	}
	o.SigningSeed, e = base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return fmt.Errorf("invalid signing seed")
	}
	// Validate key permissions separately, without reading it into log output.
	if _, e = zerolab.ReadSecret(key); e != nil {
		return e
	}
	o.ApplyPeer = zerolab.CommandPeerUpdater(peer)
	handler, e := zerolab.New(o)
	if e != nil {
		return e
	}
	defer handler.Close()
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ErrorLog: log.New(io.Discard, "", 0)}
	fmt.Fprintln(os.Stderr, "experimental Zero lab HTTPS controller starting")
	return server.ListenAndServeTLS(cert, key)
}
