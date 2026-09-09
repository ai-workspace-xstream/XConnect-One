# Windows controlled-client runtime

XConnect-One ships a minimal native Windows `amd64` path for the standalone
CLI. It keeps the existing WireGuard-over-VLESS contract: the local WireGuard
peer sends UDP to `127.0.0.1:<local-port>`, the external Xray process carries
that UDP stream over VLESS/TLS to the controller-selected gateway, and the
gateway relays it to WireGuard. The generated WireGuard file is the same
standard `[Interface]`/`[Peer]` format used by the Linux runtime.

## Required software and permissions

- Run `xconnect.exe` from an elevated Builtin Administrators process. The
  runtime refuses to apply, stop, or clean up without an elevated token.
- Run `xconnect runtime bootstrap` from an administrator PowerShell to install
  or verify a native `amd64` WireGuard for Windows package that provides
  `wireguard.exe` and `wg.exe`. The CLI searches `PATH`, then the standard
  `%ProgramFiles%\WireGuard\` directory.
- Bootstrap downloads the pinned native `amd64` `xray.exe`, verifies its
  SHA256, and stores it beneath the protected One state directory. Xray must
  support the VLESS/TLS, XUDP and UDP `dokodemo-door` settings emitted by this
  repository.
- Use a dedicated local NTFS state directory. The runtime protects its
  generated directories and files with a protected DACL granting full access
  only to Local System, the owning operator, and Builtin Administrators. The
  state still contains private key material and must not be copied into backups
  or shared folders.

WireGuard for Windows' official tunnel-service CLI is used directly:

```text
wireguard.exe /installtunnelservice <interface>.conf
wireguard.exe /uninstalltunnelservice <interface>
```

The tunnel service is named `WireGuardTunnel$<interface>`. The runtime checks
that an existing service points to the expected WireGuard executable and the
exact XConnect-owned configuration before refusing or removing it. It never
uses a shell or accepts an arbitrary service name.

## Lifecycle and failure behavior

`join` and `sync` render the Xray and WireGuard files, validate Xray with
`xray.exe run -test -config`, start Xray, verify that the Xray-owned loopback
UDP socket is present, install the WireGuard tunnel service, wait for its
adapter, and run `wg.exe show`. The existing manifest/hash transaction then
controls idempotence, last-known-good rollback, `down`, and owned cleanup.

Windows process identity uses the executable path and process creation FILETIME
to avoid killing a reused PID. Process output is discarded. Command and
readiness operations have bounded contexts; a successful tunnel-service
install that fails adapter readiness receives a best-effort uninstall using
the same validated tunnel name. If that compensation cannot complete, the
service is deliberately left for operator inspection rather than guessed at.

Local readiness is not a WireGuard handshake or application reachability test.
No background supervisor, firewall/kill switch, gateway deployment, or
automatic credential refresh is included.

## Verification scope

CI runs the repository test suite on Windows and builds the release artifact
with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`. Windows-only unit tests cover
the official CLI argument mapping and tunnel-name validation without starting
an adapter or service. This extraction was not run on a Windows host, so no
real WireGuard service, Xray process, handshake, cloud controller, or
end-to-end network validation is claimed.

For a bounded already-enrolled Windows UAT run, use the companion
[desktop verification kit](desktop-uat-verification.md). It accepts an
explicit CLI path, checks the exact gateway peer handshake, and labels skipped
or unavailable checks as `UNVERIFIED` rather than treating them as a pass.
The kit permits `sync` to change the CLI-owned runtime/routes and adds no
other routing or DNS behavior.
The verifier reads `runtime.interface` for the owned WireGuard interface;
`runtime.adapter_id` remains the runtime identifier (`xray-core`) and is never
used as a `wg.exe` interface argument.
