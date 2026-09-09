# XConnect-One

XConnect-One is the independently released controlled-endpoint client for the
XConnect Zero Trust network. It receives a device-bound configuration from the
XConnect Zero API in `accounts`, generates protected local WireGuard/Xray
configuration, starts the client data plane, and verifies local readiness before
acknowledging the applied generation.

XConnect Zero owns the control plane and `portal` owns its WebUI. XConnect APP
remains independent: it may optionally invoke the versioned `app-bridge` plugin
interface, but it does not own One's CLI, protocol state machine, credentials,
or private-network runtime.

Independent Go CLI for a private WireGuard overlay carried over an external
Xray VLESS/TLS connection. Module: `github.com/ai-workspace-xstream/XConnect-One`.
This repository contains no Flutter app, FFI bridge, embedded Xray, or dependency
on a sibling checkout. It does not change or replace `xconnect-app`.

## Architecture and ownership

XConnect Zero's API and persistence belong to **Accounts**, outside this
repository. The proposed WebUI portal is **`/panel/xconnect-zero`**; it is an
architecture proposal, not a portal implemented or deployed here. XConnect-One
is the independent Linux CLI consumer of those APIs. Any integration with
`xconnect-app` is through plugin composition only, not a source merge or shared
mutable state. This extraction does not implement that plugin integration.

## Build and test

Go 1.26.4 or newer is required. All imported packages are from the standard
library; no `go.sum` or local `replace` directive is needed.

```sh
go test ./...
go vet ./...
go build -trimpath -o dist/xconnect ./cmd/xconnect
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/xconnect-linux-amd64 ./cmd/xconnect
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/xconnect-linux-arm64 ./cmd/xconnect
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o dist/xconnect-macos-arm64 ./cmd/xconnect
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o dist/xconnect-macos-amd64 ./cmd/xconnect
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o dist/xconnect-windows-amd64.exe ./cmd/xconnect
```

The CI workflow tests Linux, macOS and Windows builds, runs the race detector
and vet, and publishes their controlled-client binaries. Tests use HTTP
fixtures and injected runtime backends; they do not establish a live VPN or
change the host network.

## Linux prerequisites

Install compatible `xray`, `wg`, and `wg-quick` executables in a trusted `PATH`.
Xray must support VLESS/TLS, XUDP and a UDP `dokodemo-door` inbound. It is an
external executable, not linked into this binary; no Xray version has been
certified by this extraction. The runtime checks generated configuration using
`xray run -test -config` before activation.

The host needs WireGuard kernel support, the tools used by `wg-quick` (including
its shell and route-management tools), readable Linux `/proc`, and effective
UID 0. Merely granting network capabilities is insufficient for the current
root check. DNS settings in a legacy configuration may also require the
resolver integration used by `wg-quick`. Keep the control plane and gateway
reachable under the routes provided by the controller.

An independently deployed, compatible Accounts overlay controller must supply
enrollment, device sessions, signing keys, signed configuration and ACK APIs.
The gateway must accept the issued VLESS identity and forward its UDP traffic
to WireGuard, with this device's WireGuard public key, address, return routes
and access policy provisioned. This repository does not deploy either service.

The macOS controlled-client runtime is documented in
[docs/macos-controlled-client-integration.md](docs/macos-controlled-client-integration.md).
It uses the same external-runtime contract as Linux: One starts the signed
Xray and WireGuard processes it owns. It neither requires nor implements an
XConnect APP host adapter or Packet Tunnel handoff.

## macOS prerequisites and installation

面向自建节点的安装、加入和数据面验证见
[docs/self-hosted-install-and-validation.md](docs/self-hosted-install-and-validation.md)。
其中的 `curl https://install.svc.plus/xconnect-one | bash` 入口只安装
One CLI；Xray、WireGuard 和 Zero 邀请仍由节点管理员分别提供。

Install compatible external `xray`, `wg`, `wg-quick`, and `wireguard-go`, plus
WireGuard userspace support (for example the supported Homebrew toolchain).
Build the binary for
the host architecture, then install the checked release binary on the command
path before enrollment:

```sh
sudo install -d -m 0755 /usr/local/bin
sudo install -m 0755 dist/xconnect-macos-arm64 /usr/local/bin/xconnect
sudo /usr/local/bin/xconnect diagnose --state-dir /var/lib/xconnect-one
```

The command uses its inherited executable path to locate external runtimes.
Before running it with `sudo`, ensure the administrator environment can find
the trusted Xray and WireGuard executables (or use the deployment mechanism to
place them in an administrator-visible path). The CLI creates only its named,
owned WireGuard interface and files beneath its explicit state directory; it
does not read, alter, or rely on XConnect APP state.

## Windows prerequisites

See [docs/windows-runtime.md](docs/windows-runtime.md). Windows uses the same
CLI lifecycle and signed configuration contract as Linux and macOS, but
requires an elevated native `amd64` process, external `xray.exe`, and WireGuard
for Windows' `wireguard.exe` and `wg.exe`. The CLI does not install or update
those external runtimes.

## Bounded desktop UAT verification

For an already-enrolled macOS or Windows client, the repository includes a
bounded verification kit in [docs/desktop-uat-verification.md](docs/desktop-uat-verification.md).
It accepts an explicit CLI binary path and dedicated state directory, then
checks `sync`, exact device/network identity in owned `status`, external
runtime presence, the exact gateway WireGuard peer's latest handshake, one
literal overlay target, and one HTTP response marker. It reports `PASS`,
`FAIL`, or `UNVERIFIED`; it does not join, install runtimes, change DNS, add
routing beyond the CLI's `sync`, or use remote execution.

## One self-registration

The standalone binary supports invite-free, owner-credential-free
self-registration on Linux, macOS and Windows. See
[docs/self-registration.md](docs/self-registration.md) for the HTTPS contract,
private resumable state, pending safety boundary, and usage of
`xconnect register --controller ... --network ...`. Pending registration never
starts an external runtime; approval reuses the formal signed-config, apply,
and ACK enrollment path.

## Enroll, sync, and connect

Run these commands on the Linux host after installing the built binary as
`/usr/local/bin/xconnect`. Replace the invite with one issued by your controller.
Use the same explicit **absolute** state directory and operating user for every
command. Do not share that directory with another installation or the app.

```sh
sudo /usr/local/bin/xconnect join --state-dir /var/lib/xconnect-one \
  --device-id private-laptop --name private-laptop \
  'xconnect://join/REPLACE_WITH_ISSUED_TOKEN?controller=https%3A%2F%2Fcontroller.example'

sudo /usr/local/bin/xconnect sync --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect status --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect diagnose --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect down --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect sync --state-dir /var/lib/xconnect-one
```

The invite is a one-time secret: avoid exposing it in shell history, shared
terminal recordings or process listings. Invite enrollment is the durable
device-credential path needed for subsequent `sync`. The token above is a
placeholder, not a usable invitation.

Both `join` and `sync` apply the configuration and start the tunnel. There is
no separate `generate` command or offline export mode. The sync sequence is:

1. Load the bound device credential and obtain/reuse an enrollment session.
2. Fetch, verify and compile signed configuration, enforcing the generation floor.
3. Generate private Xray/WireGuard files, validate Xray, start Xray, verify its
   loopback socket ownership, run `wg-quick up`, and check `wg show`.
4. Read back local runtime state, send the application ACK, and persist state.

An already-current healthy revision avoids restarting the runtime. Cached `up`
is disabled and returns an error requiring `sync`, because saved compiled state
cannot prove current signature expiry and may predate an unacknowledged active
revision. `down` retains enrollment state; use `sync` to verify and restart.

For a controller that supports policy-bound SignedConfig v2, opt in explicitly:

```sh
sudo /usr/local/bin/xconnect sync --signed-config-v2 --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect credential rotate --state-dir /var/lib/xconnect-one
sudo /usr/local/bin/xconnect leave --state-dir /var/lib/xconnect-one
```

The v2 option must be supplied on each sync; it is not a persisted CLI preference.
V2 requests do not fall back if the server lacks that capability. Normal `leave`
uses the device credential to request revocation before local cleanup; a receipt
can report that gateway policy reconciliation is still pending. `leave
--local-only` removes local owned state without revoking the remote device.

Account-token enrollment remains available through `join --server URL
--token-file PATH --config-contract signed`, with optional `--network-id` and
`--node-id`. It is a compatibility path and does not itself provide the durable
invite credential required by `sync`. The inherited default server is
`https://accounts.svc.plus`; specify your own controller explicitly. Account
commands also accept `XCONNECT_TOKEN`, but a protected token file avoids relying
on environment preservation across `sudo`.

Other inherited commands are `admin invite create` and `policy explain` (both
use account credentials). Subcommands accept `-h` to print flags, although the
inherited flag handler returns a nonzero exit status for help. Successful
commands produce JSON; errors use `error[code]` and exit status 1.

## Security and stored state

The extraction retains Ed25519 signature verification, configuration ownership
and expiry checks on fetch, generation/digest replay protection, session proofs,
credential rotation recovery, revocation replay state, operation locks and
runtime identity checks. Invites require signed configuration. Account-token
`join` defaults to `auto`, which permits legacy fallback only on the specific
signed-capability-unavailable error before the signed contract is locked. Use
`--config-contract signed` to require signatures on that compatibility path.
Use HTTPS: the generic account client still accepts HTTP URLs; strict invite
validation permits HTTP only for explicit localhost development.

Linux credentials are permission-protected plaintext files, not a hardware
keystore or encrypted vault. Treat the entire state directory and its backups
as secrets. Important files include `protected/device-credential.json`,
`state.json` (including the local WireGuard private key), signing/contract state,
and temporary enrollment/operation records. Runtime artifacts are stored under
`runtime/revisions/<revision-hash>-<random>/xray.json` and `<interface>.conf`.
Files use mode 0600 and runtime directories 0700. Active and last-known-good
manifests retain process identity and configuration hashes for rollback and
owned-resource cleanup. Never edit generated files while the runtime is active.

## Actual limitations

- **Local readiness is not connectivity.** `status`, `diagnose` and ACK success
  establish process/socket/interface readiness, not a WireGuard handshake,
  reachable peer, working DNS, correct remote policy, or internet access.
  Verify the configured interface with `wg show <interface> latest-handshakes`
  and test an authorized private service from the client. A fresh handshake
  alone still does not establish application reachability.
- The signed compiler supports exactly one address and one gateway peer. It
  sends WG UDP to local Xray, then VLESS/TLS to the remote gateway. For signed
  config the remote relay target is fixed at **127.0.0.1:51820 on the gateway**;
  Xray and WireGuard must be co-hosted in the appropriate network namespace.
  Arbitrary mesh discovery, gateway deployment and multi-peer compilation are
  not implemented.
- Only controller-supplied `AllowedIPs` are routed by `wg-quick`. There is no
  universal full-tunnel or DNS-leak guarantee, automatic endpoint route
  exemption, or kill switch. The signed compiler currently supplies no DNS
  settings. Private-network reachability requires gateway forwarding and
  return routing to be configured outside this CLI.
- V2 validates the signed policy reference, artifact digest, expiry and replay
  floor and records accepted policy metadata. It does **not** install a local
  firewall or verify gateway ACL enforcement. Gateway enforcement remains an
  external requirement; a policy-bound ACK is not proof that ACLs are active.
- Signature expiry is checked when fetching. Cached `up` is disabled; use
  `sync` to fetch and verify configuration. No background process refreshes
  configuration, stops an expired tunnel, retries sync, or supervises Xray.
  Arrange refresh and revocation enforcement operationally.
- Runtime apply rollback covers local activation failures. A later ACK or
  state-persistence failure can leave a newly active runtime with older saved
  state; do not interpret every failed sync as a stopped tunnel. Inspect status
  and retry after resolving the error. V1 advances its signed floor before
  apply; v2 advances after runtime readback and ACK, preserving upstream behavior.
- Startup refuses any existing interface with the requested name. A failed
  `wg-quick up` never triggers a blind `wg-quick down`. Cleanup checks trusted
  files and the recorded Linux interface index, and runs even after Xray dies
  or loses its listener. Replaced interfaces, stale PID identities and old
  manifests lacking interface identity fail closed and require operator review.
  External network managers must not concurrently modify these interfaces:
  inspection plus external `wg-quick` execution is not an atomic kernel lease.
  Failed or interrupted startup can leave an unowned partial interface requiring
  manual inspection; automatic deletion is deliberately refused. `wg-quick`
  itself may perform its own failure cleanup.
- macOS is a supported external-runtime controlled-client CLI. It requires a
  root-launched Xray binary plus compatible `wg`, `wg-quick`, and WireGuard
  userspace/kernel support (for example the supported Homebrew toolchain). It
  does not use XConnect APP state. The APP may optionally host the same CLI as
  a plugin, but that plugin mode does not change the standalone CLI contract.
- Windows is a supported native `amd64` external-runtime controlled-client.
  It manages only its named WireGuard tunnel service and protected state; see
  [docs/windows-runtime.md](docs/windows-runtime.md). Mobile tunnel hosts are
  not shipped.
- Real Linux Xray/WireGuard execution and end-to-end networking were not tested
  during extraction on the macOS development host. Passing tests and Linux
  cross-builds are not live-network certification. Runtime subprocess output
  is discarded to avoid exposing secrets, limiting failure diagnostics.

See [PROVENANCE.md](PROVENANCE.md) for the exact source and extraction changes.
Distributed under [Apache-2.0](LICENSE); external runtimes have their own licenses.
