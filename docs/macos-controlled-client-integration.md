# macOS controlled-client runtime

This document defines the standalone macOS role in the three-node XConnect One
validation topology. It is not a source merge with `xconnect-app`, and it does
not require a macOS host adapter or Packet Tunnel handoff.

## Topology

```text
XConnect Zero
  accounts: devices, networks, policy, signed configuration
  portal: administration UI
       |
       +--> XConnect One Gateway       AWS t4g.small Spot / Linux relay
       +--> XConnect One Linux client  AWS t4g.micro Spot / Linux CLI runtime
       +--> XConnect One macOS client  local Mac / standalone CLI runtime
                                      WireGuard over VLESS
```

The three entries are separate device roles in Zero. A macOS device has its own
device ID, WireGuard key pair, address allocation, signed configuration and
state directory. It never reuses a Linux device's credential or state.

## Cross-platform CLI contract

Linux, macOS and Windows ship one controlled-client contract: `join`, `sync`,
`status`, `diagnose`, `down`, and `leave` have identical control-plane and
state semantics. All platforms use the same invitation format, device-bound
credential, signed configuration verification, generation replay protection,
ACK policy, and explicit state-directory ownership.

Only the transport/runtime adapter is platform-specific. Linux and Windows
start compatible external Xray and WireGuard tools. macOS is being moved to an
explicit XConnect APP transport-provider contract: One manages its own
WireGuard interface but does not manage the APP's Xray, SOCKS5 or TUN process.
None of the adapters may introduce a platform-specific Zero API, configuration
format, enrollment state, or lifecycle vocabulary.

## Runtime ownership

XConnect-One owns Zero invitation exchange, device credential and session
renewal, signature verification, replay protection, its local WireGuard key,
configuration generation, WireGuard lifecycle, status checks and ACK
sequencing. On macOS the APP transport provider owns Xray, SOCKS5 and TUN; One
does not embed, inspect, configure, start or stop those APP processes. One runs
the compatible externally installed WireGuard userspace/kernel tools under
administrator privileges.

The CLI creates only its declared interface and files under its explicit state
directory. It must not touch existing `utun` devices, XConnect APP settings,
APP credentials, or an APP-managed VPN connection. `down` and `leave` remove
only One-owned runtime state; `leave` also revokes the remote device.

XConnect APP remains an independent product. Its macOS plugin is the future
transport provider and may launch the same CLI with a dedicated One state
directory. It must expose a versioned, loopback-only UDP relay contract bound
to the signed One configuration, but the CLI does not inspect APP state or use
a private APP API. Such composition must not change the standalone Zero
enrollment or signed-config contract. The current released macOS CLI still
uses its independent external tproxy path until this provider contract ships.

## Data path

```text
macOS XConnect-One CLI
  -> APP-owned local UDP relay
  -> APP-owned Xray/SOCKS5 or TUN transport
  -> VLESS/TLS/XUDP
  -> Gateway Xray
  -> Gateway WireGuard
  -> private network
```

The signed Zero configuration describes the Gateway transport and WireGuard
peer. The remote Gateway address is never replaced with a public WireGuard
endpoint: WireGuard traffic remains carried over VLESS.

## Lifecycle

1. Install the One binary on the command path and install compatible external
   Xray/WireGuard runtimes.
2. Issue a unique platform-specific invitation from Zero Portal.
3. Run `xconnect join`; One exchanges the invitation, creates its local key and
   fetches signed configuration.
4. Run `xconnect sync`; One validates the configuration, starts its local Xray
   and WireGuard processes, verifies local readiness, and ACKs the generation.
5. Verify a recent Gateway/client WireGuard handshake plus authorized private
   ping and HTTP.
6. Run `xconnect down` after a disposable test, or `xconnect leave` to revoke
   the device and remove One-owned local state.

## Security and acceptance

- Zero is the only authoritative source for device, policy and signed config.
- GitOps contains only non-sensitive topology, ports, role and digest metadata;
  Vault holds bootstrap and transport secrets.
- Private keys, invitations and raw signed configuration must not appear in
  command-line arguments, logs, public listeners, or shared APP state.
- A local process check is not network proof: acceptance requires the recent
  handshake and the authorized private ping/HTTP test.

| Check | Expected result |
|---|---|
| invite exchange | Separate platform device is created |
| signed config | Device, network, generation and ownership validate |
| runtime | Only the CLI-owned Xray/WireGuard profile changes |
| VLESS transport | WireGuard reaches Gateway through VLESS/TLS/XUDP |
| Zero ACK | Sent after local runtime readiness is verified |
| private path | Gateway handshake and authorized ping/HTTP succeed |
| teardown | `down` removes the One-owned overlay path |
| isolation | Linux, macOS, Windows and APP credentials/state remain separate |

For a bounded already-enrolled desktop UAT run on macOS, use
[docs/desktop-uat-verification.md](desktop-uat-verification.md). The companion
Windows script follows the same check and exit-status contract. The verifier
allows `sync` to apply the CLI-owned runtime/routes but adds no routing of its
own.
