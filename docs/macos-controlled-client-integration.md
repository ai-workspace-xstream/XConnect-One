# macOS controlled-client integration

This document defines the macOS role in the three-node XConnect One
validation topology. It is an integration contract, not a source merge with
`xconnect-app`.

## Topology

```text
XConnect Zero
  accounts: devices, networks, policy, signed configuration
  portal: administration UI
       |
       +--> XConnect One Gateway       AWS t4g.small Spot / Linux relay
       +--> XConnect One Linux client  AWS t4g.micro Spot / Linux CLI runtime
       +--> XConnect One macOS client  local Mac / CLI + XConnect APP plugin
                                      WireGuard over APP-owned VLESS egress
```

The three entries are separate device roles in Zero. A macOS device must have
its own device ID, WireGuard key pair, address allocation and signed
configuration. It must never reuse the Linux client's credential or state
directory.

## Ownership

### XConnect-One CLI

The independent CLI owns:

- Zero invite exchange, device credential and session renewal;
- signed configuration verification and generation replay protection;
- local WireGuard private-key generation and protected state;
- compilation of the macOS WireGuard client profile;
- desired runtime state (`sync`, `down`, `leave`) and ACK sequencing;
- a narrow local handoff to the XConnect APP plugin.

The CLI does not import Flutter code, link `libXray`, read the APP's node
database, or copy the APP's private VLESS credentials.

### XConnect APP

The APP remains an independently installable product. Its existing macOS
Packet Tunnel extension owns:

- `NETunnelProviderManager` and the user-approved system VPN boundary;
- the existing Xray/libXray VLESS egress;
- Packet Tunnel lifecycle, utun setup and native entitlements;
- user-visible permission, connection and error presentation.

The APP plugin accepts a versioned One runtime handoff. It may translate the
handoff into its existing Packet Tunnel profile, but it must not become the
source of Zero identity or policy state.

### Gateway

The Gateway is an independent Linux relay. It terminates the VLESS transport
and forwards the UDP WireGuard stream to its co-located WireGuard listener.
It does not run the macOS CLI and does not receive a macOS private key.

## Data path

The macOS path is deliberately asymmetric:

```text
macOS WireGuard client
  -> local UDP relay / APP-owned VLESS egress
  -> VLESS/TLS/XUDP
  -> Gateway Xray
  -> Gateway WireGuard
  -> private network
```

The signed Zero configuration describes the Gateway transport and the
WireGuard peer. The macOS host adapter maps those fields to the native
Packet Tunnel implementation. The remote Gateway address is never replaced
with a public WireGuard endpoint: WireGuard remains carried over VLESS.

## Handoff contract

The first implementation should use a local, permission-restricted IPC
adapter supplied by XConnect APP. The contract must contain only:

- protocol version and request ID;
- device ID, network ID and configuration generation;
- a digest of the signed configuration;
- the compiled WireGuard profile reference in an APP-group protected file;
- the VLESS egress profile reference, resolved by the APP's existing node
  store, never a copied UUID or password;
- requested action: `apply`, `down`, `status` or `cleanup`.

Private keys and raw signed configuration must not appear in command-line
arguments, process listings, logs or a public TCP listener. The APP adapter
must verify file ownership, mode, generation and digest before handing the
profile to the Packet Tunnel extension. The CLI must treat the adapter as an
external runtime and ACK only after it reports an applied generation.

The existing `app-bridge` JSONL protocol remains the optional composition
entry point. Its current `join` and `sync` calls are control-plane calls for
the independent CLI; a future macOS runtime extension may add a separately
versioned runtime method rather than changing the meaning of existing fields.

## Lifecycle

1. The user installs or updates XConnect APP and grants the Packet Tunnel
   permission once.
2. The user supplies an invite issued by Zero Portal for platform `darwin`.
3. XConnect-One exchanges the invite, generates a local WireGuard key and
   fetches the signed configuration.
4. XConnect-One writes a protected handoff and asks the APP adapter to apply
   the generation.
5. The APP configures its existing VLESS egress and Packet Tunnel boundary;
   the local WireGuard profile sends its UDP peer traffic to that egress.
6. XConnect-One checks adapter status and sends the Zero ACK.
7. `sync` repeats the signed fetch and only restarts the runtime when the
   generation or digest changes. `down` stops local data-plane ownership but
   retains enrollment. `leave` revokes the device before local cleanup.

## Security invariants

- XConnect APP and XConnect-One use separate state directories.
- Zero is the only authoritative source for device, policy and signed config.
- The APP's VLESS node database is not exported to GitOps or One state.
- GitOps may contain non-sensitive topology, ports, role and digest metadata;
  Vault remains the source for bootstrap and transport secrets.
- A macOS device receives a unique WireGuard address and peer policy.
- A local readiness result is not accepted as a network proof. Validation
  must include a recent Gateway/client WireGuard handshake and an authorized
  private ping/HTTP check.

## Acceptance matrix

| Check | Expected result |
|---|---|
| macOS invite exchange | Device is created with platform `darwin` |
| signed config | Generation, device and network ownership validate |
| WireGuard profile | Only the CLI-owned macOS profile is changed |
| VLESS reuse | APP starts/reuses its existing egress; One receives no VLESS secret |
| Packet Tunnel | APP reports the requested generation applied |
| Zero ACK | Sent only after the APP adapter confirms apply |
| private path | macOS -> VLESS -> Gateway -> WireGuard reaches authorized target |
| teardown | `down` removes the local overlay path and private target is unreachable |
| isolation | Linux and macOS credentials, addresses and state remain distinct |

The current standalone One binary does not yet implement this macOS adapter.
Until the adapter and Packet Tunnel handoff land, macOS validation is limited
to build, protocol parsing and control-plane fixtures; it must not be called a
successful private-network join.
