# XConnect Zero WireGuard-over-VLESS architecture

Status: normative design for the standalone XConnect One CLI and XConnect
Gateway data path. This document separates product ownership from runtime
process ownership. It does not replace a signed configuration, create a
network, or authorize a device.

## Design rules

1. XConnect Zero `accounts` is the only authority for networks, devices,
   Gateway selection, policy, enrollment, signed configuration and ACKs.
2. XConnect Gateway is an independent Linux relay/service. It owns its local
   Gateway Xray and WireGuard runtime.
3. XConnect One is an independent Linux, macOS and Windows controlled-client
   CLI. Linux and Windows own the configuration and lifecycle of their external
   Xray and WireGuard processes. macOS owns its WireGuard lifecycle and uses an
   explicit XConnect APP transport-provider contract.
4. Xray is an external runtime, not XConnect One source code, a bundled
   library, or a separate XConnect One product. One creates and validates a
   private config for its own process; it must not modify another application's
   Xray config or process.
5. XConnect APP remains independent. Its TUN, Xray process, SOCKS listener,
   credentials, state and lifecycle are never read, written, started or
   stopped by One.
6. GitOps contains only non-sensitive deployment intent. Vault retains
   signing material, Gateway TLS private keys and other secrets. The Portal
   never receives a WireGuard private key or device credential.

## Component ownership

| Component | Owns | Does not own |
| --- | --- | --- |
| Zero `accounts` | network/device/policy records, registration approval, signed Gateway and One configs, sessions and ACK records | Xray or WireGuard processes, device private keys |
| Zero `portal` | owner-scoped management UI and BFF requests | credentials, private keys, host runtime execution |
| XConnect Gateway | Gateway enrollment, signed config verification, Gateway Xray/WireGuard files and lifecycle, peer table and ACK | Portal UI, Zero signing authority, One private keys |
| XConnect One (Linux/Windows) | registration/join/sync, signed config verification, its WireGuard key/config/lifecycle, its external Xray adapter config/lifecycle and ACK | Gateway role, Zero policy/signing, XConnect APP state or processes |
| XConnect One (macOS) | registration/join/sync, signed config verification, its WireGuard key/config/lifecycle, transport-provider binding and ACK | Gateway role, Zero policy/signing, APP Xray/SOCKS/TUN state or process lifecycle |
| External Xray | VLESS/TLS/XUDP transport for the process started by its owner | Zero data model, peer authorization, address allocation |
| WireGuard | encrypted overlay interface, peer keys, addresses and allowed routes | VLESS transport, policy issuance, identity approval |
| XConnect APP | its own UI, TUN, Xray/SOCKS/VLESS runtime and plugin host | One's state directory, One's credentials and One-owned interfaces |

## Control plane

```text
Portal → owner-scoped BFF → Accounts
                           ├─ networks / gateways / devices / policies
                           ├─ invitations / self-registration approval
                           ├─ device sessions / signed configuration
                           └─ applied-config ACK and status records
```

The controller chooses an enrolled Gateway and signs a device-bound config.
The signature binds the network, device, generation, expiry, local loopback
endpoint, VLESS/TLS transport values and WireGuard peer values. A client must
reject unsigned, expired, cross-network, cross-device or replayed config.

## Gateway runtime

The Gateway is an independent Linux service:

```text
join → session renewal → signed Gateway config sync/verify
     → render Gateway Xray + WireGuard → apply → ACK
```

Its signed config contains the overlay address, external TLS endpoint, VLESS
identity and approved One peer table:

```text
Gateway public TCP/TLS listener
  Xray VLESS inbound
       ↓
Gateway-local UDP 51820
       ↓
Gateway WireGuard interface and approved One peers
```

Gateway WireGuard stores One public keys and their assigned `/32` addresses.
It must not derive peers from GitOps, Portal input or unverified local files.

## One runtime

The same control-plane CLI contract is used on Linux, macOS and Windows:

```text
register or join → sync signed config → verify and compile
                 → bind the platform transport provider + WireGuard config
                 → start/verify WireGuard → ACK
```

`register` creates only a pending request and private local state. Before owner
approval it must not start Xray, WireGuard, alter routes, or ACK. `join` keeps
support for a short-lived formal invitation. After approval or invitation
exchange, `sync` verifies the signed config and applies the owned runtime.

One's WireGuard peer never uses the public Gateway WireGuard port directly:

```ini
Endpoint = 127.0.0.1:51830
```

On Linux and Windows this loopback endpoint belongs to One's external tproxy
process. On macOS it belongs to the APP transport provider and must be obtained
through its explicit plugin contract. It is never a public listener.

## WireGuard-over-VLESS data path

```text
XConnect One WireGuard
  ↓ encrypted UDP
One-owned external Xray adapter: 127.0.0.1:51830 (dokodemo-door UDP)
  ↓ VLESS + TLS + XUDP
Gateway external Xray: public TCP/TLS endpoint
  ↓ local UDP 51820
Gateway WireGuard
  ↓
authorized Zero Trust private network
```

WireGuard provides overlay cryptography, device keys, addresses and AllowedIPs.
Xray carries that encrypted UDP over VLESS/TLS. It does not assign addresses,
approve devices or replace the Gateway peer table.

The local adapter configuration is generated from verified signed config and is
written only under One's protected state directory. One validates the external
Xray config before start, checks that the loopback relay belongs to the process
it started, then starts WireGuard. On failure it rolls back only its own Xray
process and WireGuard interface. `down` and `leave` do not stop or delete any
APP-owned or third-party runtime.

## Platform transport profiles

The signed Zero config always binds the One WireGuard peer to a loopback relay.
Selection of the local transport provider is an explicit local deployment
choice; it is not a Portal setting and must not leak APP credentials into Zero.

### 1. Linux and Windows: independent external Xray tproxy

One writes and starts its protected external `xray/tproxy` process. It owns the
local UDP relay and uses the signed VLESS/TLS details to reach the Gateway.
This is the Linux and Windows baseline.

```text
WireGuard → One-owned Xray tproxy → VLESS/TLS/XUDP → Gateway
```

### 2. macOS: XConnect APP transport provider

On macOS, the APP plugin owns the local UDP relay and its Xray/SOCKS5/TUN
processes. One does not render or start an Xray process. It binds its WireGuard
peer to the loopback relay endpoint returned by the versioned APP provider.

```text
WireGuard → APP-owned local UDP relay → APP Xray/SOCKS5 or TUN → Gateway
```

The provider must be loopback-only, have a stable health/lifecycle signal, and
bind the exact signed Gateway transport without exposing One credentials. The
APP must avoid routing its own transport recursively; that remains APP-owned
route policy. One does not start, stop, configure or inspect the APP's Xray,
SOCKS5 or TUN process.

An APP SOCKS5 listener alone cannot be the WireGuard peer endpoint: WireGuard
sends raw UDP and does not implement SOCKS5 UDP ASSOCIATE. The macOS provider
therefore includes the APP-owned UDP-to-SOCKS5/VLESS adaptation behind its
loopback relay. Pure SOCKS5 support without that UDP adapter is insufficient.

## XConnect APP composition

XConnect APP is outside the Linux/Windows required path and is the explicit
macOS transport provider. A One plugin may start the released CLI with a
dedicated state directory using the documented local bridge protocol. This does
not merge processes or state.

The macOS provider contract must add, before this mode can ship: a protocol
version, loopback relay endpoint, provider health state, an apply/withdraw
operation bound to a signed One config generation, and explicit ownership of
the relay process. It must never expose APP credentials, raw configuration or
private keys to One. Current releases have not implemented this provider
contract; v0.1.9 still uses the independent external tproxy path on macOS.

## Acceptance evidence

| Layer | Required evidence |
| --- | --- |
| Zero | owner-scoped device and network; valid signed config |
| Gateway | verified config, Xray/WireGuard active, ACK recorded |
| One | verified config, One-owned Xray relay and WireGuard interface active, ACK recorded |
| Transport | recent handshake for the exact Gateway peer |
| Private network | authorized ping and exact HTTP marker through the overlay |
| Isolation | no APP state/process/interface was read, written, started or stopped |

A process status or ACK proves neither a current WireGuard handshake nor private
reachability. A successful UAT result requires each applicable row.
