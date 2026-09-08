# XConnect Gateway/One data plane and Zero WireGuard-over-VLESS architecture

Status: normative design for the standalone XConnect One CLI and XConnect
Gateway data path. This document separates product ownership from runtime
process ownership. It does not replace a signed configuration, create a
network, or authorize a device.

## Delivery order

The first delivery is a control-plane-free transport lab. It automates the
external runtime on Gateway, Linux One, Windows One and an opt-in macOS One,
then proves the data path before Zero enrollment is introduced:

```text
Gateway Xray server + Gateway WireGuard peers
        ↕ VLESS/TLS/XUDP
One external xray/tproxy + One WireGuard peer (per platform)
```

This lab proves runtime ownership, routing, ports, exact-peer handshakes and
private ping/HTTP. It creates no Zero device, sends no ACK, and is not an
enrollment result. Its temporary configuration is replaced—not supplemented—by
signed configuration only after the transport baseline passes.

## Design rules

1. XConnect Zero `accounts` is the only authority for networks, devices,
   Gateway selection, policy, enrollment, signed configuration and ACKs.
2. XConnect Gateway is an independent Linux relay/service. It owns its local
   Gateway Xray and WireGuard runtime.
3. XConnect One is an independent Linux, macOS and Windows controlled-client
   CLI. It owns the configuration and lifecycle of its external Xray tproxy and
   WireGuard processes on every supported desktop platform.
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
| XConnect One | registration/join/sync, signed config verification, its WireGuard key/config/lifecycle, external Xray tproxy config/lifecycle and ACK | Gateway role, Zero policy/signing, XConnect APP state or processes |
| External Xray | VLESS/TLS/XUDP transport for the process started by its owner | Zero data model, peer authorization, address allocation |
| WireGuard | encrypted overlay interface, peer keys, addresses and allowed routes | VLESS transport, policy issuance, identity approval |
| XConnect APP | its own UI, TUN, Xray/SOCKS/VLESS runtime and plugin host | One's state directory, One's credentials and One-owned interfaces |

## Phase 0: transport-lab automation

The lab creates disposable Linux Gateway and Linux/Windows One nodes with a
strict TTL. macOS uses an explicitly authorized local or self-hosted runner;
it cannot be represented truthfully by a GitHub-hosted runner without the
required administrator operations.

1. Every node generates its WireGuard private key locally in its protected
   state directory. The orchestrator exchanges public keys only.
2. Gateway starts its TLS/VLESS Xray server, WireGuard interface and exact
   `/32` peer table for each participating One.
3. Each One starts its owned external `xray/tproxy` loopback relay on
   `127.0.0.1:51830`, then its WireGuard interface whose endpoint is that
   relay—not the Gateway UDP port.
4. The pipeline checks Xray configuration and service health, the exact
   WireGuard peer handshake, a private ping, and a run-specific private HTTP
   response for each platform.
5. Failure or expiry removes only the lab-owned processes, interfaces,
   temporary TLS materials and disposable cloud nodes.

GitOps declares only non-sensitive roles, versions, instance shapes and test
CIDRs. It never contains VLESS identities, TLS private material, WireGuard
private keys or rendered peer configuration. Those values must not be emitted
to logs, artifacts or the Portal.

| Node | Automated runtime | Required evidence |
| --- | --- | --- |
| Linux Gateway | VLESS/TLS Xray server, WireGuard, One public peers, private HTTP marker | TCP/TLS listener, interface, exact peer handshakes |
| Linux One | external `xray/tproxy`, WireGuard, Gateway peer | loopback relay, interface, handshake, ping/HTTP |
| Windows One | external `xray/tproxy`, WireGuard for Windows, Gateway peer | same as Linux on a disposable Spot node |
| macOS One | external `xray/tproxy`, `wireguard-go`/WireGuard, Gateway peer | same as Linux with explicit local/admin authorization |

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
                 → render local Xray tproxy + WireGuard config
                 → validate/start Xray → start/verify WireGuard → ACK
```

`register` creates only a pending request and private local state. Before owner
approval it must not start Xray, WireGuard, alter routes, or ACK. `join` keeps
support for a short-lived formal invitation. After approval or invitation
exchange, `sync` verifies the signed config and applies the owned runtime.

One's WireGuard peer never uses the public Gateway WireGuard port directly:

```ini
Endpoint = 127.0.0.1:51830
```

This loopback endpoint belongs to One's external tproxy process on Linux,
macOS and Windows. It is never a public listener or an XConnect APP endpoint.

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

## Platform transport profile

Linux, macOS and Windows use the same independent data-plane pattern:

```text
WireGuard → One-owned external Xray tproxy → VLESS/TLS/XUDP → Gateway
```

One writes and starts its protected external `xray/tproxy` process, owns the
local UDP relay, and uses signed VLESS/TLS details to reach the Gateway. The
runtime remains external software, but its process and files belong to One's
explicit state directory.

## Future XConnect APP plugin

XConnect APP is not a current transport dependency. A future plugin may launch
the released One CLI through the documented local bridge with a dedicated state
directory. The plugin must preserve the same Zero enrollment and signed-config
contract, and must not merge or share APP and One process ownership, credentials
or state. Any future APP TUN/SOCKS5 composition is a separately versioned
extension, not a replacement for the standalone three-platform One data plane.

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

## Phase 1: replace the lab input with Zero

Once the transport lab passes, Accounts becomes the only source of the same
runtime inputs: owner-scoped network selection, enrollment, signed config,
policy and revocation. Gateway and One then verify those inputs and ACK applied
generations; the transport topology and platform ownership above do not change.
