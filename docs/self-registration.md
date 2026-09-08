# One self-registration

The standalone `xconnect` binary supports the same self-registration command
on Linux, macOS and Windows:

```text
xconnect register --controller https://accounts.example \
  --network net_public --state-dir /path/to/private/state
```

`--controller` must be HTTPS. `--network` is the public network ID. `--device-id`
and `--name` are optional local identity overrides; the default device ID is
derived from the platform and hostname. Self-registration has no invite-token,
owner-credential, token-file, or environment-token input.

The command generates one X25519 WireGuard key pair and stores a resumable
`registration.json` in the state directory. The state directory is private
(0700 where supported) and the file is written atomically with mode 0600. The
registration bearer and the approved exchange response remain only in that
file; neither is printed, logged, placed in a URL, or passed as a command-line
argument. A failed request or cancellation preserves the existing registration
state and key.

The controller first receives a pending registration. While the exchange is
pending, One performs only bounded HTTPS polling and local state I/O: it does
not invoke Xray, WireGuard, `wg-quick`, routes, DNS, or an ACK. Polling is at
least five seconds apart with bounded backoff, is cancellation-aware, and never
extends the controller's original 15-minute registration expiry.

After the registration is created or resumed, progress is written to stderr
using only the registration ID, device ID, network ID, UTC expiry, and the
lowercase SHA-256 hex fingerprint of the 32 raw bytes decoded from the
canonical padded-Standard-Base64 WireGuard public key. The message tells the
operator to approve the device in Zero. The registration and private key are
never included.

After approval, the existing enrollment path is reused: the exact exchange
response is staged privately, the signed config is verified and compiled, the
selected external runtime applies it, and the existing signed-config ACK and
LastKnown state commit complete the join. A completed registration clears the
temporary registration and enrollment state. A rejected, consumed, expired,
or invalid-token response exits with its stable registration error and never
starts the runtime. An already-joined local state is rejected before creating a
new registration. Once the approved exchange handoff has been durably written,
the local state can resume without exchanging the consumed registration token
again. There remains a narrow crash window between receiving HTTP 200 and
persisting that approved handoff; this client cannot recover from a crash in
that window and does not claim universal crash recovery.

The binary manages the external runtime contract; it does not install or
update Xray or WireGuard. Runtime prerequisites and privilege requirements are
platform-specific and are documented in the existing Linux, macOS and Windows
runtime guides. This feature does not add host adapters, GUI code, PacketTunnel
code, broad DNS/routes, or changes to the existing invite `join` command.

## Controller contract

Create:

```http
POST /api/overlay/v1/registrations
Content-Type: application/json
```

The body contains only `network_id`, `device_id`, optional `name` and
`hostname`, `platform`, and `wireguard_public_key`. A successful response is
HTTP 201 with `Cache-Control: no-store` and `registration_id` (`xreg_`),
`registration_token` (`xrt_`), `status: "pending"`, UTC `expires_at`, and
`interval: 5`.

Exchange uses an empty body and the temporary bearer:

```http
POST /api/overlay/v1/registrations/{registration_id}/exchange
Authorization: Bearer xrt_...
```

HTTP 202 returns the pending status, expiry and interval. HTTP 200 is the
existing `ExchangeResponse` consumed by the normal enrollment flow. The client
maps HTTP 401 to `invalid_registration_token`, 409 to
`registration_rejected` or `registration_consumed` according to the returned
code, and 410 to `registration_expired`. Create-time HTTP 429 maps to
`registration_limited`.

## Offline verification

The test suite uses injected control-plane and runtime fakes plus TLS test
servers. It verifies exact request shape, strict JSON and cache policy,
terminal errors, 0600 state, resumability, no runtime/ACK while pending, and
approved signed-config/apply/ACK reuse. It does not claim a live desktop or
controller run.
