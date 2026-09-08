# macOS and Windows desktop UAT verification

This kit is a bounded, operator-run verification layer for an **already
enrolled** XConnect-One device. It does not run `join`, install Xray or
WireGuard, add independent routes, change DNS, create a host adapter, use
XConnect APP state, or execute on a remote host. `sync` is intentionally
allowed to apply the CLI-owned runtime and routes; the verifier adds no routing
or DNS changes
of its own. The Linux cloud lab run marker
`34196049126` is an upstream baseline; these scripts do not claim to rerun or
re-certify that lab.

The checks are deliberately narrow:

1. Run `xconnect sync` against the supplied state directory.
2. Require `xconnect status` to report the exact expected device ID and network
   ID, an enrolled device, an applied runtime, an Xray core, a non-expired
   credential, a positive generation, and a valid `runtime.interface`. The
   status JSON is parsed structurally, captured privately, and is not printed.
3. Confirm the platform's external runtime commands are present.
4. Read `latest-handshakes` for the exact supplied gateway WireGuard public key
   on the interface reported by `status`, and require a recent nonzero
   timestamp.
5. Ping the literal IPv4 host in `--overlay-target` once.
6. Fetch that exact HTTP(S) URL once, without proxies or redirects, with a
   ten-second timeout and require the supplied response marker as one complete
   response line.

The scripts do not print CLI output, WireGuard output, credentials, private
keys, the expected marker, or the gateway key. The gateway key is accepted as
public information only so the check cannot accidentally accept a handshake
from another peer.

`runtime.adapter_id` and `runtime.interface` are different API fields. The
former identifies the runtime adapter and remains `xray-core`; the latter is
the non-sensitive WireGuard interface from the trusted desktop manifest. Only
`runtime.interface` is passed to `wg show`.

## Result contract

Each check prints one line such as `check=wg-handshake status=PASS`, followed
by exactly one overall result line:

| Result | Exit | Meaning |
|---|---:|---|
| `PASS` | 0 | Every requested check passed. |
| `FAIL` | 1 | Input validation failed, `sync`/`status` failed, state was not owned and healthy, the exact peer was absent/stale, or an attempted ping/HTTP check failed. |
| `UNVERIFIED` | 2 | A prerequisite was unavailable or a check was explicitly skipped. The result is not a pass. Affected checks are labeled `UNVERIFIED` or `SKIPPED`. |

There is no implicit success when a check is skipped. Use `--skip-ping` or
`--skip-http` only for a controlled partial run; the overall result will be
`UNVERIFIED`.

## macOS

Use the standalone script from this repository. The CLI path must be an
absolute executable path; it does not need to be installed on `PATH`. The
state directory must already contain the enrolled device state and must be an
absolute existing directory.

```sh
scripts/verify-desktop-macos.sh \
  --cli /Users/me/bin/xconnect \
  --state-dir /Users/me/.xconnect-one-macos-uat \
  --expected-device-id dev_desktop \
  --expected-network-id net_uat \
  --gateway-wg-public-key 'REPLACE_WITH_GATEWAY_PUBLIC_KEY' \
  --overlay-target 'http://10.77.0.42:8080/uat/run' \
  --http-expected-marker 'run=34196049126'
```

The script expects `xray`, `wg`, `wg-quick`, and `wireguard-go` to be available
to the invoked CLI. The verifier also checks their presence, but does not
install or select them. Run with the same privilege context used by the enrolled CLI so
that `sync`, `status`, and `wg show` observe the same owned runtime. `sync` may
change the CLI-owned runtime and routes; the verifier does not add any others.
macOS JSON status parsing uses the system `/usr/bin/plutil` key-path parser;
no line-oriented JSON parsing, `jq`, or Python dependency is used. The
`--command-timeout-seconds` option bounds `sync`, `status`, and `wg show`.
The Darwin backend resolves the manifest logical name through the
root-controlled `/var/run/wireguard/<logical>.name` mapping and its matching
`<utunN>.sock`, then verifies the real `utunN` OS interface. The reported
interface is that real `utunN`; only `wg show` receives the translated name,
while `wg-quick` continues to receive the original config path. The mapping
accepts the upstream root-owned `0400` (or `0600`) name file; the socket must
be root-owned with `0600` or `0700`, with no group/other permissions, and both
paths must be fresh relative to each other.

The overlay target is restricted to an IPv4 literal to keep this kit from
silently expanding into DNS or broad route verification. The URL's host is
the one ping target; its full URL is the one HTTP target.

## Windows

Run PowerShell from an elevated console. As on macOS, the CLI path is explicit
and does not need to be on `PATH`.

```powershell
.\scripts\verify-desktop-windows.ps1 `
  -CliPath 'C:\Users\me\bin\xconnect.exe' `
  -StateDir 'C:\Users\me\.xconnect-one-windows-uat' `
  -ExpectedDeviceId 'dev_desktop' `
  -ExpectedNetworkId 'net_uat' `
  -GatewayWireGuardPublicKey 'REPLACE_WITH_GATEWAY_PUBLIC_KEY' `
  -OverlayTarget 'http://10.77.0.42:8080/uat/run' `
  -HttpExpectedMarker 'run=34196049126'
```

The Windows verifier requires `xray.exe`, `wg.exe`, and `wireguard.exe` to be
discoverable; for the two WireGuard commands it also checks the standard
`%ProgramFiles%\WireGuard\` location used by XConnect-One. XConnect-One itself
uses the official WireGuard tunnel-service boundary; the verifier only reads
`wg.exe show` and does not install, uninstall, or mutate that service.
`ping.exe` and `curl.exe` are used with bounded calls when the corresponding
checks are enabled. `-CommandTimeoutSeconds` bounds `sync`, `status`, and
`wg.exe show`.

## Offline tests and limitations

Run the parser/input tests on a Unix-like development host:

```sh
scripts/test-desktop-verification.sh
```

Those tests use only local fixture files, local stand-in executables, and the
current clock. They do not invoke XConnect-One, WireGuard, ping, curl, a
controller, a gateway, or any remote execution. A Windows host should run the
PowerShell parser test:

```powershell
scripts\test-desktop-verification.ps1
```

The Windows test exits before any external command or network operation. In
this integration review it was **NOT RUN** because PowerShell was unavailable
on the macOS development host. This repository does not claim a live Windows
tunnel test.

The verifier checks the local client's view of a handshake and application
reachability. It does not prove gateway policy correctness, return routes
beyond the selected target, DNS behavior, full-tunnel behavior, or any other
network destination. A recent handshake without a matching ping and marker is
not a pass.
