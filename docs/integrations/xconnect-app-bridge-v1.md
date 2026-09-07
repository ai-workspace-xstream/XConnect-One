# XConnect APP bridge protocol v1

XConnect-One remains an independent CLI. XConnect APP can optionally present
XConnect-One through a host-owned plugin that starts the released `xconnect`
binary as a child process. The APP must not import this repository's Go source,
reuse its internal state files, or link against its domain packages.

The optional bridge command is:

```text
xconnect app-bridge
```

It is a local JSON Lines protocol on the process standard input/output. The
plugin owns process lifecycle, elevation and local transport access. It may
wrap standard input/output in a same-user socket adapter, but it must not
expose the bridge through a TCP listener. The plugin uses a dedicated absolute
state directory, for example `/var/lib/xconnect-app/one`, and must not share it
with a separately managed CLI installation.

The JSON request schema is available at
[`xconnect-app-bridge-v1.schema.json`](xconnect-app-bridge-v1.schema.json).
There is one request and exactly one response per line. Lines larger than 64
KiB are rejected. Unknown request and parameter fields are rejected so a new
host cannot silently depend on an older One release.

## Negotiation and requests

Every request has this envelope:

```json
{"protocol_version":"1","request_id":"host-generated-id","method":"status","params":{"state_dir":"/var/lib/xconnect-app/one"}}
```

The host first sends `negotiate` with `{"protocol_versions":["1"]}`. A
successful response exposes the selected protocol capabilities:

```json
{"protocol_version":"1","request_id":"capabilities-1","result":{"methods":["negotiate","join","sync","status","leave","diagnose"],"protocol_versions":["1"],"secret_output_fields":[],"sensitive_input_fields":["join.invite"],"state_dir_required":true,"transport":"stdio-jsonl"}}
```

The request `params` are limited to the following fields.

| Method | Parameters | Operation |
| --- | --- | --- |
| `join` | `state_dir`, `invite`, optional `device_id`, `name`, `network_id`, `node_id` | Uses a signed `xconnect://join/...` invitation. Direct controller URLs and account tokens are excluded from the bridge. |
| `sync` | `state_dir`, optional `signed_config_v2` | Fetches, verifies and applies the current signed configuration. |
| `status` | `state_dir` | Returns One's current local status JSON. |
| `leave` | `state_dir`, optional `local_only` | Revokes then removes One state, unless `local_only` is explicitly set. The host must ask the user before this action. |
| `diagnose` | `state_dir` | Returns local runtime diagnostic JSON. |

`state_dir` is mandatory, absolute, and host-owned. The APP should treat it as
opaque. It must not read or write credentials, signed configuration, runtime
files or lock files inside it.

## Responses and errors

Successful command output is returned as the `result` JSON value:

```json
{"protocol_version":"1","request_id":"status-1","result":{"joined":true}}
```

Failed calls return only an opaque code:

```json
{"protocol_version":"1","request_id":"sync-1","error":{"code":"controlplane_unavailable"}}
```

Bridge protocol errors are `bridge_invalid_request`,
`bridge_unsupported_version`, `bridge_unsupported_method`,
`bridge_invalid_params`, and `bridge_invalid_result`. Existing XConnect-One
error codes may be returned for accepted calls. No error message is included.
The host can map codes to its own localized UI, but must never display request
payloads or process stderr as a fallback.

## Secret and ownership rules

`join.invite` is the sole permitted secret-bearing input. It is consumed only
by One and is never echoed in a response. Account tokens, device credentials,
private keys, Vault material, controller bootstrap tokens, and raw controller
configuration are forbidden bridge fields. The host must not log JSON input,
output, stderr, command arguments, or its local socket traffic.

The bridge does not establish remote reachability or prove Gateway policy
enforcement. Its `status`, `diagnose`, `join` and `sync` results have the same
local-readiness scope as the standalone CLI. XConnect APP remains independently
buildable and functional when no One plugin or bridge process is installed.
