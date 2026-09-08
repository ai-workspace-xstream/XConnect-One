#!/bin/sh

# Bounded, operator-run UAT checks for an already-enrolled XConnect-One
# desktop client. It may invoke `sync`, which applies the CLI-owned runtime and
# routes; it never joins, installs tools, adds routing beyond that CLI action,
# or prints captured command output. It is intentionally POSIX shell so the
# same check contract can be mirrored by verify-desktop-windows.ps1.

set -u

SCRIPT_NAME=$(basename "$0")
RESULT=PASS
TMP_DIR=
CLI_PATH=
STATE_DIR=
EXPECTED_DEVICE_ID=
EXPECTED_NETWORK_ID=
GATEWAY_KEY=
OVERLAY_TARGET=
TARGET_HOST=
HTTP_MARKER=
HANDSHAKE_MAX_AGE=300
COMMAND_TIMEOUT_SECONDS=30
SKIP_PING=0
SKIP_HTTP=0

usage() {
    cat <<'EOF'
Usage:
  verify-desktop-macos.sh --cli PATH --state-dir PATH \
    --expected-device-id ID --expected-network-id ID \
    --gateway-wg-public-key BASE64 --overlay-target URL \
    --http-expected-marker TEXT [options]

Required paths are absolute. The overlay target must be an http(s) URL whose
host is a literal IPv4 address; that address is also used for the one-packet
ping. The URL is fetched once with a ten-second timeout.

Options:
  --handshake-max-age-seconds N  Maximum accepted peer handshake age (default 300)
  --command-timeout-seconds N    Timeout for sync, status, and wg show (default 30)
  --skip-ping                   Mark ping SKIPPED and finish UNVERIFIED
  --skip-http                   Mark HTTP marker check SKIPPED and finish UNVERIFIED
  -h, --help                    Show this message

Exit status:
  0 PASS, 1 FAIL, 2 UNVERIFIED (including explicitly skipped checks)
EOF
}

print_check() {
    # Do not add values supplied by the operator to output: the marker may be
    # sensitive and the key is deliberately not echoed even though it is public.
    printf 'check=%s status=%s\n' "$1" "$2"
}

set_unverified() {
    if [ "$RESULT" = PASS ]; then
        RESULT=UNVERIFIED
    fi
}

fail_check() {
    print_check "$1" FAIL
    printf 'verification failed at check=%s\n' "$1" >&2
    RESULT=FAIL
    finalize 1
}

skip_check() {
    print_check "$1" SKIPPED
    set_unverified
}

finalize() {
    requested_status=$1
    if [ "$RESULT" = FAIL ]; then
        printf 'result=FAIL\n'
        exit 1
    fi
    if [ "$RESULT" = UNVERIFIED ]; then
        printf 'result=UNVERIFIED\n'
        exit 2
    fi
    printf 'result=PASS\n'
    exit "$requested_status"
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

json_value() {
    json_path=$1
    json_file=$2
    [ -x /usr/bin/plutil ] || return 1
    /usr/bin/plutil -extract "$json_path" raw -o - "$json_file" 2>/dev/null
}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

validate_binding_id() {
    binding_id=$1
    [ "${#binding_id}" -ge 3 ] && [ "${#binding_id}" -le 128 ] || return 1
    case "$binding_id" in *[!A-Za-z0-9_.:-]*) return 1 ;; esac
    case "$binding_id" in
        [A-Za-z0-9][A-Za-z0-9_.:-]*) return 0 ;;
        *) return 1 ;;
    esac
}

is_ipv4() {
    old_ifs=$IFS
    IFS=.
    set -- $1
    IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        is_uint "$octet" || return 1
        [ "$octet" -le 255 ] || return 1
    done
}

validate_public_key() {
    key=$1
    [ "${#key}" -eq 44 ] || return 1
    case "$key" in *[!A-Za-z0-9+/=]*) return 1 ;; esac
    key_without_padding=${key%?}
    case "$key_without_padding" in *'='*) return 1 ;; esac
    case "$key" in [A-Za-z0-9+/]*=) return 0 ;; *) return 1 ;; esac
}

validate_target() {
    target=$1
    case "$target" in
        http://*|https://*) ;;
        *) return 1 ;;
    esac
    case "$target" in
        *[![:print:]]*|' '*|*'\t'*|*'@'*) return 1 ;;
    esac
    authority_path=${target#*://}
    authority=${authority_path%%/*}
    [ -n "$authority" ] || return 1
    case "$authority" in
        *:*:*) return 1 ;; # IPv6 and ambiguous authorities are out of scope.
    esac
    case "$authority" in
        *:*)
            target_host=${authority%%:*}
            target_port=${authority#*:}
            is_uint "$target_port" || return 1
            [ "$target_port" -ge 1 ] 2>/dev/null || return 1
            [ "$target_port" -le 65535 ] 2>/dev/null || return 1
            ;;
        *) target_host=$authority ;;
    esac
    is_ipv4 "$target_host" || return 1
    TARGET_HOST=$target_host
    return 0
}

validate_inputs() {
    case "$CLI_PATH" in
        /*) ;;
        *) printf 'verification failed at check=input\n' >&2; return 1 ;;
    esac
    [ -f "$CLI_PATH" ] && [ -x "$CLI_PATH" ] || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    case "$STATE_DIR" in
        /*) [ "$STATE_DIR" != / ] || { printf 'verification failed at check=input\n' >&2; return 1; } ;;
        *) printf 'verification failed at check=input\n' >&2; return 1 ;;
    esac
    [ -d "$STATE_DIR" ] || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    validate_binding_id "$EXPECTED_DEVICE_ID" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    validate_binding_id "$EXPECTED_NETWORK_ID" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    validate_public_key "$GATEWAY_KEY" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    validate_target "$OVERLAY_TARGET" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    [ -n "$HTTP_MARKER" ] || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    case "$HTTP_MARKER" in
        *'
'*) printf 'verification failed at check=input\n' >&2; return 1 ;;
    esac
    if printf '%s' "$HTTP_MARKER" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        printf 'verification failed at check=input\n' >&2
        return 1
    fi
    marker_bytes=$(printf '%s' "$HTTP_MARKER" | wc -c | tr -d '[:space:]')
    is_uint "$marker_bytes" && [ "$marker_bytes" -le 4096 ] 2>/dev/null || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    is_uint "$HANDSHAKE_MAX_AGE" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    [ "$HANDSHAKE_MAX_AGE" -ge 1 ] 2>/dev/null && [ "$HANDSHAKE_MAX_AGE" -le 86400 ] 2>/dev/null || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    is_uint "$COMMAND_TIMEOUT_SECONDS" || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    [ "$COMMAND_TIMEOUT_SECONDS" -ge 1 ] 2>/dev/null && [ "$COMMAND_TIMEOUT_SECONDS" -le 300 ] 2>/dev/null || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    [ -x /usr/bin/plutil ] && [ -x /usr/bin/perl ] || {
        printf 'verification failed at check=input\n' >&2
        return 1
    }
    return 0
}

run_bounded() {
    output_file=$1
    shift
    /usr/bin/perl -e '
        my $timeout = shift @ARGV;
        my $pid = fork();
        exit 125 unless defined $pid;
        if ($pid == 0) {
            setpgrp(0, 0);
            exec @ARGV;
            exit 127;
        }
        my $timed_out = 0;
        local $SIG{ALRM} = sub {
            $timed_out = 1;
            kill "TERM", -$pid;
            sleep 1;
            kill "KILL", -$pid;
        };
        alarm $timeout;
        waitpid($pid, 0);
        alarm 0;
        exit 124 if $timed_out;
        exit 125 if $? == -1;
        exit 128 + ($? & 127) if $? & 127;
        exit($? >> 8);
    ' "$COMMAND_TIMEOUT_SECONDS" "$@" >"$output_file" 2>/dev/null
}

check_external_runtime() {
    missing=0
    for tool in xray wg wg-quick wireguard-go; do
        tool_path=$(command -v "$tool" 2>/dev/null || true)
        [ -n "$tool_path" ] && [ -f "$tool_path" ] && [ -x "$tool_path" ] || missing=1
    done
    if [ "$missing" -ne 0 ]; then
        print_check external-runtime UNVERIFIED
        set_unverified
        return 1
    fi
    print_check external-runtime PASS
    return 0
}

check_handshake() {
    interface=$1
    handshake_file="$TMP_DIR/handshakes"
    if ! run_bounded "$handshake_file" wg show "$interface" latest-handshakes; then
        fail_check wg-handshake
    fi
    timestamp=$(handshake_timestamp "$GATEWAY_KEY" "$handshake_file")
    is_uint "$timestamp" || fail_check wg-handshake
    [ "$timestamp" -gt 0 ] || fail_check wg-handshake
    now=$(date +%s)
    is_uint "$now" || fail_check wg-handshake
    [ "$timestamp" -le $((now + 60)) ] || fail_check wg-handshake
    age=$((now - timestamp))
    [ "$age" -ge 0 ] || fail_check wg-handshake
    [ "$age" -le "$HANDSHAKE_MAX_AGE" ] || fail_check wg-handshake
    print_check wg-handshake PASS
}

handshake_timestamp() {
    expected_key=$1
    handshake_file=$2
    awk -v expected="$expected_key" '$1 == expected {print $2; exit}' "$handshake_file"
}

check_ping() {
    if [ "$SKIP_PING" -eq 1 ]; then
        skip_check ping
        return
    fi
    if ping -n -c 1 -W 3000 "$TARGET_HOST" >/dev/null 2>/dev/null; then
        print_check ping PASS
    else
        fail_check ping
    fi
}

check_http() {
    if [ "$SKIP_HTTP" -eq 1 ]; then
        skip_check http-marker
        return
    fi
    body_file="$TMP_DIR/http-body"
    if ! curl --fail --silent --show-error --noproxy '*' --max-time 10 --output "$body_file" -- "$OVERLAY_TARGET" 2>/dev/null; then
        fail_check http-marker
    fi
    if grep -Fxq -- "$HTTP_MARKER" "$body_file"; then
        print_check http-marker PASS
    else
        fail_check http-marker
    fi
}

main() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --cli)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                CLI_PATH=$2; shift 2 ;;
            --state-dir)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                STATE_DIR=$2; shift 2 ;;
            --expected-device-id)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                EXPECTED_DEVICE_ID=$2; shift 2 ;;
            --expected-network-id)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                EXPECTED_NETWORK_ID=$2; shift 2 ;;
            --gateway-wg-public-key)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                GATEWAY_KEY=$2; shift 2 ;;
            --overlay-target)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                OVERLAY_TARGET=$2; shift 2 ;;
            --http-expected-marker)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                HTTP_MARKER=$2; shift 2 ;;
            --handshake-max-age-seconds)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                HANDSHAKE_MAX_AGE=$2; shift 2 ;;
            --command-timeout-seconds)
                [ "$#" -ge 2 ] || { usage >&2; exit 1; }
                COMMAND_TIMEOUT_SECONDS=$2; shift 2 ;;
            --skip-ping) SKIP_PING=1; shift ;;
            --skip-http) SKIP_HTTP=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; exit 1 ;;
        esac
    done

    if ! validate_inputs; then
        print_check input FAIL
        printf 'result=FAIL\n'
        exit 1
    fi
    print_check input PASS

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xconnect-desktop-verify.XXXXXX") || fail_check sync
    trap cleanup EXIT HUP INT TERM

    if ! run_bounded "$TMP_DIR/sync" "$CLI_PATH" sync --state-dir "$STATE_DIR"; then
        fail_check sync
    fi
    print_check sync PASS

    if ! run_bounded "$TMP_DIR/status" "$CLI_PATH" status --state-dir "$STATE_DIR"; then
        fail_check status
    fi
    joined=$(json_value joined "$TMP_DIR/status" || true)
    status_device_id=$(json_value device_id "$TMP_DIR/status" || true)
    status_network_id=$(json_value network_id "$TMP_DIR/status" || true)
    runtime_applied=$(json_value runtime.applied "$TMP_DIR/status" || true)
    runtime_core=$(json_value runtime.core_id "$TMP_DIR/status" || true)
    credential_present=$(json_value credential.present "$TMP_DIR/status" || true)
    credential_expired=$(json_value credential.expired "$TMP_DIR/status" || true)
    generation=$(json_value generations.state "$TMP_DIR/status" || true)
    interface=$(json_value runtime.interface "$TMP_DIR/status" || true)
    [ "$joined" = true ] || fail_check status
    [ "$status_device_id" = "$EXPECTED_DEVICE_ID" ] || fail_check status
    [ "$status_network_id" = "$EXPECTED_NETWORK_ID" ] || fail_check status
    [ "$runtime_applied" = true ] || fail_check status
    [ "$runtime_core" = xray ] || fail_check status
    [ "$credential_present" = true ] || fail_check status
    [ "$credential_expired" = false ] || fail_check status
    is_uint "$generation" || fail_check status
    [ "$generation" -gt 0 ] || fail_check status
    case "$interface" in
        ''|*[!A-Za-z0-9_.+=-]*) fail_check status ;;
    esac
    [ "${#interface}" -le 15 ] || fail_check status
    print_check status PASS

    if ! check_external_runtime; then
        skip_check wg-handshake
        skip_check ping
        skip_check http-marker
        finalize 2
    fi
    check_handshake "$interface"
    check_ping
    check_http
    finalize 0
}

if [ "${XCONNECT_DESKTOP_VERIFY_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
