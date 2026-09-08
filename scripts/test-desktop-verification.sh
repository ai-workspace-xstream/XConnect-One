#!/bin/sh

# Offline contract tests for the shell verifier's input and JSON/handshake
# parsers. No real CLI, WireGuard, ping, HTTP, or remote execution is used.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
VERIFY_SCRIPT="$SCRIPT_DIR/verify-desktop-macos.sh"
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xconnect-desktop-verify-test.XXXXXX")
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

XCONNECT_DESKTOP_VERIFY_SOURCE_ONLY=1 . "$VERIFY_SCRIPT"
unset XCONNECT_DESKTOP_VERIFY_SOURCE_ONLY

valid_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

cat >"$TEST_DIR/status-compact.json" <<'EOF'
{"metadata":{"joined":false,"runtime":{"applied":false}},"credential":{"present":true,"expired":false},"runtime":{"adapter_id":"xray-core","interface":"utun7","core_id":"xray","applied":true},"generations":{"state":1},"network_id":"net_uat","joined":true,"device_id":"dev_desktop"}
EOF
cat >"$TEST_DIR/status-reordered.json" <<'EOF'
{
  "network_id": "net_uat",
  "runtime": { "interface": "utun7", "applied": true, "adapter_id": "xray-core", "core_id": "xray" },
  "device_id": "dev_desktop",
  "credential": { "expired": false, "present": true },
  "generations": { "state": 1 },
  "joined": true,
  "metadata": { "joined": false, "runtime": { "applied": false } }
}
EOF

for fixture in "$TEST_DIR/status-compact.json" "$TEST_DIR/status-reordered.json"; do
    [ "$(json_value joined "$fixture")" = true ]
    [ "$(json_value device_id "$fixture")" = dev_desktop ]
    [ "$(json_value network_id "$fixture")" = net_uat ]
    [ "$(json_value runtime.applied "$fixture")" = true ]
    [ "$(json_value runtime.core_id "$fixture")" = xray ]
    [ "$(json_value runtime.adapter_id "$fixture")" = xray-core ]
    [ "$(json_value runtime.interface "$fixture")" = utun7 ]
    [ "$(json_value credential.present "$fixture")" = true ]
    [ "$(json_value credential.expired "$fixture")" = false ]
    [ "$(json_value generations.state "$fixture")" = 1 ]
    [ "$(json_value metadata.joined "$fixture")" = false ]
    [ "$(json_value metadata.runtime.applied "$fixture")" = false ]
done

validate_public_key "$valid_key"
! validate_public_key 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
validate_target 'http://10.77.0.42:8080/uat/run'
[ "$TARGET_HOST" = 10.77.0.42 ]
! validate_target 'http://overlay.example/uat/run'
! validate_target 'http://10.77.0.42:0/uat/run'
! validate_target 'http://user@10.77.0.42/uat/run'

now=$(date +%s)
printf '%s %s\n' "$valid_key" "$now" >"$TEST_DIR/handshakes"
[ "$(handshake_timestamp "$valid_key" "$TEST_DIR/handshakes")" = "$now" ]
printf '%s %s\n' 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=' "$now" >>"$TEST_DIR/handshakes"
[ "$(handshake_timestamp "$valid_key" "$TEST_DIR/handshakes")" = "$now" ]

# Full verifier contract with local stand-ins. Every executable below is a
# fixture; PATH is deliberately restricted so no host runtime or network tool
# is selected.
FAKE_BIN="$TEST_DIR/bin"
mkdir "$FAKE_BIN"
cat >"$TEST_DIR/fake-cli" <<'EOF'
#!/bin/sh
case "$1" in
    sync) exit 0 ;;
    status)
        printf '%s\n' '{"credential":{"present":true,"expired":false},"runtime":{"adapter_id":"xray-core","interface":"utun7","core_id":"xray","applied":true},"generations":{"state":1},"network_id":"net_uat","joined":true,"device_id":"dev_desktop","metadata":{"joined":false,"runtime":{"applied":false}}}'
        exit 0
        ;;
esac
exit 1
EOF
chmod 755 "$TEST_DIR/fake-cli"
cat >"$TEST_DIR/slow-cli" <<'EOF'
#!/bin/sh
sleep 5
EOF
chmod 755 "$TEST_DIR/slow-cli"
cat >"$FAKE_BIN/xray" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$FAKE_BIN/wg-quick" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$FAKE_BIN/wireguard-go" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$FAKE_BIN/wg" <<EOF
#!/bin/sh
[ "\$1" = show ] && [ "\$2" = utun7 ] && [ "\$3" = latest-handshakes ] || exit 1
printf '%s %s\\n' '$valid_key' "\$(date +%s)"
EOF
cat >"$FAKE_BIN/ping" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$FAKE_BIN/curl" <<'EOF'
#!/bin/sh
body=
saw_noproxy=0
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then body=$2; shift 2
    elif [ "$1" = --noproxy ] && [ "${2:-}" = '*' ]; then saw_noproxy=1; shift 2
    else shift
    fi
done
[ "$saw_noproxy" -eq 1 ] || exit 2
if [ "${CURL_SUBSTRING:-0}" = 1 ]; then printf '%s\n' 'prefix run=34196049126 suffix' >"$body"
else printf '%s\n' 'run=34196049126' >"$body"
fi
exit 0
EOF
chmod 755 "$FAKE_BIN"/*

set +e
PATH="$FAKE_BIN:/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/fake-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_desktop --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' >"$TEST_DIR/pass.out" 2>"$TEST_DIR/pass.err"
pass_code=$?
set -e
[ "$pass_code" -eq 0 ]
grep -Fq 'result=PASS' "$TEST_DIR/pass.out"
! grep -Fq "$valid_key" "$TEST_DIR/pass.out" "$TEST_DIR/pass.err"
! grep -Fq 'run=34196049126' "$TEST_DIR/pass.out" "$TEST_DIR/pass.err"

set +e
CURL_SUBSTRING=1 PATH="$FAKE_BIN:/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/fake-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_desktop --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' >"$TEST_DIR/substring.out" 2>"$TEST_DIR/substring.err"
substring_code=$?
set -e
[ "$substring_code" -eq 1 ]
grep -Fq 'check=http-marker status=FAIL' "$TEST_DIR/substring.out"

set +e
PATH="/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/slow-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_desktop --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' --command-timeout-seconds 1 >"$TEST_DIR/timeout.out" 2>"$TEST_DIR/timeout.err"
timeout_code=$?
set -e
[ "$timeout_code" -eq 1 ]
grep -Fq 'check=sync status=FAIL' "$TEST_DIR/timeout.out"

set +e
PATH="$FAKE_BIN:/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/fake-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_other --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' >"$TEST_DIR/mismatch.out" 2>"$TEST_DIR/mismatch.err"
mismatch_code=$?
set -e
[ "$mismatch_code" -eq 1 ]
grep -Fq 'check=status status=FAIL' "$TEST_DIR/mismatch.out"
grep -Fq 'result=FAIL' "$TEST_DIR/mismatch.out"

set +e
PATH="$FAKE_BIN:/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/fake-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_desktop --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' --skip-http >"$TEST_DIR/skip.out" 2>"$TEST_DIR/skip.err"
skip_code=$?
set -e
[ "$skip_code" -eq 2 ]
grep -Fq 'check=http-marker status=SKIPPED' "$TEST_DIR/skip.out"
grep -Fq 'result=UNVERIFIED' "$TEST_DIR/skip.out"

set +e
PATH="/usr/bin:/bin" "$VERIFY_SCRIPT" \
    --cli "$TEST_DIR/fake-cli" --state-dir "$TEST_DIR" \
    --expected-device-id dev_desktop --expected-network-id net_uat \
    --gateway-wg-public-key "$valid_key" \
    --overlay-target 'http://10.77.0.42:8080/uat/run' \
    --http-expected-marker 'run=34196049126' >"$TEST_DIR/unverified.out" 2>"$TEST_DIR/unverified.err"
unverified_code=$?
set -e
[ "$unverified_code" -eq 2 ]
grep -Fq 'check=external-runtime status=UNVERIFIED' "$TEST_DIR/unverified.out"
grep -Fq 'result=UNVERIFIED' "$TEST_DIR/unverified.out"

printf 'test-desktop-verification: PASS\n'
