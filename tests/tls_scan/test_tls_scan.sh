#!/bin/bash
#
# Backs skills/web-vulnerability-testing/scripts/tls-scan.sh's own header
# comment, which is explicit that only the openssl_fallback path was
# verified against real TLS servers, while the testssl.sh/sslscan/nmap
# parsing paths were implemented from documented output shapes and never
# run against a real install. This test:
#
#   1. Runs the real openssl_fallback path against an actual local
#      self-signed HTTPS server (mock_tls_server.py) - real handshake,
#      real certificate parsing, real hostname-mismatch check.
#   2. Fixture-tests the testssl.sh/sslscan/nmap output-normalization
#      logic against canned tool output, since those tools aren't
#      installed wherever this test runs.
#
# All four scenarios force which cascade branch tls-scan.sh takes by
# prepending stub testssl.sh/sslscan/nmap executables to PATH - a stub
# that exits 1 without producing output makes the script fall through to
# the next tool exactly as it would if the real tool were simply absent;
# a stub that copies a fixture file to the path the real tool would have
# written makes the script parse that canned output for real, through
# its own actual parsing code (not a reimplementation of it).
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
TLS_SCAN="$REPO_ROOT/skills/web-vulnerability-testing/scripts/tls-scan.sh"
FIXTURES="$HERE/fixtures"
WORK=$(mktemp -d)
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

FAILED=0

# Builds a fresh stub PATH directory. Args: name-of-tool-that-should
# "succeed" (copy a fixture to the output path it's given) or "" for none
# (all three fail, forcing openssl_fallback).
build_stub_path() {
    local succeed_tool="$1"
    local stub_dir="$2"
    mkdir -p "$stub_dir"

    if [ "$succeed_tool" = "testssl.sh" ]; then
        cat > "$stub_dir/testssl.sh" << STUBEOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        --jsonfile) out="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "$FIXTURES/testssl_sample.json" "\$out"
STUBEOF
    else
        printf '#!/bin/bash\nexit 1\n' > "$stub_dir/testssl.sh"
    fi

    if [ "$succeed_tool" = "sslscan" ]; then
        cat > "$stub_dir/sslscan" << STUBEOF
#!/bin/bash
out=""
for arg in "\$@"; do
    case "\$arg" in
        --xml=*) out="\${arg#--xml=}" ;;
    esac
done
cp "$FIXTURES/sslscan_sample.xml" "\$out"
STUBEOF
    else
        printf '#!/bin/bash\nexit 1\n' > "$stub_dir/sslscan"
    fi

    if [ "$succeed_tool" = "nmap" ]; then
        cat > "$stub_dir/nmap" << STUBEOF
#!/bin/bash
out=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        -oX) out="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "$FIXTURES/nmap_sample.xml" "\$out"
STUBEOF
    else
        printf '#!/bin/bash\nexit 1\n' > "$stub_dir/nmap"
    fi

    chmod +x "$stub_dir/testssl.sh" "$stub_dir/sslscan" "$stub_dir/nmap"
}

REAL_PATH="$PATH"

# --- Scenario 1: openssl_fallback against a real local self-signed server ---
echo "--- openssl_fallback: real self-signed localhost TLS1.2/1.3-only server ---"

openssl req -x509 -newkey rsa:2048 -days 1 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=localhost" \
    >"$WORK/openssl_req.log" 2>&1

PORT=8999
python3 "$HERE/mock_tls_server.py" "$PORT" "$WORK/cert.pem" "$WORK/key.pem" &
SERVER_PID=$!

ready=0
server_died=0
for _ in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mock TLS server process (PID $SERVER_PID) died before becoming ready"
        server_died=1
        break
    fi
    if curl -sk --max-time 1 "https://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.2
done
if [ "$server_died" = "1" ]; then
    FAILED=1
elif [ "$ready" != "1" ]; then
    echo "FAIL: mock TLS server never became ready on port $PORT"
    FAILED=1
else
    STUB1="$WORK/stub_bin_fallback"
    build_stub_path "" "$STUB1"
    PATH="$STUB1:$REAL_PATH" "$TLS_SCAN" --target localhost --port "$PORT" --output "$WORK/fallback.json"
    cat "$WORK/fallback.json"

    tool_used=$(jq -r '.tool_used' "$WORK/fallback.json")
    [ "$tool_used" = "openssl_fallback" ] || { echo "FAIL: expected tool_used=openssl_fallback, got $tool_used"; FAILED=1; }

    self_signed=$(jq -r '.certificate.self_signed' "$WORK/fallback.json")
    [ "$self_signed" = "true" ] || { echo "FAIL: expected certificate.self_signed=true, got $self_signed"; FAILED=1; }

    hostname_mismatch=$(jq -r '.certificate.hostname_mismatch' "$WORK/fallback.json")
    [ "$hostname_mismatch" = "false" ] || { echo "FAIL: expected certificate.hostname_mismatch=false (--target matches cert CN=localhost), got $hostname_mismatch"; FAILED=1; }

    not_after=$(jq -r '.certificate.not_after' "$WORK/fallback.json")
    [ -n "$not_after" ] || { echo "FAIL: expected certificate.not_after to be populated"; FAILED=1; }

    expired=$(jq -r '.certificate.expired' "$WORK/fallback.json")
    [ "$expired" = "false" ] || { echo "FAIL: expected certificate.expired=false for a cert valid 1 day from now, got $expired"; FAILED=1; }

    weak_count=$(jq '.weak_protocols_detected | length' "$WORK/fallback.json")
    [ "$weak_count" = "0" ] || { echo "FAIL: expected zero weak protocols against a TLS1.2+-only server, got $weak_count"; FAILED=1; }

    tls12=$(jq -r '.protocols_supported.tls1_2' "$WORK/fallback.json")
    [ "$tls12" = "true" ] || { echo "FAIL: expected protocols_supported.tls1_2=true, got $tls12"; FAILED=1; }
fi

kill "$SERVER_PID" 2>/dev/null
SERVER_PID=""

# --- Scenario 2: testssl.sh output normalization (fixture) ---
echo "--- testssl.sh output normalization (canned fixture) ---"
STUB2="$WORK/stub_bin_testssl"
build_stub_path "testssl.sh" "$STUB2"
PATH="$STUB2:$REAL_PATH" "$TLS_SCAN" --target example.com --port 443 --output "$WORK/testssl.json"
cat "$WORK/testssl.json"

tool_used=$(jq -r '.tool_used' "$WORK/testssl.json")
[ "$tool_used" = "testssl" ] || { echo "FAIL: expected tool_used=testssl, got $tool_used"; FAILED=1; }

weak=$(jq -c '.weak_protocols_detected | sort' "$WORK/testssl.json")
[ "$weak" = '["tls1_0","tls1_1"]' ] || { echo "FAIL: expected weak_protocols_detected=[tls1_0,tls1_1], got $weak"; FAILED=1; }

known_vuln_id=$(jq -r '.known_vulnerabilities[0].id' "$WORK/testssl.json")
known_vuln_count=$(jq '.known_vulnerabilities | length' "$WORK/testssl.json")
[ "$known_vuln_count" = "1" ] && [ "$known_vuln_id" = "ROBOT" ] || { echo "FAIL: expected exactly one known_vulnerabilities entry (ROBOT), got count=$known_vuln_count id=$known_vuln_id"; FAILED=1; }

cert_subject=$(jq -r '.certificate.subject' "$WORK/testssl.json")
[ "$cert_subject" = "example.com" ] || { echo "FAIL: expected certificate.subject=example.com, got $cert_subject"; FAILED=1; }

cert_expired=$(jq -r '.certificate.expired' "$WORK/testssl.json")
[ "$cert_expired" = "false" ] || { echo "FAIL: expected certificate.expired=false, got $cert_expired"; FAILED=1; }

cert_self_signed=$(jq -r '.certificate.self_signed' "$WORK/testssl.json")
[ "$cert_self_signed" = "false" ] || { echo "FAIL: expected certificate.self_signed=false, got $cert_self_signed"; FAILED=1; }

# --- Scenario 3: sslscan output normalization (fixture) ---
echo "--- sslscan output normalization (canned fixture) ---"
STUB3="$WORK/stub_bin_sslscan"
build_stub_path "sslscan" "$STUB3"
PATH="$STUB3:$REAL_PATH" "$TLS_SCAN" --target example.com --port 443 --output "$WORK/sslscan.json"
cat "$WORK/sslscan.json"

tool_used=$(jq -r '.tool_used' "$WORK/sslscan.json")
[ "$tool_used" = "sslscan" ] || { echo "FAIL: expected tool_used=sslscan, got $tool_used"; FAILED=1; }

tls12=$(jq -r '.protocols_supported.tls1_2' "$WORK/sslscan.json")
tls10=$(jq -r '.protocols_supported.tls1_0' "$WORK/sslscan.json")
[ "$tls12" = "true" ] && [ "$tls10" = "false" ] || { echo "FAIL: expected tls1_2=true and tls1_0=false, got tls1_2=$tls12 tls1_0=$tls10"; FAILED=1; }

weak_count=$(jq '.weak_protocols_detected | length' "$WORK/sslscan.json")
[ "$weak_count" = "0" ] || { echo "FAIL: expected zero weak protocols, got $weak_count"; FAILED=1; }

self_signed=$(jq -r '.certificate.self_signed' "$WORK/sslscan.json")
[ "$self_signed" = "true" ] || { echo "FAIL: expected certificate.self_signed=true (subject==issuer in fixture), got $self_signed"; FAILED=1; }

# --- Scenario 4: nmap output normalization (fixture) ---
echo "--- nmap output normalization (canned fixture) ---"
STUB4="$WORK/stub_bin_nmap"
build_stub_path "nmap" "$STUB4"
PATH="$STUB4:$REAL_PATH" "$TLS_SCAN" --target example.com --port 443 --output "$WORK/nmap.json"
cat "$WORK/nmap.json"

tool_used=$(jq -r '.tool_used' "$WORK/nmap.json")
[ "$tool_used" = "nmap" ] || { echo "FAIL: expected tool_used=nmap, got $tool_used"; FAILED=1; }

tls12=$(jq -r '.protocols_supported.tls1_2' "$WORK/nmap.json")
tls13=$(jq -r '.protocols_supported.tls1_3' "$WORK/nmap.json")
[ "$tls12" = "true" ] && [ "$tls13" = "true" ] || { echo "FAIL: expected tls1_2=true and tls1_3=true, got tls1_2=$tls12 tls1_3=$tls13"; FAILED=1; }

known_vuln_id=$(jq -r '.known_vulnerabilities[0].id' "$WORK/nmap.json")
[ "$known_vuln_id" = "heartbleed" ] || { echo "FAIL: expected known_vulnerabilities[0].id=heartbleed, got $known_vuln_id"; FAILED=1; }

expired=$(jq -r '.certificate.expired' "$WORK/nmap.json")
[ "$expired" = "true" ] || { echo "FAIL: expected certificate.expired=true (fixture's not_after is 2020-01-01, in the past), got $expired"; FAILED=1; }

self_signed=$(jq -r '.certificate.self_signed' "$WORK/nmap.json")
[ "$self_signed" = "false" ] || { echo "FAIL: expected certificate.self_signed=false (fixture subject != issuer), got $self_signed"; FAILED=1; }

exit $FAILED
