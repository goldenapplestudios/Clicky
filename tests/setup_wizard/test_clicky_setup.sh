#!/bin/bash
#
# Tests for tools/clicky-setup.sh - the setup wizard - and
# tools/advanced_agent_assignment.py's per-agent model assignment.
#
# Every AI-CLI/nix/npm binary this wizard can call is stubbed on PATH
# (fake_bin/) - same pattern tests/tls_scan/ already uses for
# testssl.sh/sslscan/nmap: a stub that exits 0 with canned output makes
# the wizard take the "tool present and working" branch through its own
# real code, not a reimplementation of it; a stub that's simply absent
# from fake_bin/ (with PATH restricted to fake_bin/ plus only the bare
# OS coreutils directories, never the real system PATH) makes the wizard
# correctly detect "not installed." This is what makes it safe to run
# this suite anywhere, including CI and a developer's own machine,
# without ever touching the real ~/.clicky/, ~/.claude/settings.json,
# ~/.codex/config.toml, or actually invoking Nix/npm/network.
# CLICKY_CONFIG_DIR/CLICKY_CLAUDE_SETTINGS_PATH/CLICKY_AGENT_MODELS_PATH
# are always pointed at a fresh temp dir before any invocation - see
# tools/clicky-setup.sh's own comment on why that env-var override
# exists (found the hard way, during this feature's own development,
# when a manual test run wrote to the real settings.json).
#
# clicky-setup.sh itself is pure bash - no python3 needed to run the
# default flow at all (a direct correction: the wizard's whole job is
# getting someone from "nothing installed" to "Clicky works," so it
# can't itself require an interpreter the operator might not have).
# CORE_PATH below is deliberately just the bare OS coreutils
# directories (/bin, /usr/bin) - enough for bash/grep/sed/mkdir/date to
# resolve, nothing else - so Fixtures 1 and 4 genuinely exercise "no
# interpreters, no AI CLIs, no nix, no npm," not just "no AI CLIs."
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WIZARD="$REPO_ROOT/tools/clicky-setup.sh"
FAKE_BIN="$HERE/fake_bin"
CORE_PATH="/bin:/usr/bin"

# Empty directories aren't tracked by git - a fresh clone won't have
# this one, so create it rather than assume it exists.
mkdir -p "$FAKE_BIN"
rm -f "$FAKE_BIN"/*

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed (needed for this suite's own JSON assertions, not the wizard itself)"; exit 0; }

FAILED=0
check() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $label"
        echo "  expected: $expected"
        echo "  actual:   $actual"
        FAILED=1
    else
        echo "PASS: $label"
    fi
}
contains() {
    local label="$1" haystack="$2" needle="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        echo "PASS: $label"
    else
        echo "FAIL: $label - expected output to contain: $needle"
        FAILED=1
    fi
}

mk_workdir() {
    local d
    d=$(mktemp -d)
    mkdir -p "$d/clicky-config" "$d/claude"
    echo "$d"
}

# --- Fixture 1: nothing installed at all --------------------------------
echo "=== Case: no AI CLIs, no nix, no codex, no npm - decline everything ==="
WORK=$(mk_workdir)
OUT=$(PATH="$CORE_PATH" \
    CLICKY_PREFLIGHT=off \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_LOCAL_BIN="$WORK/localbin" \
    CLICKY_CONFIG_DIR="$WORK/clicky-config" \
    CLICKY_CONFIG_PATH="$WORK/clicky-config/config.json" \
    CLICKY_CLAUDE_SETTINGS_PATH="$WORK/claude/settings.json" \
    bash "$WIZARD" << 'EOF'
n
n
EOF
)
echo "$OUT"
contains "declined-nix: no AI CLI hosts message shown" "$OUT" "(none detected on PATH)"
contains "declined-nix: Kalilix skip message shown" "$OUT" "Skipping - agents will use whatever's already on your PATH"
contains "declined-codex: npm-missing message shown" "$OUT" "npm isn't on PATH either"
check "declined: tool_provisioning written as none" \
    "$(python3 -c "import json; print(json.load(open('$WORK/clicky-config/config.json'))['tool_provisioning'])")" "none"
check "declined: no settings.json written (no CLI hosts detected)" \
    "$([ -f "$WORK/claude/settings.json" ] && echo yes || echo no)" "no"
rm -rf "$WORK"

# --- Fixture 2: all 4 CLIs + nix + codex present and working ------------
echo ""
echo "=== Case: all 4 CLI hosts detected, nix+kalilix+codex all working ==="
WORK=$(mk_workdir)
cat > "$FAKE_BIN/nix" << 'NIXEOF'
#!/bin/bash
case "$1 $2" in
    "registry add") exit 0 ;;
    "registry list") echo "flake:kalilix github:scopecreep-zip/kalilix"; exit 0 ;;
esac
if [ "$1" = "develop" ]; then
    # --command true, or --command bash -c '<coverage script>'
    shift 2  # drop "develop kalilix#kali"
    if [ "$1" = "--command" ]; then
        shift
        exec "$@"
    fi
fi
exit 1
NIXEOF
chmod +x "$FAKE_BIN/nix"

cat > "$FAKE_BIN/codex" << 'CODEXEOF'
#!/bin/bash
if [ "$1" = "exec" ]; then
    echo "OK"
    exit 0
fi
if [ "$1" = "mcp" ] && [ "$2" = "list" ]; then
    echo "clicky-gateway"
    exit 0
fi
exit 0
CODEXEOF
chmod +x "$FAKE_BIN/codex"

for name in claude opencode copilot npm jq; do
    cat > "$FAKE_BIN/$name" << 'STUBEOF'
#!/bin/bash
exit 0
STUBEOF
    chmod +x "$FAKE_BIN/$name"
done
# real jq needed for the settings.json sync to actually work in this
# fixture - overwrite the no-op stub with a symlink to the real binary
# if one exists, so this fixture exercises the real jq-based sync path.
if command -v jq >/dev/null 2>&1; then
    ln -sf "$(command -v jq)" "$FAKE_BIN/jq"
fi

# `bash`/`true`/`grep`/etc. need to still resolve inside the fake nix
# develop --command wrapper above, and inside clicky-setup.sh itself -
# fake_bin first so our stubs win for the names we're actually testing,
# CORE_PATH after for everything else.
OUT=$(PATH="$FAKE_BIN:$CORE_PATH" \
    CLICKY_PREFLIGHT=off \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_LOCAL_BIN="$WORK/localbin" \
    CLICKY_CONFIG_DIR="$WORK/clicky-config" \
    CLICKY_CONFIG_PATH="$WORK/clicky-config/config.json" \
    CLICKY_CLAUDE_SETTINGS_PATH="$WORK/claude/settings.json" \
    bash "$WIZARD" << 'EOF'
y
EOF
)
echo "$OUT"
contains "all-present: all 4 hosts detected" "$OUT" "- claude:"
contains "all-present: nix Kalilix ready message" "$OUT" "Kalilix ready"
contains "all-present: cross-provider severity review ready" "$OUT" "Cross-provider severity review ready"
contains "all-present: codex already registered detected" "$OUT" "already has clicky-gateway registered"
check "all-present: tool_provisioning=kalilix written" \
    "$(python3 -c "import json; print(json.load(open('$WORK/clicky-config/config.json'))['tool_provisioning'])")" "kalilix"
if command -v jq >/dev/null 2>&1; then
    check "all-present: settings.json synced with pluginConfigs.clicky.options" \
        "$(python3 -c "import json; d=json.load(open('$WORK/claude/settings.json')); print(d['pluginConfigs']['clicky']['options']['tool_provisioning'])")" "kalilix"
else
    echo "SKIP: settings.json sync assertion (no real jq on this machine)"
fi
rm -rf "$WORK" "$FAKE_BIN"/*

# --- Fixture 3: codex installed but not authenticated --------------------
echo ""
echo "=== Case: codex installed, not authenticated ==="
WORK=$(mk_workdir)
cat > "$FAKE_BIN/codex" << 'CODEXEOF'
#!/bin/bash
if [ "$1" = "exec" ]; then
    echo "Error: not logged in" >&2
    exit 1
fi
exit 0
CODEXEOF
chmod +x "$FAKE_BIN/codex"
# Needs a real `bash` resolvable too (sync_codex_registration re-runs
# .codex/install.sh via `bash <path>`), and CODEX_HOME isolated so that
# re-run doesn't write real prompt files into ~/.codex/prompts/.
OUT=$(PATH="$FAKE_BIN:$CORE_PATH" \
    CODEX_HOME="$WORK/codex-home" \
    CLICKY_PREFLIGHT=off \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_LOCAL_BIN="$WORK/localbin" \
    CLICKY_CONFIG_DIR="$WORK/clicky-config" \
    CLICKY_CONFIG_PATH="$WORK/clicky-config/config.json" \
    CLICKY_CLAUDE_SETTINGS_PATH="$WORK/claude/settings.json" \
    bash "$WIZARD" << 'EOF'
n
EOF
)
contains "not-authed: hands off to codex login cleanly" "$OUT" "codex login"
contains "not-authed: summary reflects fallback with fix instruction" "$OUT" "run \`codex login\`, then re-run this wizard"
rm -rf "$WORK" "$FAKE_BIN"/*

echo ""
echo "=== Idempotent re-run: existing config values are preserved ==="
WORK=$(mk_workdir)
mkdir -p "$WORK/clicky-config"
cat > "$WORK/clicky-config/config.json" << 'EOF'
{
  "default_password_wordlist": "/custom/path/wordlist.txt",
  "tool_provisioning": "none"
}
EOF
PATH="$CORE_PATH" \
    CLICKY_PREFLIGHT=off \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_LOCAL_BIN="$WORK/localbin" \
    CLICKY_CONFIG_DIR="$WORK/clicky-config" \
    CLICKY_CONFIG_PATH="$WORK/clicky-config/config.json" \
    CLICKY_CLAUDE_SETTINGS_PATH="$WORK/claude/settings.json" \
    bash "$WIZARD" > /dev/null << 'EOF'
n
n
EOF
check "idempotent: pre-existing custom value preserved across re-run" \
    "$(python3 -c "import json; print(json.load(open('$WORK/clicky-config/config.json'))['default_password_wordlist'])")" "/custom/path/wordlist.txt"
rm -rf "$WORK"

# --- bash 3.2 compatibility - the real target this suite exists for -----
echo ""
echo "=== Re-run Fixture 1 under real /bin/bash (macOS's frozen 3.2.57) ==="
WORK=$(mk_workdir)
OUT=$(PATH="$CORE_PATH" \
    CLICKY_PREFLIGHT=off \
    CLICKY_NIX_CANDIDATES= \
    CLICKY_LOCAL_BIN="$WORK/localbin" \
    CLICKY_CONFIG_DIR="$WORK/clicky-config" \
    CLICKY_CONFIG_PATH="$WORK/clicky-config/config.json" \
    CLICKY_CLAUDE_SETTINGS_PATH="$WORK/claude/settings.json" \
    /bin/bash "$WIZARD" << 'EOF'
n
n
EOF
)
contains "bash-3.2: still detects nothing installed correctly" "$OUT" "(none detected on PATH)"
check "bash-3.2: tool_provisioning written as none" \
    "$(python3 -c "import json; print(json.load(open('$WORK/clicky-config/config.json'))['tool_provisioning'])")" "none"
rm -rf "$WORK"

echo "=== Case: preflight RESOLVES missing dependencies, not just reports them ==="
# The fixtures above run with CLICKY_PREFLIGHT=off because preflight is the
# one step that installs software and uses the network. This case turns it
# back on deliberately.
#
# Background: on a fresh Kali install (python3.13, no python3.13-venv), the
# clicky-gateway MCP server failed to start for EVERY session and nothing in
# the install process said so. Since all 8 Clicky agents are provisioned with
# the gateway's tools and nothing else, that is a total outage rather than a
# degradation - the operator only discovered it when an agent dispatch
# produced an agent with no tools at all. Preflight exists to catch that at
# install time and to FIX it, not to print instructions and move on.
PRE_WORK=$(mktemp -d)
PRE_STUB=$(mktemp -d)
# No usable sudo, so the only way jq can appear is the rootless path.
printf '#!/bin/sh\nexit 1\n' > "$PRE_STUB/sudo"
chmod +x "$PRE_STUB/sudo"

if ! curl -sSf --max-time 15 -o /dev/null https://github.com 2>/dev/null; then
    echo "SKIP: no network - preflight resolves real dependencies by design"
else
    PRE_OUT=$(printf 'n\nn\nn\n' | env \
        PATH="$PRE_STUB:$CORE_PATH" \
        CLICKY_LOCAL_BIN="$PRE_WORK/localbin" \
        CLICKY_NIX_CANDIDATES= \
        CLICKY_CONFIG_DIR="$PRE_WORK/clicky-config" \
        CLICKY_CONFIG_PATH="$PRE_WORK/clicky-config/config.json" \
        CLICKY_CLAUDE_SETTINGS_PATH="$PRE_WORK/claude/settings.json" \
        CLAUDE_PLUGIN_DATA="$PRE_WORK/plugindata" \
        bash "$WIZARD" 2>&1)

    contains "preflight: reports jq missing" "$PRE_OUT" "jq: MISSING"
    contains "preflight: actually installs jq rather than only advising" "$PRE_OUT" "jq: installed"
    check "preflight: the installed jq binary really runs" \
        "$("$PRE_WORK/localbin/jq" --version >/dev/null 2>&1 && echo yes || echo no)" "yes"
    contains "preflight: provisions the gateway for real" "$PRE_OUT" "Gateway: READY"
    check "preflight: the provisioned venv can actually import mcp" \
        "$("$PRE_WORK/plugindata/venv/bin/python3" -c 'import mcp' >/dev/null 2>&1 && echo yes || echo no)" "yes"
    contains "preflight: summary reports the gateway ready" "$PRE_OUT" "MCP gateway:      ready"
    # A gateway provisioned mid-session is useless until the host restarts:
    # Claude Code attempts the MCP connection once at session start and does
    # not retry, which is why the original repair still needed a restart.
    contains "preflight: summary tells the operator to restart" "$PRE_OUT" "Restart your CLI host"

    echo "--- a tampered jq download must be refused, never installed ---"
    TAM_WORK=$(mktemp -d)
    TAM_STUB=$(mktemp -d)
    printf '#!/bin/sh\nexit 1\n' > "$TAM_STUB/sudo"
    chmod +x "$TAM_STUB/sudo"
    # curl stub returning an attacker-controlled payload for any -o fetch.
    cat > "$TAM_STUB/curl" <<'TAMPEREOF'
#!/bin/sh
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && printf '#!/bin/sh\necho PWNED\n' > "$out"
exit 0
TAMPEREOF
    chmod +x "$TAM_STUB/curl"

    TAM_OUT=$(printf 'n\nn\nn\n' | env \
        PATH="$TAM_STUB:$CORE_PATH" \
        CLICKY_LOCAL_BIN="$TAM_WORK/localbin" \
        CLICKY_NIX_CANDIDATES= \
        CLICKY_CONFIG_DIR="$TAM_WORK/clicky-config" \
        CLICKY_CONFIG_PATH="$TAM_WORK/clicky-config/config.json" \
        CLICKY_CLAUDE_SETTINGS_PATH="$TAM_WORK/claude/settings.json" \
        CLAUDE_PLUGIN_DATA="$TAM_WORK/plugindata" \
        bash "$WIZARD" 2>&1)

    contains "tamper: checksum mismatch is detected" "$TAM_OUT" "CHECKSUM MISMATCH"
    check "tamper: the tampered binary is NOT installed" \
        "$([ ! -e "$TAM_WORK/localbin/jq" ] && echo absent || echo present)" "absent"
    # Failure must never be reported as success.
    contains "tamper: gateway failure is surfaced, not swallowed" "$TAM_OUT" "Gateway: FAILED"
    contains "tamper: summary warns against running /pentest" "$TAM_OUT" "Do NOT run /pentest yet"
    rm -rf "$TAM_WORK" "$TAM_STUB"
fi
rm -rf "$PRE_WORK" "$PRE_STUB"

exit $FAILED
