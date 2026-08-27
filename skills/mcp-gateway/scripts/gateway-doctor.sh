#!/bin/bash
#
# gateway-doctor.sh - end-to-end health check for the Clicky MCP gateway.
#
# Why this exists: every Clicky agent holds ONLY gateway tools
# (mcp__plugin_clicky_clicky-gateway__*). When the gateway fails to connect an
# agent has no tools at all - and the observed failure mode is not a loud stop
# but a silent degrade. In a real engagement the API-security stage reported:
# "the mcp__plugin_clicky_clicky-gateway__* tools were not exposed to this
# subagent (ToolSearch returned no matches), so testing ran via Bash with the
# target manually tokenized."
#
# That fallback is worse than a crash, for two reasons. It defeats the privacy
# gateway outright - the entire point is that raw target/credential values
# never transit the model, and "manually tokenized" means they did. And it
# yields a report that looks complete while the tool chain it claims to have
# used was never running.
#
# The gateway is therefore a hard precondition, and this script is how an
# engagement proves it before starting. Every check names its own remediation,
# because a health check that reports only "unhealthy" just relocates the
# debugging cost.
#
# Exit codes:
#   0  healthy - safe to start an engagement
#   1  unhealthy - DO NOT start an engagement; output says which link is broken
#
# Usage: gateway-doctor.sh [--quiet]
set -uo pipefail

QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "$HERE/.." && pwd)"
LAUNCH_SH="$HERE/launch.sh"

FAILED=0
say() { [ "$QUIET" -eq 1 ] || echo "$@"; }
ok()  { say "  OK    $1"; }
bad() { echo "  FAIL  $1"; [ -n "${2:-}" ] && echo "        -> $2"; FAILED=1; }

say "Clicky MCP gateway health check"
say ""

# --- 1. the launcher --------------------------------------------------------
if [ -x "$LAUNCH_SH" ]; then
    ok "launcher present: $LAUNCH_SH"
else
    bad "launcher missing or not executable: $LAUNCH_SH" \
        "plugin.json registers \${CLAUDE_PLUGIN_ROOT}/skills/mcp-gateway/scripts/launch.sh"
fi

# A PATH copy is how the generated OpenCode/Codex/Copilot targets reach the
# gateway - they resolve it by name, never by absolute path.
if command -v clicky-gateway >/dev/null 2>&1; then
    resolved="$(command -v clicky-gateway)"
    ok "clicky-gateway on PATH: $resolved"
    real="$(readlink -f "$resolved" 2>/dev/null)"
    expected="$(readlink -f "$LAUNCH_SH" 2>/dev/null)"
    if [ -n "$real" ] && [ -n "$expected" ] && [ "$real" != "$expected" ]; then
        bad "clicky-gateway on PATH points at a DIFFERENT checkout: $real" \
            "expected $expected - re-run tools/clicky-setup.sh"
    fi
else
    say "  NOTE  clicky-gateway not on PATH (only needed for OpenCode/Codex/Copilot targets)"
fi

# --- 2. the virtualenv ------------------------------------------------------
VENV_DIR=""
if [ -x "$HERE/provision-venv.sh" ]; then
    VENV_DIR="$(timeout 600 bash "$HERE/provision-venv.sh" 2>/dev/null | tail -1)"
fi
if [ -n "$VENV_DIR" ] && [ -x "$VENV_DIR/bin/python3" ]; then
    ok "venv provisioned: $VENV_DIR"
else
    bad "venv not provisioned (provision-venv.sh produced no usable python)" \
        "run: bash $HERE/provision-venv.sh"
fi

# --- 3. dependencies and module import -------------------------------------
if [ -n "$VENV_DIR" ] && [ -x "$VENV_DIR/bin/python3" ]; then
    missing=""
    for mod in mcp httpx2 pydantic; do
        "$VENV_DIR/bin/python3" -c "import $mod" 2>/dev/null || missing="$missing $mod"
    done
    if [ -z "$missing" ]; then
        ok "python dependencies importable (mcp, httpx2, pydantic)"
    else
        bad "missing python dependencies:$missing" "run: bash $HERE/provision-venv.sh"
    fi

    if err="$(cd "$GATEWAY_DIR" && "$VENV_DIR/bin/python3" -c "import sys; sys.path.insert(0,'.'); import server" 2>&1)"; then
        ok "server.py imports cleanly"
    else
        bad "server.py failed to import" "$(echo "$err" | tail -3 | tr '\n' ' ')"
    fi
fi

# --- 3b. the Kalilix toolchain (lazy, so NOT part of startup) ---------------
#
# Reported separately from the handshake on purpose. Since the toolchain is
# resolved lazily on first execute_command rather than before the server
# starts, a cold or broken toolchain no longer prevents the gateway from
# connecting - it degrades what agents can run. Those are different failures
# and deserve different lines.
if [ "${CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING:-none}" = "kalilix" ]; then
    if [ -x "$HERE/toolchain-path.sh" ]; then
        if out="$(bash "$HERE/toolchain-path.sh" --check 2>&1)"; then
            ok "Kalilix toolchain cache is warm and valid"
        else
            # Not a failure: the next execute_command resolves it. Say so
            # rather than reporting a healthy gateway as broken.
            say "  NOTE  toolchain cache cold or stale - the first command of the"
            say "        next engagement will resolve it (~45s, once). $(printf '%s' "$out" | tail -1)"
        fi
    else
        bad "toolchain-path.sh missing at $HERE/toolchain-path.sh" \
            "server.py calls it lazily; without it Kalilix tools never reach agents"
    fi
else
    say "  NOTE  tool_provisioning is not 'kalilix' - agents use the ambient PATH"
fi

# --- 4. a real MCP handshake ------------------------------------------------
# The decisive check: every test above can pass while the server still fails to
# speak the protocol. This drives launch.sh exactly as an MCP client does, over
# real stdio, using only the SYSTEM python so the check never depends on the
# component it is testing.
if [ "$FAILED" -eq 0 ] && [ -x "$LAUNCH_SH" ]; then
    handshake_out="$(timeout 240 python3 "$HERE/gateway_handshake_probe.py" "$LAUNCH_SH" --timeout 180 2>&1)"
    handshake="$(printf '%s\n' "$handshake_out" | head -1)"
    # The probe emits NOTE:/WARN: lines after its verdict. WARN means the server
    # violated the stdio transport contract (non-MCP data on stdout), which
    # breaks strict clients even when this lenient probe still succeeds - so it
    # is a failure here, not a footnote.
    while IFS= read -r extra; do
        case "$extra" in
            NOTE:*) say "  ${extra}" ;;
            WARN:*) bad "${extra#WARN: }" "the stdio transport requires that stdout carry MCP messages only" ;;
        esac
    done < <(printf '%s\n' "$handshake_out" | tail -n +2)
    case "$handshake" in
        TOOLS\ *)
            names="${handshake#TOOLS }"
            ok "MCP handshake succeeded"
            missing_tools=""
            for t in create_session register_target execute_command fetch_url \
                     read_file write_file search_files; do
                case ",$names," in *",$t,"*) ;; *) missing_tools="$missing_tools $t" ;; esac
            done
            if [ -z "$missing_tools" ]; then
                ok "all required tools exposed ($(echo "$names" | tr ',' ' ' | wc -w) total)"
            else
                bad "gateway connected but is missing tools:$missing_tools" \
                    "server.py may not be the version this checkout expects"
            fi
            ;;
        NO_INITIALIZE_RESPONSE*)
            bad "gateway did not answer 'initialize' over stdio" \
                "run 'bash $LAUNCH_SH' by hand and read its stderr" ;;
        NO_TOOLS_LIST*)
            bad "gateway initialized but did not answer 'tools/list'" \
                "run 'bash $LAUNCH_SH' by hand and read its stderr" ;;
        *)
            bad "MCP handshake failed" "${handshake:-timed out}" ;;
    esac
elif [ "$FAILED" -ne 0 ]; then
    say "  SKIP  MCP handshake not attempted - fix the failures above first"
fi

# --- CVP org binding (informational, never fails the check) ----------------
# Anthropic's real-time cyber safeguards gate offensive dual-use work
# per-ORGANIZATION; a Cyber Verification Program approval is scoped to a
# specific org UUID. On a real engagement, offensive subagents were terminated
# mid-run with a [cyber] error while the session's org was not the approved
# one. Surface the org so the operator can confirm it instead of guessing.
say ""
say "Cyber Verification Program (org binding):"
_claude_json="${HOME}/.claude.json"
if [ -f "$_claude_json" ] && command -v python3 >/dev/null 2>&1; then
    _org=$(python3 -c 'import json,sys
try:
    a = json.load(open(sys.argv[1])).get("oauthAccount", {})
    uuid = a.get("organizationUuid") or "?"
    label = a.get("organizationName") or a.get("emailAddress") or "?"
    print(f"{uuid}  ({label})")
except Exception:
    print("")' "$_claude_json" 2>/dev/null)
    if [ -n "$_org" ]; then
        say "  authenticated org: $_org"
        say "  CVP is org-scoped: confirm THIS org is your approved one. If offensive"
        say "  subagents are terminated with a [cyber] error even though you are"
        say "  approved, the approval is likely bound to a different org (switch with"
        say "  /login) or still propagating - it is not a gateway fault."
    else
        say "  could not read org from $_claude_json (informational only)"
    fi
else
    say "  (skipped: no $_claude_json or python3 - informational only)"
fi

say ""
if [ "$FAILED" -eq 0 ]; then
    say "HEALTHY: the gateway is reachable and exposes its tools."
    exit 0
fi
echo ""
echo "UNHEALTHY: do NOT start an engagement."
echo "Every Clicky agent holds only gateway tools, so a broken gateway does not"
echo "fail loudly - it produces agents that silently fall back to other tooling,"
echo "leaking raw target values through the model and reporting results from a"
echo "tool chain that was never running."
exit 1
