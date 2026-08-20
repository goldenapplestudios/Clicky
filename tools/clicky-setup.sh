#!/bin/bash
#
# Clicky setup wizard: detect everything possible automatically, apply
# safe/reversible changes with no per-item confirmation, and ask for
# confirmation only before genuinely consequential, system-level,
# hard-to-reverse actions (installing Nix, installing a global CLI
# tool). Ends with one summary rather than a trail of prompts along the
# way. See the implementation plan this fulfills (Kalilix pentest-tool
# provisioning + a CLI-neutral setup wizard) for the full research trail.
#
# Pure bash - NO python3 (or any other interpreter) dependency for this
# default flow. This file was originally written in Python; rewritten to
# bash after a direct correction: a setup wizard whose whole job is
# getting someone from "nothing installed" to "Clicky works" cannot
# itself require an interpreter the operator might not have yet. bash is
# the one interpreter this repo already hard-requires everywhere
# (skills/mcp-gateway/scripts/launch.sh, every skill script, etc.), so
# it's the only safe assumption for an entry-point script. The one place
# this still reaches for an external tool is syncing Claude Code's
# ~/.claude/settings.json (real, unbounded, third-party-owned JSON - not
# safe to hand-edit with sed/grep the way this script's OWN simple flat
# ~/.clicky/config.json is) - tries jq first, then python3, and degrades
# to printing the exact block to paste in by hand if neither is present,
# never blocking the rest of the wizard on that one optional nicety.
#
# --advanced (per-agent framework/model assignment) is explicitly NOT
# part of this default flow and DOES require python3 - a fair ask for
# that path specifically, since it already needs
# tools/generate-cli-targets.py (itself Python, a maintainer tool per
# its own doc comment) to apply Codex/OpenCode overrides. Checked and
# reported plainly if missing, not silently assumed.
#
# Usage:
#   tools/clicky-setup.sh             # the 4-step guided flow
#   tools/clicky-setup.sh --advanced  # per-agent framework/model assignment (needs python3)
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

CLICKY_CONFIG_DIR="${CLICKY_CONFIG_DIR:-$HOME/.clicky}"
CLICKY_CONFIG_PATH="${CLICKY_CONFIG_PATH:-$CLICKY_CONFIG_DIR/config.json}"
# Overridable for tests - never touch the operator's real global settings
# file from an automated test run. See tests/setup_wizard/ for why this
# matters (an early manual test of the Python predecessor of this script
# once wrote to the real file, before this override existed).
CLAUDE_SETTINGS_PATH="${CLICKY_CLAUDE_SETTINGS_PATH:-$HOME/.claude/settings.json}"

KALILIX_FLAKE_REGISTRY_NAME="kalilix"
KALILIX_FLAKE_URL="github:scopecreep-zip/kalilix"

# The tools Kalilix's #kali devShell provides, per its own KALI_SHELL.md
# (confirmed against the real upstream repo). NOTE: Kalilix's own doc
# states "Total: 32 Security Tools" in prose, but its own
# category-by-category table (which this list transcribes exactly) sums
# to 33 distinct tool names - an inconsistency in their docs, not a
# transcription error here.
KALILIX_TOOLS=(
    ffuf gobuster dirb sqlmap nikto wpscan burpsuite
    nmap masscan nc socat
    john hashcat hydra medusa
    enum4linux enum4linux-ng
    dnsenum
    aircrack-ng
    theharvester whatweb recon-ng
    vol volatility2
    radare2 objdump strings binwalk
    metasploit
    wireshark tcpdump
    curl wget
)

# Kalilix's own documented Lix install command (README.md, "Installation
# (4 Commands)", step 1) - shown to the operator in full before running,
# never run silently.
LIX_INSTALL_CMD='curl -sSf -L https://install.lix.systems/lix | sh -s -- install \
    --no-confirm \
    --extra-conf "experimental-features = nix-command flakes" \
    --extra-conf "allow-unfree = true" \
    --extra-conf "warn-dirty = false"'

CODEX_INSTALL_CMD="npm install -g @openai/codex@latest"

_header() {
    echo
    echo "[$1] $2"
    local rule_len=$((${#1} + ${#2} + 4))
    printf '%*s\n' "$rule_len" '' | tr ' ' '-'
}

_confirm() {
    local answer
    read -r -p "$1 [y/N] " answer
    case "$answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# --- [1/4] Detect --------------------------------------------------------

CLI_CLAUDE=""; CLI_OPENCODE=""; CLI_CODEX=""; CLI_COPILOT=""
FOUND_TOOLS_COUNT=0
NIX_PRESENT="false"

detect() {
    _header "1/4" "Detecting your environment"

    CLI_CLAUDE="$(command -v claude 2>/dev/null || true)"
    CLI_OPENCODE="$(command -v opencode 2>/dev/null || true)"
    CLI_CODEX="$(command -v codex 2>/dev/null || true)"
    CLI_COPILOT="$(command -v copilot 2>/dev/null || true)"

    FOUND_TOOLS_COUNT=0
    for t in "${KALILIX_TOOLS[@]}"; do
        command -v "$t" >/dev/null 2>&1 && FOUND_TOOLS_COUNT=$((FOUND_TOOLS_COUNT + 1))
    done

    if command -v nix >/dev/null 2>&1; then
        NIX_PRESENT="true"
    fi

    echo "  Platform: $(uname -s) $(uname -m)"
    echo "  AI CLI hosts found:"
    local any=0
    [ -n "$CLI_CLAUDE" ] && { echo "    - claude: $CLI_CLAUDE"; any=1; }
    [ -n "$CLI_OPENCODE" ] && { echo "    - opencode: $CLI_OPENCODE"; any=1; }
    [ -n "$CLI_CODEX" ] && { echo "    - codex: $CLI_CODEX"; any=1; }
    [ -n "$CLI_COPILOT" ] && { echo "    - copilot: $CLI_COPILOT"; any=1; }
    [ "$any" -eq 0 ] && echo "    (none detected on PATH)"
    echo "  Pentest tools already on PATH: $FOUND_TOOLS_COUNT/${#KALILIX_TOOLS[@]} of Kalilix's set"
    if [ "$NIX_PRESENT" = "true" ]; then
        echo "  Nix: present"
    else
        echo "  Nix: not found"
    fi
    if [ -f "$CLICKY_CONFIG_PATH" ]; then
        echo "  Existing config found at $CLICKY_CONFIG_PATH - values below default to what's already there"
    fi
}

# --- [2/4] Pentest tools (Kalilix) ---------------------------------------

TOOL_PROVISIONING="none"

offer_kalilix() {
    _header "2/4" "Pentest tools (Kalilix)"
    echo "  Clicky can give agents a real, reproducible pentest toolkit -"
    echo "  ${#KALILIX_TOOLS[@]} tools (nmap, sqlmap, hydra, metasploit, and more) via"
    echo "  Kalilix (github.com/scopecreep-zip/kalilix), a Nix flake. No manual"
    echo "  installs, no version drift - the same tools every time, on"
    echo "  macOS/Linux/WSL."

    if [ "$NIX_PRESENT" != "true" ]; then
        echo
        echo "  This requires Nix, which isn't installed. Here's exactly what would run"
        echo "  (Kalilix's own documented installer, https://lix.systems/install/):"
        echo
        echo "    $LIX_INSTALL_CMD"
        echo
        if _confirm "  Install Nix now?"; then
            echo "  Installing Nix (this can take a minute)..."
            local nix_install_log="/tmp/clicky-nix-install.$$"
            if ! sh -c "$LIX_INSTALL_CMD" > "$nix_install_log" 2>&1; then
                echo "  ✗ Nix install failed:"
                tail -c 500 "$nix_install_log" | sed 's/^/    /'
                rm -f "$nix_install_log"
                echo "  Skipping Kalilix for now. Re-run this wizard after installing Nix yourself."
                TOOL_PROVISIONING="none"
                return
            fi
            rm -f "$nix_install_log"
            echo "  ✓ Nix installed"
            NIX_PRESENT="true"
            # A fresh Nix install commonly needs its own profile script
            # sourced before `nix` resolves in THIS shell (the installer
            # sets up ~/.nix-profile/etc/profile.d/nix.sh or similar) -
            # try the standard locations rather than telling the operator
            # to restart their terminal mid-wizard.
            for profile in "/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh" \
                            "$HOME/.nix-profile/etc/profile.d/nix.sh"; do
                [ -f "$profile" ] && . "$profile" 2>/dev/null
            done
            if ! command -v nix >/dev/null 2>&1; then
                echo "  Nix installed but not yet on PATH in this shell - re-run this wizard in a new terminal to continue."
                TOOL_PROVISIONING="none"
                return
            fi
        else
            echo "  Skipping - agents will use whatever's already on your PATH."
            echo "  Re-run this wizard anytime to enable this."
            TOOL_PROVISIONING="none"
            return
        fi
    fi

    echo
    echo "  Registering the '$KALILIX_FLAKE_REGISTRY_NAME' flake shortcut..."
    nix registry add "$KALILIX_FLAKE_REGISTRY_NAME" "$KALILIX_FLAKE_URL" >/dev/null 2>&1

    echo "  Pre-warming the local Nix store (first time may take a while)..."
    if ! nix develop "$KALILIX_FLAKE_REGISTRY_NAME#kali" --command true >/tmp/clicky-kalilix-probe.$$ 2>&1; then
        echo "  ✗ Kalilix's #kali shell failed to build/fetch:"
        tail -c 500 "/tmp/clicky-kalilix-probe.$$" | sed 's/^/    /'
        rm -f "/tmp/clicky-kalilix-probe.$$"
        echo "  Leaving tool_provisioning=none - launch.sh will also detect this and fall back safely."
        TOOL_PROVISIONING="none"
        return
    fi
    rm -f "/tmp/clicky-kalilix-probe.$$"

    local coverage_script="" t
    for t in "${KALILIX_TOOLS[@]}"; do
        coverage_script="${coverage_script}command -v $t >/dev/null 2>&1 && echo $t; "
    done
    # Write to a temp file rather than a process-substitution `while read`
    # loop - confirmed earlier in this same feature's development that a
    # heredoc nested inside `<(...)` breaks under bash 3.2 (macOS's
    # frozen /bin/bash); this call has no heredoc, but writing to a file
    # first keeps every subprocess-output-consumption in this script
    # using the one pattern already proven safe on that target, rather
    # than assuming this particular case is fine.
    local coverage_out="/tmp/clicky-kalilix-coverage.$$"
    nix develop "$KALILIX_FLAKE_REGISTRY_NAME#kali" --command bash -c "$coverage_script" > "$coverage_out" 2>/dev/null

    local found_count=0 found_tools=() missing_tools=()
    while IFS= read -r line; do
        [ -n "$line" ] && { found_count=$((found_count + 1)); found_tools+=("$line"); }
    done < "$coverage_out"
    rm -f "$coverage_out"

    for t in "${KALILIX_TOOLS[@]}"; do
        local is_found="false" f
        for f in "${found_tools[@]:-}"; do
            [ "$f" = "$t" ] && { is_found="true"; break; }
        done
        [ "$is_found" = "false" ] && missing_tools+=("$t")
    done

    echo "  ✓ Kalilix ready - $found_count/${#KALILIX_TOOLS[@]} tools available on this platform"
    if [ "${#missing_tools[@]}" -gt 0 ]; then
        local missing_str="${missing_tools[*]}"
        echo "    Not available on this platform: ${missing_str// /, }"
    fi
    TOOL_PROVISIONING="kalilix"
}

# --- [3/4] Cross-provider severity review --------------------------------

SEVERITY_REVIEW_STATUS="fallback"

offer_codex_for_severity_review() {
    _header "3/4" "Cross-checked severity scoring"
    echo "  Clicky's severity-analyst-agent double-checks a report's severity"
    echo "  ratings using a SECOND, independent AI provider (Codex/GPT) rather than"
    echo "  reviewing itself. Research this design is based on found that"
    echo "  same-provider 'adversarial' review shares correlated blind spots that"
    echo "  get worse with model capability, not better - see"
    echo "  agents/severity-analyst-agent.md's 'Why This Exists' section. Requires"
    echo "  Codex CLI. Without it, severity review still runs - just in a weaker,"
    echo "  same-provider fallback mode."

    if [ -z "$CLI_CODEX" ]; then
        echo
        echo "  Codex CLI isn't installed. Here's exactly what would run:"
        echo
        echo "    $CODEX_INSTALL_CMD"
        echo
        if ! command -v npm >/dev/null 2>&1; then
            echo "  npm isn't on PATH either, so this wizard can't install it for you."
            echo "  Install Node.js/npm first, then re-run this wizard."
            SEVERITY_REVIEW_STATUS="not_installed"
            return
        fi
        if _confirm "  Install Codex CLI now?"; then
            echo "  Installing Codex CLI..."
            local codex_install_log="/tmp/clicky-codex-install.$$"
            if ! npm install -g @openai/codex@latest > "$codex_install_log" 2>&1; then
                echo "  ✗ Codex CLI install failed:"
                tail -c 500 "$codex_install_log" | sed 's/^/    /'
                rm -f "$codex_install_log"
                SEVERITY_REVIEW_STATUS="not_installed"
                return
            fi
            rm -f "$codex_install_log"
            echo "  ✓ Codex CLI installed"
            CLI_CODEX="$(command -v codex 2>/dev/null || true)"
        else
            echo "  Skipping - severity review will use the same-provider fallback."
            SEVERITY_REVIEW_STATUS="not_installed"
            return
        fi
    fi

    echo "  Checking whether Codex CLI is authenticated and working..."
    local probe_out
    probe_out="$(codex exec "respond with exactly: OK" 2>/dev/null)"
    if printf '%s' "$probe_out" | grep -q "OK"; then
        echo "  ✓ Cross-provider severity review ready"
        SEVERITY_REVIEW_STATUS="ready"
        return
    fi

    echo "  Codex CLI is installed but not ready yet (likely not signed in)."
    echo "  Run \`codex login\` to finish this, then re-run this wizard to confirm."
    echo "  Severity review will use the same-provider fallback until then."
    SEVERITY_REVIEW_STATUS="needs_auth"
}

# --- [4/4] Apply ----------------------------------------------------------

# Reads one string/number/boolean value for `key` out of our OWN,
# known-flat-shape config.json - safe to do with grep/sed here
# specifically because this script controls both the writer and reader
# of this exact file (one `"key": value` pair per line, always). This is
# NOT a general JSON parser and must never be pointed at a file this
# script doesn't itself own (see sync_claude_settings() below, which
# reaches for jq/python3 instead for exactly that reason - Claude Code's
# settings.json is arbitrary, third-party-shaped JSON).
_own_config_get() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 1
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*//p" "$file" \
        | head -1 \
        | sed -e 's/,[[:space:]]*$//' -e 's/^"//' -e 's/"$//'
}

write_clicky_config() {
    local tool_provisioning="$1"
    local pw_wordlist un_wordlist web_wordlist_dir max_parallel confirm_before scope_enf calib_min

    pw_wordlist="$(_own_config_get "$CLICKY_CONFIG_PATH" default_password_wordlist)"
    pw_wordlist="${pw_wordlist:-/usr/share/wordlists/rockyou.txt}"
    un_wordlist="$(_own_config_get "$CLICKY_CONFIG_PATH" default_username_wordlist)"
    un_wordlist="${un_wordlist:-/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt}"
    web_wordlist_dir="$(_own_config_get "$CLICKY_CONFIG_PATH" default_web_wordlist_dir)"
    max_parallel="$(_own_config_get "$CLICKY_CONFIG_PATH" max_parallel_operations)"
    max_parallel="${max_parallel:-3}"
    confirm_before="$(_own_config_get "$CLICKY_CONFIG_PATH" require_confirmation_before_exploitation)"
    confirm_before="${confirm_before:-false}"
    scope_enf="$(_own_config_get "$CLICKY_CONFIG_PATH" scope_enforcement)"
    scope_enf="${scope_enf:-enforce}"
    calib_min="$(_own_config_get "$CLICKY_CONFIG_PATH" calibration_min_sample_size)"
    calib_min="${calib_min:-5}"

    mkdir -p "$CLICKY_CONFIG_DIR"
    local made_backup="false"
    if [ -f "$CLICKY_CONFIG_PATH" ]; then
        cp "$CLICKY_CONFIG_PATH" "$CLICKY_CONFIG_PATH.bak.$(date -u +%Y%m%dT%H%M%SZ)"
        made_backup="true"
    fi

    {
        echo "{"
        echo "  \"default_password_wordlist\": \"$pw_wordlist\","
        echo "  \"default_username_wordlist\": \"$un_wordlist\","
        if [ -n "$web_wordlist_dir" ]; then
            echo "  \"default_web_wordlist_dir\": \"$web_wordlist_dir\","
        fi
        echo "  \"max_parallel_operations\": $max_parallel,"
        echo "  \"require_confirmation_before_exploitation\": $confirm_before,"
        echo "  \"scope_enforcement\": \"$scope_enf\","
        echo "  \"calibration_min_sample_size\": $calib_min,"
        echo "  \"tool_provisioning\": \"$tool_provisioning\""
        echo "}"
    } > "$CLICKY_CONFIG_PATH"

    if [ "$made_backup" = "true" ]; then
        echo "  ✓ Wrote $CLICKY_CONFIG_PATH (backup saved)"
    else
        echo "  ✓ Wrote $CLICKY_CONFIG_PATH"
    fi
}

sync_claude_settings() {
    local tool_provisioning="$1"
    local pw_wordlist un_wordlist max_parallel confirm_before scope_enf calib_min
    pw_wordlist="$(_own_config_get "$CLICKY_CONFIG_PATH" default_password_wordlist)"
    un_wordlist="$(_own_config_get "$CLICKY_CONFIG_PATH" default_username_wordlist)"
    max_parallel="$(_own_config_get "$CLICKY_CONFIG_PATH" max_parallel_operations)"
    confirm_before="$(_own_config_get "$CLICKY_CONFIG_PATH" require_confirmation_before_exploitation)"
    scope_enf="$(_own_config_get "$CLICKY_CONFIG_PATH" scope_enforcement)"
    calib_min="$(_own_config_get "$CLICKY_CONFIG_PATH" calibration_min_sample_size)"

    local options_json
    options_json=$(cat << JSONEOF
{"default_password_wordlist":"$pw_wordlist","default_username_wordlist":"$un_wordlist","max_parallel_operations":$max_parallel,"require_confirmation_before_exploitation":$confirm_before,"scope_enforcement":"$scope_enf","calibration_min_sample_size":$calib_min,"tool_provisioning":"$tool_provisioning"}
JSONEOF
)

    mkdir -p "$(dirname "$CLAUDE_SETTINGS_PATH")"
    local backup=""
    if [ -f "$CLAUDE_SETTINGS_PATH" ]; then
        backup="$CLAUDE_SETTINGS_PATH.bak.$(date -u +%Y%m%dT%H%M%SZ)"
        cp "$CLAUDE_SETTINGS_PATH" "$backup"
    fi

    if command -v jq >/dev/null 2>&1; then
        local existing="{}"
        [ -f "$CLAUDE_SETTINGS_PATH" ] && existing="$(cat "$CLAUDE_SETTINGS_PATH")"
        if ! printf '%s' "$existing" | jq --argjson opts "$options_json" \
            '.pluginConfigs.clicky.options = $opts' > "$CLAUDE_SETTINGS_PATH.tmp.$$" 2>/dev/null; then
            rm -f "$CLAUDE_SETTINGS_PATH.tmp.$$"
            echo "  ✗ Couldn't parse $CLAUDE_SETTINGS_PATH with jq - skipping Claude Code sync (your other settings are untouched)"
            _print_manual_settings_block "$options_json"
            return
        fi
        mv "$CLAUDE_SETTINGS_PATH.tmp.$$" "$CLAUDE_SETTINGS_PATH"
        echo "  ✓ Synced to Claude Code ($CLAUDE_SETTINGS_PATH${backup:+, backup: $(basename "$backup")})"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$CLAUDE_SETTINGS_PATH" "$options_json" << 'PYEOF'
import json, sys
settings_path, options_json = sys.argv[1], sys.argv[2]
settings = {}
try:
    with open(settings_path) as f:
        settings = json.load(f)
except (OSError, ValueError):
    pass
settings.setdefault("pluginConfigs", {}).setdefault("clicky", {})["options"] = json.loads(options_json)
with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
        echo "  ✓ Synced to Claude Code ($CLAUDE_SETTINGS_PATH${backup:+, backup: $(basename "$backup")})"
    else
        echo "  - Neither jq nor python3 found - can't safely sync $CLAUDE_SETTINGS_PATH automatically"
        echo "    (this is a convenience only - launch.sh already reads ~/.clicky/config.json directly)"
        _print_manual_settings_block "$options_json"
    fi
}

_print_manual_settings_block() {
    echo "    To sync by hand, merge this into $CLAUDE_SETTINGS_PATH's top-level object:"
    echo "      \"pluginConfigs\": {\"clicky\": {\"options\": $1}}"
}

sync_codex_registration() {
    [ -n "$CLI_CODEX" ] || return
    local install_script="$REPO_ROOT/.codex/install.sh"
    [ -f "$install_script" ] || return
    if codex mcp list 2>/dev/null | grep -q "clicky-gateway"; then
        echo "  ✓ Codex CLI already has clicky-gateway registered"
        return
    fi
    echo "  Registering clicky-gateway with Codex CLI..."
    if bash "$install_script" >/dev/null 2>&1; then
        echo "  ✓ Registered clicky-gateway with Codex CLI"
    else
        echo "  ✗ Codex registration failed - run .codex/install.sh yourself to see why"
    fi
}

apply_all() {
    _header "4/4" "Applying configuration"
    write_clicky_config "$TOOL_PROVISIONING"

    if [ -n "$CLI_CLAUDE" ]; then
        sync_claude_settings "$TOOL_PROVISIONING"
    else
        echo "  - Claude Code not detected, skipping settings.json sync"
    fi

    if [ -n "$CLI_CODEX" ]; then
        sync_codex_registration
    else
        echo "  - Codex CLI not detected, skipping MCP registration"
    fi

    if [ -n "$CLI_OPENCODE" ]; then
        echo "  - opencode: already reads config from ~/.clicky/config.json via launch.sh, nothing further to apply"
    else
        echo "  - opencode not detected, skipping"
    fi
    if [ -n "$CLI_COPILOT" ]; then
        echo "  - copilot: already reads config from ~/.clicky/config.json via launch.sh, nothing further to apply"
    else
        echo "  - copilot not detected, skipping"
    fi
}

print_summary() {
    echo
    echo "============================================================"
    echo "Done."
    echo "============================================================"
    if [ "$TOOL_PROVISIONING" = "kalilix" ]; then
        echo "  Pentest tools:    Kalilix enabled - agents get the real toolkit"
    else
        echo "  Pentest tools:    not provisioned - agents see whatever's on PATH ($FOUND_TOOLS_COUNT/${#KALILIX_TOOLS[@]} of Kalilix's set already found)"
    fi

    case "$SEVERITY_REVIEW_STATUS" in
        ready) echo "  Severity review:  cross-provider ✓" ;;
        needs_auth) echo "  Severity review:  same-provider fallback - run \`codex login\`, then re-run this wizard" ;;
        *) echo "  Severity review:  same-provider fallback" ;;
    esac

    local detected=""
    [ -n "$CLI_CLAUDE" ] && detected="${detected}claude, "
    [ -n "$CLI_OPENCODE" ] && detected="${detected}opencode, "
    [ -n "$CLI_CODEX" ] && detected="${detected}codex, "
    [ -n "$CLI_COPILOT" ] && detected="${detected}copilot, "
    detected="${detected%, }"
    echo "  Config applied to: ${detected:-(no AI CLI hosts detected)}"
    echo
    echo "  Advanced: assign specific agents to specific frameworks/models with:"
    echo "    tools/clicky-setup.sh --advanced"
    echo
    echo "  Run /pentest <target> to get started."
}

run_default_flow() {
    detect
    offer_kalilix
    offer_codex_for_severity_review
    apply_all
    print_summary
}

run_advanced_flow() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "The --advanced per-agent framework/model assignment needs python3"
        echo "(it already needs tools/generate-cli-targets.py, itself Python, to"
        echo "apply Codex/OpenCode overrides - a fair ask for this specific, opt-in,"
        echo "power-user path, unlike the default wizard flow above)."
        echo "Install python3, then re-run: tools/clicky-setup.sh --advanced"
        return 1
    fi
    exec python3 "$REPO_ROOT/tools/advanced_agent_assignment.py"
}

main() {
    if [ "${1:-}" = "--advanced" ]; then
        run_advanced_flow
        return $?
    fi
    run_default_flow
}

main "$@"
