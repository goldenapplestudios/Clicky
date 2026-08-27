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
#   tools/clicky-setup.sh             # the 5-step guided flow
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

# --- [1/5] Required dependencies + gateway provisioning ------------------
#
# This step exists because of a real, total outage on a fresh Kali install
# (python3.13, no python3.13-venv package): the clicky-gateway MCP server
# failed to start for every session, and nothing in the install process
# ever said so. The operator only found out when /clicky:pentest dispatched
# a recon-agent that had zero working tools - because all 8 Clicky agents
# are provisioned with the gateway's tools and nothing else, a dead gateway
# is a dead framework, not a degraded one.
#
# Two distinct gaps are closed here:
#
#   1. jq was an undeclared hard dependency. 17 scripts shell out to it,
#      including session-management/scripts/session-manager.sh (which
#      create_session itself calls) and report-generation/scripts/
#      report-generator.sh. The wizard previously only used jq as an
#      optional nicety for settings.json sync and degraded gracefully when
#      it was absent, which made it look far more optional than it is.
#
#   2. Nothing ever verified the gateway could actually be provisioned.
#      This step now RUNS provision-venv.sh rather than checking for
#      by-products of it, because "the venv directory exists" was exactly
#      the assumption that let the original bug hide - see that script's
#      "Why the health check is not just..." header note.

REQUIRED_MISSING=()
GATEWAY_READY="false"

# Where rootless fallback installs land. On PATH by default on most Linux
# distributions (Debian/Kali's /etc/skel/.profile, systemd's user
# environment) and on macOS under Homebrew-managed shells.
CLICKY_LOCAL_BIN="${CLICKY_LOCAL_BIN:-$HOME/.local/bin}"

# jq is pinned rather than floating, and verified against the SHA-256 sums
# jq publishes with that exact release. Hardcoding the digests (instead of
# fetching sha256sum.txt alongside the binary) is what makes this check
# meaningful: a digest downloaded from the same place as the artifact
# authenticates nothing. This defends against a corrupted/truncated
# download and a tampered mirror or MITM. It does not defend against a
# compromised upstream release - nothing at this layer could.
JQ_PINNED_VERSION="1.7.1"
_jq_expected_sha256() {
    case "$1" in
        jq-linux-amd64) echo "5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5" ;;
        jq-linux-arm64) echo "4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5" ;;
        jq-macos-amd64) echo "4155822bbf5ea90f5c79cf254665975eb4274d426d0709770c21774de5407443" ;;
        jq-macos-arm64) echo "0bbe619e663e0de2c550be2fe0d240d076799d6f8a652b70fa04aea8a8362e8a" ;;
        *) echo "" ;;
    esac
}

_jq_asset_name() {
    local os arch
    case "$(uname -s)" in
        Linux) os="linux" ;;
        Darwin) os="macos" ;;
        *) echo ""; return ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) echo ""; return ;;
    esac
    echo "jq-${os}-${arch}"
}

_sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else echo ""
    fi
}

# Package-manager install line, used for the sudo path and for the
# last-resort message.
_install_hint() {
    local pkg="$1"
    if command -v apt >/dev/null 2>&1; then echo "sudo apt install -y $pkg"
    elif command -v dnf >/dev/null 2>&1; then echo "sudo dnf install -y $pkg"
    elif command -v pacman >/dev/null 2>&1; then echo "sudo pacman -S --noconfirm $pkg"
    elif command -v zypper >/dev/null 2>&1; then echo "sudo zypper install -y $pkg"
    elif command -v brew >/dev/null 2>&1; then echo "brew install $pkg"
    else echo "install '$pkg' with your system package manager"
    fi
}

# True when we can install a system package without stopping to prompt for
# a password - i.e. already root, or sudo is cached/NOPASSWD.
_can_sudo_noninteractive() {
    [ "$(id -u)" = "0" ] && return 0
    command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1
}

# Install jq without requiring root, by fetching the official pinned static
# binary. This is the difference between a preflight that reports a problem
# and one that resolves it: jq is a hard dependency of 17 scripts (including
# session-manager.sh, which create_session itself calls), and on a locked-
# down box `sudo apt install jq` may simply not be available to the
# operator. A single statically-linked binary needs no root and no runtime
# deps.
_install_jq_rootless() {
    local asset expected tmp actual
    asset="$(_jq_asset_name)"
    [ -n "$asset" ] || { echo "  (no prebuilt jq for $(uname -s)/$(uname -m))"; return 1; }
    expected="$(_jq_expected_sha256 "$asset")"
    [ -n "$expected" ] || { echo "  (no pinned checksum for $asset)"; return 1; }
    command -v curl >/dev/null 2>&1 || { echo "  (curl unavailable - cannot fetch jq)"; return 1; }

    tmp="$(mktemp)"
    if ! curl -sSL --max-time 120 -o "$tmp" \
        "https://github.com/jqlang/jq/releases/download/jq-${JQ_PINNED_VERSION}/${asset}"; then
        echo "  (download failed)"
        rm -f "$tmp"
        return 1
    fi

    actual="$(_sha256_of "$tmp")"
    if [ -z "$actual" ]; then
        echo "  (no sha256sum/shasum available to verify the download - refusing to install an unverified binary)"
        rm -f "$tmp"
        return 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "  (CHECKSUM MISMATCH for $asset - refusing to install)"
        echo "     expected: $expected"
        echo "     actual:   $actual"
        rm -f "$tmp"
        return 1
    fi

    mkdir -p "$CLICKY_LOCAL_BIN"
    # 755, not `chmod +x` - mktemp creates at 600, so `+x` would yield a
    # confusing 711 (executable but unreadable to group/other).
    chmod 755 "$tmp"
    mv "$tmp" "$CLICKY_LOCAL_BIN/jq" || { rm -f "$tmp"; return 1; }
    # Make it usable for the remainder of THIS wizard run even if the
    # operator's PATH doesn't include CLICKY_LOCAL_BIN yet.
    case ":$PATH:" in
        *":$CLICKY_LOCAL_BIN:"*) ;;
        *) export PATH="$CLICKY_LOCAL_BIN:$PATH" ;;
    esac
    command -v jq >/dev/null 2>&1
}

# Resolve one missing dependency. Package manager first (keeps the system
# coherent), rootless fallback second where one exists.
_resolve_dep() {
    local dep="$1"
    if _can_sudo_noninteractive; then
        echo "  + $(_install_hint "$dep")"
        eval "$(_install_hint "$dep")" >/dev/null 2>&1
        command -v "$dep" >/dev/null 2>&1 && return 0
    fi
    if [ "$dep" = "jq" ]; then
        echo "  + installing jq ${JQ_PINNED_VERSION} to $CLICKY_LOCAL_BIN (no root needed, checksum-verified)"
        _install_jq_rootless && return 0
    fi
    return 1
}

preflight() {
    # Test/CI escape hatch. This step is the only one that installs
    # software and touches the network, which makes it incompatible with
    # the offline, PATH-restricted fixtures in tests/setup_wizard/ that
    # cover steps 2-5. Those set CLICKY_PREFLIGHT=off; preflight has its
    # own dedicated coverage in that same suite. Never set this in normal
    # operator use - skipping it is what let the original dead-gateway bug
    # reach an engagement unnoticed.
    if [ "${CLICKY_PREFLIGHT:-on}" = "off" ]; then
        return
    fi

    _header "1/5" "Checking required dependencies"

    REQUIRED_MISSING=()
    local dep
    for dep in bash python3 curl jq; do
        if command -v "$dep" >/dev/null 2>&1; then
            echo "  $dep: $(command -v "$dep")"
        else
            echo "  $dep: MISSING"
            REQUIRED_MISSING+=("$dep")
        fi
    done

    if [ "${#REQUIRED_MISSING[@]}" -gt 0 ]; then
        echo
        echo "  Resolving missing dependencies..."
        local still=()
        for dep in "${REQUIRED_MISSING[@]}"; do
            if _resolve_dep "$dep"; then
                echo "    $dep: installed ($(command -v "$dep"))"
            else
                still+=("$dep")
            fi
        done
        REQUIRED_MISSING=("${still[@]+"${still[@]}"}")

        # Only fall back to asking the operator for what genuinely could not
        # be resolved automatically (curl and python3 can't be bootstrapped
        # without a package manager, and sudo may need a password).
        if [ "${#REQUIRED_MISSING[@]}" -gt 0 ]; then
            echo
            echo "  Could not install automatically: ${REQUIRED_MISSING[*]}"
            echo "  These need elevated privileges. Run:"
            for dep in "${REQUIRED_MISSING[@]}"; do
                echo "    $(_install_hint "$dep")"
            done
            echo
            if _confirm "  Run the above now (you'll be prompted for your password)?"; then
                for dep in "${REQUIRED_MISSING[@]}"; do
                    echo "  + $(_install_hint "$dep")"
                    eval "$(_install_hint "$dep")" || echo "    (failed - install '$dep' by hand)"
                done
                still=()
                for dep in "${REQUIRED_MISSING[@]}"; do
                    command -v "$dep" >/dev/null 2>&1 || still+=("$dep")
                done
                REQUIRED_MISSING=("${still[@]+"${still[@]}"}")
            fi
        fi
    fi

    # A rootless jq install is only useful if the scripts that need it can
    # find it. Most distros already have this on PATH; say so explicitly
    # when they don't, because the symptom otherwise shows up much later as
    # session-manager.sh failing on a fresh engagement.
    if [ -x "$CLICKY_LOCAL_BIN/jq" ]; then
        case ":${PATH}:" in
            *":$CLICKY_LOCAL_BIN:"*) ;;
            *)
                echo
                echo "  NOTE: jq is installed at $CLICKY_LOCAL_BIN/jq but that directory is"
                echo "  not on your PATH. Add this to your shell profile:"
                echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
                ;;
        esac
    fi

    # --- Install the clicky-gateway launcher onto PATH -------------------
    #
    # Every generated per-CLI config (.codex/agents/*.toml,
    # .github/agents/*.md, opencode.json) registers the MCP server as the
    # bare name `clicky-gateway`, resolved on PATH - the convention every
    # MCP client documents, and what keeps those checked-in files free of
    # any machine-specific absolute path. This is what makes that name
    # resolve. See GATEWAY_COMMAND in tools/generate-cli-targets.py.
    #
    # A symlink rather than a copy, so the launcher never goes stale
    # against the repo. launch.sh walks the symlink back to its real
    # location to find the repo root.
    echo
    echo "  Installing the clicky-gateway launcher..."
    local launcher_target="$REPO_ROOT/skills/mcp-gateway/scripts/launch.sh"
    if [ -f "$launcher_target" ]; then
        mkdir -p "$CLICKY_LOCAL_BIN"
        if ln -sf "$launcher_target" "$CLICKY_LOCAL_BIN/clicky-gateway"; then
            echo "  Launcher: $CLICKY_LOCAL_BIN/clicky-gateway -> $launcher_target"
            case ":$PATH:" in
                *":$CLICKY_LOCAL_BIN:"*) ;;
                *) export PATH="$CLICKY_LOCAL_BIN:$PATH" ;;
            esac
        else
            echo "  Launcher: FAILED to symlink into $CLICKY_LOCAL_BIN"
        fi
    else
        echo "  Launcher: SKIPPED (launch.sh not found at $launcher_target)"
    fi

    # --- Provision the gateway for real ---------------------------------
    echo
    echo "  Provisioning the MCP gateway (creates a Python venv, installs 'mcp')..."
    local provision="$REPO_ROOT/skills/mcp-gateway/scripts/provision-venv.sh"
    if [ ! -x "$provision" ] && [ ! -f "$provision" ]; then
        echo "  Gateway: SKIPPED (provision-venv.sh not found at $provision)"
        return
    fi

    # Same data dir the plugin itself uses, so this provisions the real
    # venv rather than a throwaway the operator never benefits from.
    local plugin_data="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/clicky-clicky}"
    mkdir -p "$plugin_data"

    local provision_log
    provision_log="$(mktemp)"
    if CLAUDE_PLUGIN_DATA="$plugin_data" bash "$provision" >"$provision_log" 2>&1; then
        local venv_dir="$plugin_data/venv"
        if "$venv_dir/bin/python3" -c "import mcp" >/dev/null 2>&1; then
            GATEWAY_READY="true"
            echo "  Gateway: READY ($venv_dir)"
        else
            echo "  Gateway: FAILED - venv provisioned but 'import mcp' does not work"
        fi
    else
        echo "  Gateway: FAILED"
        echo
        sed 's/^/    /' "$provision_log"
    fi
    rm -f "$provision_log"
}

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

# --- [2/5] Detect --------------------------------------------------------

CLI_CLAUDE=""; CLI_OPENCODE=""; CLI_CODEX=""; CLI_COPILOT=""
FOUND_TOOLS_COUNT=0
NIX_PRESENT="false"
NIX_BIN=""

# `command -v nix` alone is NOT a reliable test for "is Nix installed."
# Both the Nix and Lix installers put nix on PATH via /etc/profile.d/nix.sh,
# which is sourced by LOGIN shells only - so on a correctly installed
# multi-user Nix box, a script run from a non-login shell finds nothing.
#
# This caused a silent, total loss of tool provisioning in the wild: the
# operator installed Nix and registered Kalilix through this very wizard,
# `nix develop kalilix#kali` genuinely worked, and Clicky still ran every
# agent with none of the toolkit - because both this file and
# skills/mcp-gateway/scripts/launch.sh concluded "nix is not on PATH."
# Keep this in sync with launch.sh's copy of _find_nix().
# Colon-separated candidate list, overridable. Tests need this: because
# this function deliberately looks OUTSIDE PATH, restricting PATH no
# longer isolates a "Nix is not installed" fixture, and without an
# override tests/setup_wizard/ would detect the developer's real Nix and
# go on to do real work (registering the flake, pre-warming the store) in
# a suite documented as never touching the real system. Set it to empty
# to simulate a machine with no Nix. Uses ${VAR-default}, not ${VAR:-...},
# so an explicitly-empty value is honored rather than replaced.
CLICKY_NIX_CANDIDATES="${CLICKY_NIX_CANDIDATES-/nix/var/nix/profiles/default/bin/nix:$HOME/.nix-profile/bin/nix:/run/current-system/sw/bin/nix:/usr/local/bin/nix}"

_find_nix() {
    if command -v nix >/dev/null 2>&1; then
        command -v nix
        return 0
    fi
    local candidate
    local IFS=':'
    for candidate in $CLICKY_NIX_CANDIDATES; do
        [ -n "$candidate" ] || continue
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

detect() {
    _header "2/5" "Detecting your environment"

    CLI_CLAUDE="$(command -v claude 2>/dev/null || true)"
    CLI_OPENCODE="$(command -v opencode 2>/dev/null || true)"
    CLI_CODEX="$(command -v codex 2>/dev/null || true)"
    CLI_COPILOT="$(command -v copilot 2>/dev/null || true)"

    FOUND_TOOLS_COUNT=0
    for t in "${KALILIX_TOOLS[@]}"; do
        command -v "$t" >/dev/null 2>&1 && FOUND_TOOLS_COUNT=$((FOUND_TOOLS_COUNT + 1))
    done

    if NIX_BIN="$(_find_nix)"; then
        NIX_PRESENT="true"
        # Nix is routinely installed but absent from a non-login shell's
        # PATH (see _find_nix). Put it on PATH for the rest of this run so
        # every later `nix registry`/`nix develop` call here works.
        case ":$PATH:" in
            *":$(dirname "$NIX_BIN"):"*) ;;
            *) export PATH="$(dirname "$NIX_BIN"):$PATH" ;;
        esac
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

# --- [3/5] Pentest tools (Kalilix) ---------------------------------------

TOOL_PROVISIONING="none"

offer_kalilix() {
    _header "3/5" "Pentest tools (Kalilix)"
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
            # Fall back to the canonical install locations too - sourcing
            # the profile scripts above is not sufficient on every layout.
            if NIX_BIN="$(_find_nix)"; then
                case ":$PATH:" in
                    *":$(dirname "$NIX_BIN"):"*) ;;
                    *) export PATH="$(dirname "$NIX_BIN"):$PATH" ;;
                esac
            fi
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

# --- [4/5] Cross-provider severity review --------------------------------

SEVERITY_REVIEW_STATUS="fallback"

offer_codex_for_severity_review() {
    _header "4/5" "Cross-checked severity scoring"
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

# --- [5/5] Apply ----------------------------------------------------------

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
    _header "5/5" "Applying configuration"
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

    # --- Warm the gateway's toolchain cache (optional) ------------------
    #
    # Runs LAST, after write_clicky_config above: the toolchain cache only
    # exists once tool_provisioning=kalilix is actually on disk, so warming
    # earlier would silently no-op.
    #
    # This is a convenience, NOT a precondition. The gateway resolves the
    # Kalilix toolchain lazily on first use (server.py, via
    # skills/mcp-gateway/scripts/toolchain-path.sh), so /pentest works whether
    # or not this ran - an earlier revision warmed here to stop the gateway
    # being reported as "failed to connect", which is no longer how that
    # failure is prevented. All warming buys now is that an operator's FIRST
    # command is fast instead of paying a one-time ~45s resolve.
    local toolchain="$REPO_ROOT/skills/mcp-gateway/scripts/toolchain-path.sh"
    if [ "$GATEWAY_READY" = "true" ] && [ -f "$toolchain" ] && [ "$TOOL_PROVISIONING" = "kalilix" ]; then
        echo
        echo "  Warming the Kalilix toolchain cache (one-time, can take ~45s)..."
        local plugin_data="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/clicky-clicky}"
        local warm_log
        warm_log="$(mktemp)"
        if CLAUDE_PLUGIN_DATA="$plugin_data" CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING=kalilix \
             bash "$toolchain" --refresh >/dev/null 2>"$warm_log"; then
            echo "  Toolchain cache: warm ✓ (your first command will be fast)"
        else
            echo "  Toolchain cache: not warmed - this is not a problem. Clicky will"
            echo "  resolve it on first use instead; that one command will just be slower."
            sed 's/^/    /' "$warm_log" | tail -3
        fi
        rm -f "$warm_log"
    fi
}

print_summary() {
    echo
    echo "============================================================"
    echo "Done."
    echo "============================================================"
    # Gateway status leads, because unlike everything else in this summary
    # it is pass/fail rather than better/worse: with a dead gateway every
    # agent dispatch gets an agent with no tools at all.
    if [ "$GATEWAY_READY" = "true" ]; then
        echo "  MCP gateway:      ready ✓"
    else
        echo "  MCP gateway:      NOT READY - Clicky cannot run until this is fixed"
    fi
    if [ "${#REQUIRED_MISSING[@]}" -gt 0 ]; then
        echo "  Required deps:    MISSING - ${REQUIRED_MISSING[*]}"
    fi

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
    if [ "$GATEWAY_READY" = "true" ]; then
        echo "  Restart your CLI host, then run /pentest <target> to get started."
        echo "  (Claude Code attempts the MCP connection once at session start and"
        echo "   does not retry, so a gateway provisioned just now needs a restart.)"
    else
        echo "  Do NOT run /pentest yet - fix the gateway above first, then re-run"
        echo "  this wizard. Running it with a dead gateway produces agents with no"
        echo "  tools, which fail in confusing ways rather than saying what's wrong."
    fi
}

run_default_flow() {
    preflight
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
