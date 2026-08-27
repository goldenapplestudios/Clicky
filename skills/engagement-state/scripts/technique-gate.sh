#!/bin/bash
#
# technique-gate.sh - preconditions that must be met before a low-yield,
# high-noise technique is allowed to run.
#
# Why this exists: brute force is the single most over-prescribed action by
# LLM pentest agents. The PentestGPT evaluation (USENIX Security '24, Table 3)
# counted it as the #1 unnecessary operation - 235 instances across models,
# roughly 3x the next category, with GPT-4 the worst offender at 92 - and
# concluded: "For all services requiring password authentication, LLMs
# typically advise brute-forcing it. This is an ineffective strategy in
# penetration testing."
#
# Prompt instructions alone do not fix this; the behavior is a learned prior.
# So this gate is enforced in the MCP gateway (skills/mcp-gateway/server.py
# refuses to execute credential-attack tooling without an authorization here),
# not merely requested in an agent prompt.
#
# A credential attack requires ALL THREE of:
#   --auth-surface   evidence that the SERVICE actually accepts credential
#                    authentication and that you have observed it
#   --username-link  evidence tying your username source to THAT service -
#                    names printed on a web page are not evidence that those
#                    people hold accounts on SSH
#   --operator-approval  the human operator said to proceed
#
# Usage:
#   technique-gate.sh init <session_dir>
#   technique-gate.sh request <session_dir> --technique credential_attack \
#        --service ssh --port 22 --auth-surface "..." --username-link "..." \
#        --operator-approval "..."
#   technique-gate.sh check <session_dir> --technique credential_attack [--service ssh]
#   technique-gate.sh list <session_dir>
#   technique-gate.sh revoke <session_dir> --technique T [--service S]
set -uo pipefail

command -v jq >/dev/null 2>&1 || { echo "technique-gate.sh: jq is required" >&2; exit 2; }

AUTH_REL="state/technique-authorizations.json"
GATED_TECHNIQUES="credential_attack"

_path() { echo "$1/$AUTH_REL"; }

cmd_init() {
    local session_dir="$1"
    mkdir -p "$session_dir/state"
    local p; p="$(_path "$session_dir")"
    [ -f "$p" ] || jq -n --arg now "$(date -Iseconds)" \
        '{version: 1, created: $now, authorizations: []}' > "$p"
    echo "$p"
}

cmd_request() {
    local session_dir="$1"; shift
    local p; p="$(_path "$session_dir")"
    [ -f "$p" ] || p="$(cmd_init "$session_dir")"
    local technique="" service="" port="" auth_surface="" username_link="" approval="" agent=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --technique) technique="$2"; shift 2 ;;
            --service) service="$2"; shift 2 ;;
            --port) port="$2"; shift 2 ;;
            --auth-surface) auth_surface="$2"; shift 2 ;;
            --username-link) username_link="$2"; shift 2 ;;
            --operator-approval) approval="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [ -n "$technique" ] || { echo "technique-gate.sh request: --technique is required" >&2; exit 2; }

    local missing=()
    if [ "$technique" = "credential_attack" ]; then
        [ -n "$auth_surface" ]  || missing+=("--auth-surface (evidence the service accepts credential auth and you observed it)")
        [ -n "$username_link" ] || missing+=("--username-link (evidence your usernames belong to THIS service, not just names seen elsewhere)")
        [ -n "$approval" ]      || missing+=("--operator-approval (the human operator authorized this specific attack)")
        [ -n "$service" ]       || missing+=("--service (which service is being attacked)")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        echo "DENIED: '$technique' cannot be authorized - unmet preconditions:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        echo "" >&2
        echo "Brute force is the most over-prescribed and lowest-yield action available to you." >&2
        echo "If you cannot supply this evidence, the correct next step is more discovery," >&2
        echo "not more guessing. See OWASP WSTG: information gathering (INFO-*) and" >&2
        echo "configuration testing (CONF-*) precede authentication testing (ATHN-*)." >&2
        exit 3
    fi

    local tmp; tmp="$(mktemp)"
    jq --arg t "$technique" --arg s "$service" --arg port "$port" --arg a "$auth_surface" \
       --arg u "$username_link" --arg ap "$approval" --arg agent "$agent" \
       --arg now "$(date -Iseconds)" '
        .authorizations = ([.authorizations[] | select(.technique != $t or .service != $s)] + [{
            technique: $t, service: $s, port: $port, granted: true, granted_at: $now,
            agent: $agent,
            preconditions: {
                auth_surface_confirmed: $a,
                username_source_linked: $u,
                operator_approved: $ap
            }
        }])' "$p" > "$tmp" && mv "$tmp" "$p"
    echo "GRANTED: $technique on ${service:-<any>}${port:+:$port}"
}

cmd_check() {
    local session_dir="$1"; shift
    local technique="" service=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --technique) technique="$2"; shift 2 ;;
            --service) service="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    local p; p="$(_path "$session_dir")"
    if [ ! -f "$p" ]; then echo "NOT AUTHORIZED: no authorizations recorded for this session"; exit 1; fi
    if jq -e --arg t "$technique" --arg s "$service" \
        'any(.authorizations[]; .technique == $t and .granted and ($s == "" or .service == $s or .service == ""))' \
        "$p" >/dev/null; then
        echo "AUTHORIZED: $technique${service:+ on $service}"; exit 0
    fi
    echo "NOT AUTHORIZED: $technique${service:+ on $service}"; exit 1
}

cmd_list() {
    local p; p="$(_path "$1")"
    [ -f "$p" ] && jq -r '.authorizations[] | "\(.technique) on \(.service // "<any>") granted \(.granted_at)"' "$p" \
        || echo "(no authorizations)"
}

cmd_revoke() {
    local session_dir="$1"; shift
    local technique="" service=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --technique) technique="$2"; shift 2 ;;
            --service) service="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    local p; p="$(_path "$session_dir")"; local tmp; tmp="$(mktemp)"
    jq --arg t "$technique" --arg s "$service" \
       '.authorizations = [.authorizations[] | select(.technique != $t or ($s != "" and .service != $s))]' \
       "$p" > "$tmp" && mv "$tmp" "$p"
    echo "revoked $technique${service:+ on $service}"
}

case "${1:-}" in
    init)    shift; cmd_init "$@" ;;
    request) shift; cmd_request "$@" ;;
    check)   shift; cmd_check "$@" ;;
    list)    shift; cmd_list "$@" ;;
    revoke)  shift; cmd_revoke "$@" ;;
    gated-techniques) echo "$GATED_TECHNIQUES" ;;
    *) sed -n '/^# Usage:/,/^set -uo/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 1 ;;
esac
