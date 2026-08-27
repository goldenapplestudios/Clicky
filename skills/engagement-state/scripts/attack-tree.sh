#!/bin/bash
#
# attack-tree.sh - persistent, externally-maintained attack-surface state.
#
# Why this exists: LLM pentest agents lose the engagement's big picture. The
# PentestGPT paper (USENIX Security '24) measured "session context lost" as the
# single largest cause of failed testing trials, and the follow-up structured-
# attack-tree work (COLM '25) showed that having the model FOLLOW an externally
# maintained tree - rather than regenerate its plan from conversation context
# each turn - raised subtask completion from 35.2% to 74.4% while using 55.9%
# fewer queries.
#
# This file is that tree. It lives on disk, outside any model's context window,
# and survives agent handoffs, compaction, and orchestrator restarts. Agents
# read it to decide what to do next and write back what they learned. An agent
# that finishes a phase without updating the tree has not finished the phase.
#
# Node statuses:
#   open        - identified, not yet investigated
#   in_progress - an agent is working it now
#   exhausted   - investigated properly, nothing found (requires --evidence)
#   confirmed   - a real finding came out of it
#   blocked     - cannot proceed (needs creds/root/operator action); say why
#   untested    - deliberately NOT investigated (out of scope, no tooling, etc.)
#
# "exhausted" and "untested" are deliberately different words. Collapsing them
# is the exact error that lets an unfinished check be reported as a clean one.
#
# Usage:
#   attack-tree.sh init <session_dir> <target> [objective]
#   attack-tree.sh add <session_dir> --title T [--parent ID] [--tactic T]
#                       [--hypothesis H] [--priority N] [--agent A]
#   attack-tree.sh set <session_dir> <node_id> <status> [--evidence E] [--note N] [--agent A]
#   attack-tree.sh note <session_dir> <node_id> <text>
#   attack-tree.sh next <session_dir>            # highest-priority open node
#   attack-tree.sh open <session_dir>            # all open/in_progress nodes
#   attack-tree.sh render <session_dir>          # human-readable tree
#   attack-tree.sh stats <session_dir>           # counts by status (JSON)
set -uo pipefail

command -v jq >/dev/null 2>&1 || { echo "attack-tree.sh: jq is required" >&2; exit 2; }

TREE_REL="state/attack-tree.json"

_tree_path() { echo "$1/$TREE_REL"; }

_require_tree() {
    local p; p="$(_tree_path "$1")"
    [ -f "$p" ] || { echo "attack-tree.sh: no attack tree at $p (run 'init' first)" >&2; exit 2; }
    echo "$p"
}

_write() {  # _write <path> <jq-filter> [args...]
    local path="$1"; shift
    local tmp; tmp="$(mktemp)"
    jq "$@" "$path" > "$tmp" && mv "$tmp" "$path"
}

_now() { date -Iseconds; }

cmd_init() {
    local session_dir="$1" target="${2:-}" objective="${3:-}"
    mkdir -p "$session_dir/state"
    local p; p="$(_tree_path "$session_dir")"
    if [ -f "$p" ]; then echo "$p"; return 0; fi
    jq -n --arg t "$target" --arg o "$objective" --arg now "$(_now)" '{
        version: 1, target: $t, objective: $o, created: $now, updated: $now,
        next_id: 1, nodes: []
    }' > "$p"
    echo "$p"
}

cmd_add() {
    local session_dir="$1"; shift
    local p; p="$(_require_tree "$session_dir")" || exit 2
    local title="" parent="" tactic="" hypothesis="" priority=50 agent=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --title) title="$2"; shift 2 ;;
            --parent) parent="$2"; shift 2 ;;
            --tactic) tactic="$2"; shift 2 ;;
            --hypothesis) hypothesis="$2"; shift 2 ;;
            --priority) priority="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [ -n "$title" ] || { echo "attack-tree.sh add: --title is required" >&2; exit 2; }
    local id; id="n$(jq -r '.next_id' "$p")"
    _write "$p" --arg id "$id" --arg title "$title" --arg parent "$parent" \
        --arg tactic "$tactic" --arg hyp "$hypothesis" --argjson prio "$priority" \
        --arg agent "$agent" --arg now "$(_now)" '
        .nodes += [{
            id: $id, parent: (if $parent == "" then null else $parent end),
            title: $title, tactic: $tactic, hypothesis: $hyp,
            status: "open", priority: $prio, agent: $agent,
            evidence: "", notes: [], created: $now, updated: $now
        }] | .next_id += 1 | .updated = $now'
    echo "$id"
}

cmd_set() {
    local session_dir="$1" node_id="$2" status="$3"; shift 3
    local p; p="$(_require_tree "$session_dir")" || exit 2
    case "$status" in
        open|in_progress|exhausted|confirmed|blocked|untested) ;;
        *) echo "attack-tree.sh set: invalid status '$status'" >&2; exit 2 ;;
    esac
    local evidence="" note="" agent=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --evidence) evidence="$2"; shift 2 ;;
            --note) note="$2"; shift 2 ;;
            --agent) agent="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    # "exhausted" is a claim that the branch was properly investigated. It is
    # the claim most likely to be wrong, so it must carry evidence.
    if [ "$status" = "exhausted" ] && [ -z "$evidence" ]; then
        echo "attack-tree.sh set: status 'exhausted' requires --evidence (what did you actually run?)." >&2
        echo "  If the branch was not investigated, use 'untested' with a --note explaining why." >&2
        exit 3
    fi
    jq -e --arg id "$node_id" 'any(.nodes[]; .id == $id)' "$p" >/dev/null || {
        echo "attack-tree.sh set: no such node '$node_id'" >&2; exit 2; }
    _write "$p" --arg id "$node_id" --arg st "$status" --arg ev "$evidence" \
        --arg note "$note" --arg agent "$agent" --arg now "$(_now)" '
        .nodes |= map(
            if .id == $id then
                .status = $st | .updated = $now
                | (if $ev != "" then .evidence = $ev else . end)
                | (if $agent != "" then .agent = $agent else . end)
                | (if $note != "" then .notes += [{at: $now, text: $note}] else . end)
            else . end
        ) | .updated = $now'
    echo "$node_id -> $status"
}

cmd_note() {
    local session_dir="$1" node_id="$2" text="$3"
    local p; p="$(_require_tree "$session_dir")" || exit 2
    _write "$p" --arg id "$node_id" --arg t "$text" --arg now "$(_now)" '
        .nodes |= map(if .id == $id then .notes += [{at: $now, text: $t}] | .updated = $now else . end)
        | .updated = $now'
    echo "noted on $node_id"
}

cmd_next() {
    local p; p="$(_require_tree "$1")" || exit 2
    jq -r '[.nodes[] | select(.status == "open")] | sort_by(-.priority) | .[0]
           // "NONE: no open nodes - re-run discovery or close the engagement"' "$p"
}

cmd_open() {
    local p; p="$(_require_tree "$1")" || exit 2
    jq -r '[.nodes[] | select(.status == "open" or .status == "in_progress")]
           | sort_by(-.priority)' "$p"
}

cmd_render() {
    local p; p="$(_require_tree "$1")" || exit 2
    echo "ATTACK TREE - target: $(jq -r '.target' "$p")"
    local obj; obj="$(jq -r '.objective // ""' "$p")"
    [ -n "$obj" ] && echo "OBJECTIVE: $obj"
    echo
    jq -r '
      def sym: {open:"[ ]", in_progress:"[~]", exhausted:"[x]",
                confirmed:"[!]", blocked:"[b]", untested:"[?]"}[.status] // "[ ]";
      def walk($parent; $depth):
        (.nodes[] | select(.parent == $parent)) as $n
        | ("  " * $depth) + ($n | sym) + " " + $n.id + " " + $n.title
          + (if $n.tactic != "" then "  (" + $n.tactic + ")" else "" end)
          + (if $n.status == "untested" then "  <- UNTESTED" else "" end),
          (. as $root | $root | walk($n.id; $depth + 1));
      . as $root | walk(null; 0)
    ' "$p" 2>/dev/null || jq -r '.nodes[] | "  [\(.status)] \(.id) \(.title)"' "$p"
    echo
    echo "counts: $(jq -c '[.nodes[].status] | group_by(.) | map({(.[0]): length}) | add // {}' "$p")"
}

cmd_stats() {
    local p; p="$(_require_tree "$1")" || exit 2
    jq -c '[.nodes[].status] | group_by(.) | map({(.[0]): length}) | add // {}' "$p"
}

case "${1:-}" in
    init)   shift; cmd_init "$@" ;;
    add)    shift; cmd_add "$@" ;;
    set)    shift; cmd_set "$@" ;;
    note)   shift; cmd_note "$@" ;;
    next)   shift; cmd_next "$@" ;;
    open)   shift; cmd_open "$@" ;;
    render) shift; cmd_render "$@" ;;
    stats)  shift; cmd_stats "$@" ;;
    *) sed -n '/^# Usage:/,/^set -uo/p' "$0" | sed 's/^# \{0,1\}//;$d'; exit 1 ;;
esac
