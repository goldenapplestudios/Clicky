#!/bin/bash
#
# Tests for skills/engagement-state/scripts/*.sh - the externalized attack
# tree, methodology coverage ledger, and technique preconditions gate.
#
# These back three specific claims the rest of the plugin now relies on:
#   1. A branch cannot be closed as "exhausted" without evidence, and
#      "untested" is a distinct, non-interchangeable status.
#   2. Coverage cannot be claimed `done` without evidence, nor `skipped`
#      without a reason - so a report can never silently present "never
#      looked" as "looked and found nothing".
#   3. A credential attack cannot be authorized without all three
#      preconditions, and the failure text explains why rather than just
#      refusing.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPTS="$REPO_ROOT/skills/engagement-state/scripts"
TREE="$SCRIPTS/attack-tree.sh"
LEDGER="$SCRIPTS/coverage-ledger.sh"
GATE="$SCRIPTS/technique-gate.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

FAILED=0
check() {  # check <label> <condition-exit-code> [detail]
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1 ${3:-}"; FAILED=1; fi
}

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT

# ---------------------------------------------------------------- attack tree
bash "$TREE" init "$D" 198.51.100.9 "recover dashboard user credentials" >/dev/null
[ -f "$D/state/attack-tree.json" ]; check "attack-tree init creates state file" $?

web=$(bash "$TREE" add "$D" --title "Web :3000" --tactic TA0043 --priority 90)
ssh_n=$(bash "$TREE" add "$D" --title "SSH :22" --tactic TA0006 --priority 30)
[ "$web" = "n1" ] && [ "$ssh_n" = "n2" ]; check "nodes get sequential ids" $?

out=$(bash "$TREE" next "$D"); grep -q '"title": "Web :3000"' <<<"$out"
check "next returns the highest-priority open node" $?

bash "$TREE" set "$D" "$web" exhausted 2>/dev/null
[ $? -eq 3 ]; check "exhausted WITHOUT evidence is refused (exit 3)" $?

err=$(bash "$TREE" set "$D" "$web" exhausted 2>&1 >/dev/null)
grep -q "untested" <<<"$err"
check "refusal points the agent at 'untested' instead" $?

bash "$TREE" set "$D" "$web" exhausted --evidence "1794 paths + build manifest read" >/dev/null 2>&1
check "exhausted WITH evidence is accepted" $?

bash "$TREE" set "$D" "$ssh_n" untested --note "no evidence dashboard names map to unix accounts" >/dev/null
st=$(bash "$TREE" stats "$D")
grep -q '"untested":1' <<<"$st" && grep -q '"exhausted":1' <<<"$st"
check "untested and exhausted are counted separately" $? "got $st"

bash "$TREE" set "$D" "$web" bogus_status >/dev/null 2>&1
[ $? -eq 2 ]; check "invalid status is rejected" $?

bash "$TREE" set "$D" n99 confirmed --evidence x >/dev/null 2>&1
[ $? -eq 2 ]; check "unknown node id is rejected" $?

render_out="$(bash "$TREE" render "$D")"
grep -q "UNTESTED" <<<"$render_out"
check "render flags untested branches visibly" $?

# ------------------------------------------------------------------- coverage
bash "$LEDGER" init "$D" >/dev/null
[ -f "$D/state/coverage.json" ]; check "coverage init creates ledger" $?

n=$(jq '.checks | length' "$D/state/coverage.json"); [ "$n" -ge 100 ]
check "catalog covers the full WSTG surface (>=100 checks)" $? "got $n"

# Every WSTG id and name in the ledger must match the vendored OWASP checklist
# verbatim. An earlier revision hand-wrote these from memory and got 25 of 36
# names wrong, including calling WSTG-APIT-01 "Test GraphQL" when its official
# name is "API Reconnaissance" (GraphQL is WSTG-APIT-99). A report that cites a
# WSTG id against the wrong test name is worse than one citing no id at all.
WSTG_SRC="$REPO_ROOT/skills/engagement-state/data/wstg-checklist.md"
mismatch=$(jq -r '.checks[] | select(.id | startswith("WSTG-")) | "\(.id)\t\(.title)"' \
    "$D/state/coverage.json" | while IFS=$'\t' read -r id title; do
        official=$(grep -oP "^\|\s*\Q$id\E\s*\|\s*\K[^|]+?(?=\s*\|)" "$WSTG_SRC" | head -1)
        [ "$title" != "$official" ] && echo "$id: '$title' != '$official'"
    done)
[ -z "$mismatch" ]
check "every WSTG title matches the official OWASP checklist verbatim" $? "$mismatch"

official_count=$(grep -coE '^\|\s*WSTG-[A-Z]{4}-[0-9]{2}\s*\|' "$WSTG_SRC")
ledger_count=$(jq '[.checks[] | select(.id | startswith("WSTG-"))] | length' "$D/state/coverage.json")
[ "$official_count" -eq "$ledger_count" ]
check "ledger carries every WSTG check (no silent subset)" $? "official=$official_count ledger=$ledger_count"

jq -e '[.checks[].id] | index("WSTG-APIT-99")' "$D/state/coverage.json" >/dev/null
check "GraphQL is catalogued at its real id (WSTG-APIT-99)" $?

jq -e '[.checks[].id] | index("WSTG-INFO-04")' "$D/state/coverage.json" >/dev/null
check "catalog includes WSTG-INFO-04 (vhost enumeration)" $?
jq -e '[.checks[].id] | index("NET-02")' "$D/state/coverage.json" >/dev/null
check "catalog includes NET-02 (UDP scan)" $?

bash "$LEDGER" mark "$D" WSTG-INFO-04 done >/dev/null 2>&1
[ $? -eq 3 ]; check "'done' WITHOUT evidence is refused" $?

bash "$LEDGER" mark "$D" WSTG-INFO-04 done --evidence "7 Host values byte-identical" >/dev/null
check "'done' WITH evidence is accepted" $?

bash "$LEDGER" mark "$D" NET-02 skipped >/dev/null 2>&1
[ $? -eq 3 ]; check "'skipped' WITHOUT a reason is refused" $?

bash "$LEDGER" mark "$D" NET-02 skipped --why "needs root" >/dev/null
check "'skipped' WITH a reason is accepted" $?

bash "$LEDGER" mark "$D" NOT-A-REAL-ID done --evidence x >/dev/null 2>&1
[ $? -eq 2 ]; check "unknown check id is rejected" $?

gaps_out="$(bash "$LEDGER" gaps "$D")"
grep -q "NET-02" <<<"$gaps_out"
check "gaps lists a skipped check (skipped is still a gap)" $?
grep -q "WSTG-INFO-04" <<<"$gaps_out"
[ $? -ne 0 ]; check "gaps excludes a check marked done" $?
report_out="$(bash "$LEDGER" report "$D")"
grep -q "NOT COVERED" <<<"$report_out"
check "report states an explicit not-covered count" $?

# --------------------------------------------------------------------- gate
bash "$GATE" init "$D" >/dev/null

bash "$GATE" check "$D" --technique credential_attack --service ssh >/dev/null 2>&1
[ $? -eq 1 ]; check "credential_attack is unauthorized by default" $?

err=$(bash "$GATE" request "$D" --technique credential_attack --service ssh --port 22 2>&1 >/dev/null)
[ $? -ne 0 ]; check "request with NO evidence is denied" $?
grep -q -- "--auth-surface" <<<"$err"; check "denial names the auth-surface precondition" $?
grep -q -- "--username-link" <<<"$err"; check "denial names the username-link precondition" $?
grep -q -- "--operator-approval" <<<"$err"; check "denial names the operator-approval precondition" $?
grep -q "WSTG" <<<"$err"; check "denial cites methodology ordering" $?

# partial evidence is still a denial - this is the case that matters, because
# an agent that scraped names off a web page can satisfy two of three
err=$(bash "$GATE" request "$D" --technique credential_attack --service ssh \
    --auth-surface "ssh offers password auth" --operator-approval "operator said go" 2>&1 >/dev/null)
[ $? -ne 0 ]; check "PARTIAL evidence (missing username-link) is still denied" $?
grep -q -- "--username-link" <<<"$err"; check "partial denial names the missing precondition only" $?

bash "$GATE" request "$D" --technique credential_attack --service ssh --port 22 \
    --auth-surface "password auth offered" \
    --username-link "usernames from /etc/passwd on this host" \
    --operator-approval "operator approved" >/dev/null
check "request with ALL THREE preconditions is granted" $?

bash "$GATE" check "$D" --technique credential_attack --service ssh >/dev/null 2>&1
check "check passes after grant" $?

bash "$GATE" check "$D" --technique credential_attack --service ftp >/dev/null 2>&1
[ $? -eq 1 ]; check "grant is scoped to its service (ftp still unauthorized)" $?

bash "$GATE" revoke "$D" --technique credential_attack --service ssh >/dev/null
bash "$GATE" check "$D" --technique credential_attack --service ssh >/dev/null 2>&1
[ $? -eq 1 ]; check "revoke removes the authorization" $?

exit $FAILED
