#!/bin/bash
#
# Syntax-checks every bash script in the plugin (skills/, hooks/, workflows/
# aren't bash so excluded) with `bash -n`. Catches nothing about behavior,
# only "does this parse."
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILED=0
COUNT=0

while IFS= read -r -d '' script; do
    COUNT=$((COUNT + 1))
    if ! bash -n "$script" 2>&1; then
        echo "SYNTAX ERROR: $script"
        FAILED=1
    fi
done < <(find "$REPO_ROOT/skills" "$REPO_ROOT/hooks" -name "*.sh" -print0 2>/dev/null)

echo "Checked $COUNT bash scripts."
exit $FAILED
