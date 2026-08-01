#!/bin/bash
#
# Syntax-checks every python script in the plugin with `python3 -m py_compile`.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILED=0
COUNT=0

while IFS= read -r -d '' script; do
    COUNT=$((COUNT + 1))
    if ! python3 -m py_compile "$script" 2>&1; then
        echo "SYNTAX ERROR: $script"
        FAILED=1
    fi
done < <(find "$REPO_ROOT/skills" -name "*.py" -print0 2>/dev/null)

echo "Checked $COUNT python scripts."
exit $FAILED
