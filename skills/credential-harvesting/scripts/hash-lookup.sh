#!/bin/bash
#
# Hash Lookup - identify a hash and attempt a fast local crack before
# falling back to manual online lookup
#
# Usage: hash-lookup.sh "{hash}"
#
# Honest about its limits: crackstation/hashkiller/hashes.org are
# web-form-based services without a stable free API to curl against, so
# this script identifies the hash, tries a handful of extremely common
# passwords locally (a fast win costs nothing), and then prints the manual
# lookup URLs rather than pretending to call an API that doesn't exist.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HASH="${1:?Usage: $0 <hash>}"

echo "=== Identifying hash ==="
if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/hash-identifier.py" ]; then
    python3 "$SCRIPT_DIR/hash-identifier.py" "$HASH"
fi
echo

echo "=== Quick local crack attempt (extremely common passwords only) ==="
COMMON_PASSWORDS=("password" "123456" "admin" "letmein" "welcome" "qwerty" "changeme" "password123" "admin123")
FOUND=""
if command -v openssl >/dev/null 2>&1; then
    for pw in "${COMMON_PASSWORDS[@]}"; do
        # Try the common raw hash algorithms; this is a heuristic pass, not
        # exhaustive - use hashcat/john for anything real
        for algo in md5 sha1 sha256 sha512; do
            candidate=$(printf '%s' "$pw" | openssl dgst -"$algo" -r 2>/dev/null | awk '{print $1}')
            if [ "$candidate" = "$(echo "$HASH" | tr 'A-F' 'a-f')" ]; then
                FOUND="$pw ($algo)"
                break 2
            fi
        done
    done
fi

if [ -n "$FOUND" ]; then
    echo "MATCH: $FOUND"
else
    echo "No match against the common-password quick list."
    echo
    echo "For a real crack attempt, use hashcat/john with a proper wordlist"
    echo "(see password-formatter.sh to prepare the hash file), or check"
    echo "these online databases manually (no free API, web form only):"
    echo "  https://crackstation.net/"
    echo "  https://hashkiller.io/"
    echo "  https://hashes.com/en/decrypt/hash"
fi
