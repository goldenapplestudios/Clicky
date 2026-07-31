#!/bin/bash
#
# SUID/SGID Finder - locate SUID/SGID binaries and flag ones with a known
# GTFOBins escalation technique
#
# Usage: suid-finder.sh
#

set -uo pipefail

# Binaries with well-known GTFOBins SUID escalation techniques (non-exhaustive
# - check https://gtfobins.github.io/ for the current full list and exact
# invocation, this is a fast local triage, not a replacement for it)
declare -a KNOWN_GTFOBINS=(
    base64 cp find python python3 perl vim vi nano less more systemctl
    awk sed tar env nice nmap docker gdb node php ruby lua
    openssl socat rsync ftp git zip
)

echo "=== SUID binaries ==="
SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null)
echo "$SUID_BINS"
echo

echo "=== SGID binaries ==="
SGID_BINS=$(find / -perm -2000 -type f 2>/dev/null)
echo "$SGID_BINS"
echo

echo "=== Cross-reference against known GTFOBins-exploitable binary names ==="
FOUND_EXPLOITABLE=0
for bin_path in $SUID_BINS $SGID_BINS; do
    bin_name=$(basename "$bin_path")
    for known in "${KNOWN_GTFOBINS[@]}"; do
        if [ "$bin_name" = "$known" ]; then
            echo "  POTENTIALLY EXPLOITABLE: $bin_path (check https://gtfobins.github.io/gtfobins/$known/ for the exact SUID technique)"
            FOUND_EXPLOITABLE=1
        fi
    done
done

if [ "$FOUND_EXPLOITABLE" -eq 0 ]; then
    echo "  None of the discovered SUID/SGID binaries matched the known-GTFOBins name list."
    echo "  This doesn't mean nothing is exploitable - custom/unusual binaries need manual review"
    echo "  (buffer overflow, command injection, PATH manipulation, shared library hijacking)."
fi
