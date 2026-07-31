#!/bin/bash
#
# Linux PrivEsc Check - orchestrated fast-pass enumeration
#
# Usage: linux-privesc-check.sh
#
# Runs the checks from the Priority 1-4 sections of this skill directly
# (sudo, SUID/SGID via suid-finder.sh, capabilities via
# capability-checker.py, writable critical files, cron jobs, kernel via
# kernel-exploit-suggester.sh). This is a fast first pass — for
# comprehensive coverage also run linPEAS/LinEnum/LSE as documented
# elsewhere in this skill.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

section() {
    echo
    echo "======================================================"
    echo "  $1"
    echo "======================================================"
}

section "Current user context"
id
echo "Groups: $(groups)"

section "SUDO privileges"
sudo -l 2>&1 || echo "(sudo -l failed or requires a password we don't have)"
if command -v sudo >/dev/null 2>&1; then
    echo "sudo version: $(sudo -V 2>/dev/null | head -1)"
fi

section "SUID/SGID binaries"
bash "$SCRIPT_DIR/suid-finder.sh"

section "Linux capabilities"
if command -v python3 >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/capability-checker.py"
else
    echo "python3 not available - falling back to raw getcap"
    getcap -r / 2>/dev/null
fi

section "Writable critical files"
for f in /etc/passwd /etc/shadow /etc/sudoers; do
    if [ -w "$f" ]; then
        echo "WRITABLE: $f"
    fi
done

section "Cron jobs"
echo "--- System crontab ---"
cat /etc/crontab 2>/dev/null
echo "--- /etc/cron.d/ ---"
ls -la /etc/cron.d/ 2>/dev/null
echo "--- Current user crontab ---"
crontab -l 2>/dev/null || echo "(none, or not permitted)"
echo "--- Writable cron scripts ---"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly; do
    find "$dir" -writable -type f 2>/dev/null
done

section "PATH and writable directories in PATH"
echo "PATH=$PATH"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [ -w "$dir" ]; then
        echo "WRITABLE PATH DIR: $dir"
    fi
done

section "Kernel / known-CVE check"
bash "$SCRIPT_DIR/kernel-exploit-suggester.sh"

section "Docker / LXD group membership"
groups | grep -qw docker && echo "User is in the docker group - can likely mount host filesystem via a privileged container"
groups | grep -qw lxd && echo "User is in the lxd group - can likely escalate via a privileged LXD container"

echo
echo "=== Fast pass complete. For deeper coverage, also run: ==="
echo "  curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
echo "  ./lse.sh -l 2"
