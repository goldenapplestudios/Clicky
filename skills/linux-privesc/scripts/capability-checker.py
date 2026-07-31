#!/usr/bin/env python3
"""Capability Checker - enumerate files with Linux capabilities and flag
dangerous ones for privilege escalation.

Usage: capability-checker.py

Wraps `getcap -r /`, which must be on PATH (part of libcap2-bin on Debian/
Ubuntu, libcap on most other distros).
"""
import shutil
import subprocess
import sys

# Capabilities that commonly lead directly to privilege escalation. Not
# exhaustive - see https://gtfobins.github.io/ (filter by "Capabilities")
# for the current full list and exact exploitation steps per binary.
DANGEROUS_CAPS = {
    "cap_setuid": "Can set process UID to 0 (root) directly",
    "cap_setgid": "Can set process GID, often chained with cap_setuid",
    "cap_dac_override": "Bypasses file read/write/execute permission checks",
    "cap_dac_read_search": "Bypasses file read and directory search permission checks",
    "cap_sys_admin": "Extremely broad - mount filesystems, namespace operations, more",
    "cap_sys_ptrace": "Can attach to and control other processes (including as root)",
    "cap_sys_module": "Can load kernel modules - direct path to root",
    "cap_net_raw": "Can craft raw packets - useful for spoofing/sniffing, lower direct-privesc value",
    "cap_chown": "Can change file ownership arbitrarily",
    "cap_fowner": "Bypasses ownership checks for file operations",
}


def main():
    if not shutil.which("getcap"):
        print("ERROR: getcap not found on PATH (install libcap2-bin / libcap).", file=sys.stderr)
        sys.exit(1)

    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: getcap -r / timed out after 120s.", file=sys.stderr)
        sys.exit(1)

    lines = [l for l in result.stdout.splitlines() if l.strip()]

    if not lines:
        print("No files with capabilities found.")
        return

    print(f"=== Files with capabilities ({len(lines)}) ===")
    flagged = []
    for line in lines:
        print(f"  {line}")
        lower = line.lower()
        for cap, reason in DANGEROUS_CAPS.items():
            if cap in lower:
                flagged.append((line, cap, reason))

    if flagged:
        print()
        print("=== Flagged for privilege escalation potential ===")
        for line, cap, reason in flagged:
            binary = line.split()[0]
            print(f"  {binary}: {cap} - {reason}")
            print(f"    Check https://gtfobins.github.io/gtfobins/{binary.split('/')[-1]}/ for the exact technique")
    else:
        print()
        print("No commonly-dangerous capabilities found among discovered binaries.")


if __name__ == "__main__":
    main()
