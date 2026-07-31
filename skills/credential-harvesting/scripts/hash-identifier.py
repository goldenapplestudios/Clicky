#!/usr/bin/env python3
"""Hash Identifier - guess a hash's algorithm from its format.

Usage: hash-identifier.py "{hash_string}"

This is pattern-matching, not cryptographic verification - several hash
types share a length (e.g. MD5 and NTLM are both 32 hex chars), so results
are reported as ranked candidates, not a single certain answer.
"""
import re
import sys

PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$", "MD5 crypt (Linux shadow $1$)"),
    (r"^\$5\$", "SHA-256 crypt (Linux shadow $5$)"),
    (r"^\$6\$", "SHA-512 crypt (Linux shadow $6$)"),
    (r"^\$y\$", "yescrypt (Linux shadow $y$)"),
    (r"^[A-Fa-f0-9]{32}$", "MD5 or NTLM (ambiguous - 32 hex chars)"),
    (r"^[A-Fa-f0-9]{40}$", "SHA-1"),
    (r"^[A-Fa-f0-9]{64}$", "SHA-256"),
    (r"^[A-Fa-f0-9]{128}$", "SHA-512"),
    (r"^[A-Fa-f0-9]{16}$", "MySQL 4.1+ (short form) or LM hash half"),
    (r"^\$apr1\$", "Apache MD5 (apr1)"),
    (r"^\$argon2(i|d|id)\$", "Argon2"),
    (r"^[A-Za-z0-9+/]{27}=$", "SHA-1 (base64)"),
    (r"^[A-Za-z0-9+/]{43}=$", "SHA-256 (base64)"),
    (r"^[A-Za-z0-9+/]{86}==$", "SHA-512 (base64)"),
]


def identify(value: str):
    matches = []
    for pattern, name in PATTERNS:
        if re.match(pattern, value.strip()):
            matches.append(name)
    return matches


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hash_string>", file=sys.stderr)
        sys.exit(1)

    value = sys.argv[1].strip()
    matches = identify(value)

    print(f"Input: {value}")
    print(f"Length: {len(value)} characters")
    if matches:
        print("Likely type(s):")
        for m in matches:
            print(f"  - {m}")
    else:
        print("No known pattern matched. Check manually, or try:")
        print("  hashid <hash>")
        print("  hash-identifier (interactive tool)")


if __name__ == "__main__":
    main()
