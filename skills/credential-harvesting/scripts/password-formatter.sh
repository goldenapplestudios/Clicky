#!/bin/bash
#
# Password Formatter - prepare a hash file for hashcat or John the Ripper
#
# Usage:
#   password-formatter.sh hashcat "{hash_file}" "{hash_type}"
#   password-formatter.sh john "{hash_file}" "{format}"
#

set -euo pipefail

# Wordlist referenced in the emitted crack commands: the flake-pinned rockyou,
# exported as CLICKY_ROCKYOU by the toolchain shell (see flake.nix). The
# commands below embed the *literal* $CLICKY_ROCKYOU reference rather than its
# expanded value, so they resolve in whatever toolchain shell actually runs
# them and this suggestion-printer takes no load-time dependency on the var
# (it must keep working under `set -u` to print usage on any host, including a
# non-kalilix one where the var is unset). Single source, no /usr/share
# fallback: on a flake-provisioned host that path does not exist.
ROCKYOU='$CLICKY_ROCKYOU'

# Common hash-type name -> hashcat -m mode number
hashcat_mode() {
    case "$(echo "$1" | tr 'A-Z' 'a-z')" in
        md5) echo 0 ;;
        sha1) echo 100 ;;
        sha256) echo 1400 ;;
        sha512) echo 1700 ;;
        ntlm) echo 1000 ;;
        "linux-shadow-md5"|md5crypt) echo 500 ;;
        "linux-shadow-sha256") echo 7400 ;;
        "linux-shadow-sha512") echo 1800 ;;
        bcrypt) echo 3200 ;;
        mysql) echo 300 ;;
        mssql) echo 1731 ;;
        *)
            echo "UNKNOWN" ;;
    esac
}

do_hashcat() {
    local hash_file="${1:?hash file required}"
    local hash_type="${2:?hash type required}"

    [ -f "$hash_file" ] || { echo "ERROR: hash file not found: $hash_file" >&2; exit 1; }

    local mode
    mode=$(hashcat_mode "$hash_type")
    if [ "$mode" = "UNKNOWN" ]; then
        echo "WARNING: unrecognized hash type '$hash_type' - pass the hashcat -m number directly instead." >&2
        mode="$hash_type"
    fi

    # Strip anything before a ':' delimiter that isn't part of the hash
    # (common when hashes are exported alongside usernames)
    local clean_file="${hash_file%.txt}.hashcat"
    awk -F: '{print $NF}' "$hash_file" | grep -v '^$' > "$clean_file"

    echo "Prepared: $clean_file ($(wc -l < "$clean_file" | tr -d ' ') hash(es))"
    echo
    echo "Run with:"
    echo "  hashcat -m $mode -a 0 \"$clean_file\" $ROCKYOU"
    echo "  hashcat -m $mode -a 3 \"$clean_file\" '?a?a?a?a?a?a'   # brute force, 6 chars, all charsets"
}

do_john() {
    local hash_file="${1:?hash file required}"
    local format="${2:-}"

    [ -f "$hash_file" ] || { echo "ERROR: hash file not found: $hash_file" >&2; exit 1; }

    local clean_file="${hash_file%.txt}.john"
    cp "$hash_file" "$clean_file"

    echo "Prepared: $clean_file"
    echo
    if [ -n "$format" ]; then
        echo "Run with:"
        echo "  john --format=$format --wordlist=$ROCKYOU \"$clean_file\""
    else
        echo "No format specified - john will attempt auto-detection. Run with:"
        echo "  john --wordlist=$ROCKYOU \"$clean_file\""
        echo "If auto-detection picks the wrong format, list candidates with:"
        echo "  john --list=formats | grep -i <hint>"
    fi
    echo
    echo "Show cracked results any time with:"
    echo "  john --show \"$clean_file\""
}

main() {
    # NB: the usage string must NOT live inside a ${1:?...} default - the
    # literal '}' in "{hashcat|john}" terminates the parameter expansion
    # early, so `mode` captured the whole tail and every subcommand fell
    # through to "Unknown mode". Check arity explicitly instead.
    if [ "$#" -lt 1 ]; then
        echo "Usage: $0 {hashcat|john} <hash_file> <hash_type_or_format>" >&2
        exit 1
    fi
    local mode="$1"
    shift
    case "$mode" in
        hashcat) do_hashcat "$@" ;;
        john) do_john "$@" ;;
        *)
            echo "Unknown mode: $mode (expected hashcat or john)" >&2
            exit 1
            ;;
    esac
}

main "$@"
