#!/bin/bash
#
# Target Validation Script for Penetration Testing
# Ensures safe targets and prevents dangerous operations
#

set -euo pipefail

# Function to validate IP address format
validate_ip() {
    local ip=$1

    # Check basic format
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        return 1
    fi

    # Check each octet
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ]; then
            return 1
        fi
    done

    return 0
}

# Function to check if IP is dangerous
is_dangerous_ip() {
    local ip=$1

    # Localhost
    if [[ "$ip" =~ ^127\. ]] || [[ "$ip" == "0.0.0.0" ]]; then
        echo "ERROR: Cannot scan localhost"
        return 0
    fi

    # Cloud metadata services
    if [[ "$ip" == "169.254.169.254" ]]; then
        echo "ERROR: Cannot scan cloud metadata service"
        return 0
    fi

    # Link-local addresses
    if [[ "$ip" =~ ^169\.254\. ]]; then
        echo "ERROR: Cannot scan link-local addresses"
        return 0
    fi

    return 1
}

# Function to check if IP is private
is_private_ip() {
    local ip=$1

    # 10.0.0.0/8
    if [[ "$ip" =~ ^10\. ]]; then
        return 0
    fi

    # 172.16.0.0/12
    if [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        return 0
    fi

    # 192.168.0.0/16
    if [[ "$ip" =~ ^192\.168\. ]]; then
        return 0
    fi

    return 1
}

# Function to check if target is merely SHAPED like an IP range
# ("N.N.N.N-N" - digits/dots then a hyphen then digits), independent of
# whether the numbers involved are actually valid. Used as a gate to keep
# ANY range-shaped input (even a malformed one, e.g. "127.0.0.1-999" with
# an out-of-bounds end octet) out of the hostname fallback below - see
# validate_ip_range() for why that matters.
looks_like_ip_range() {
    echo "$1" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}$'
}

# Function to check if target is a well-formed IP range like
# "10.10.10.1-254" (dotted-quad base address, valid octets, then "-" and a
# 0-255 end-of-range number for the last octet). Must be checked BEFORE
# validate_hostname: the hostname regex's per-label hyphen handling would
# otherwise happily accept the "1-254" tail as a normal hostname label and
# misclassify the whole range as VALID_HOSTNAME, skipping
# is_dangerous_ip()/is_private_ip() entirely. Callers must also gate on
# looks_like_ip_range() directly (not just call this and fall through to
# validate_hostname on failure) so a *malformed* range with a dangerous
# base (e.g. "127.0.0.1-999") doesn't slip through the same way.
validate_ip_range() {
    local target=$1

    if ! looks_like_ip_range "$target"; then
        return 1
    fi

    local base_ip="${target%-*}"
    local range_end="${target##*-}"

    if ! validate_ip "$base_ip"; then
        return 1
    fi

    if [ "$range_end" -gt 255 ] || [ "$range_end" -lt 0 ]; then
        return 1
    fi

    return 0
}

# Function to check if target is merely SHAPED like an IPv4 address (four
# purely-numeric dot-separated groups), independent of whether the octets
# are actually in the valid 0-255 range. Used as a gate to keep an
# out-of-range dotted-quad input (e.g. "300.300.300.300", which validate_ip
# already rejected) from falling through to validate_hostname, whose regex
# is permissive enough to accept a numeric-only dotted string as a
# "hostname" and misclassify a malformed IP as VALID_HOSTNAME.
looks_like_ipv4() {
    echo "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

# Function to validate hostname
validate_hostname() {
    local hostname=$1

    # Check for valid hostname format
    if ! echo "$hostname" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'; then
        return 1
    fi

    # Block dangerous hostnames
    if [[ "$hostname" == "localhost" ]] || [[ "$hostname" == "localhost.localdomain" ]]; then
        echo "ERROR: Cannot scan localhost"
        return 1
    fi

    # Block metadata service hostnames
    if [[ "$hostname" == "metadata.google.internal" ]] || [[ "$hostname" == "metadata.aws.internal" ]]; then
        echo "ERROR: Cannot scan cloud metadata services"
        return 1
    fi

    # A single-label name with no dot ("doing", "webserver") is either a real
    # internal host or - far more often - a stray word that reached this script
    # as a mis-parsed argument. The regex above cannot tell those apart, so it
    # used to accept BOTH: an operator who typed
    #   /pentest <10.0.0.1> [From doing some recon ...]
    # instead of substituting the argument-hint placeholders had "doing" bound
    # to $target, validated clean as VALID_HOSTNAME, and watched an entire
    # engagement configure itself around a word from their own sentence.
    #
    # Resolution is the discriminator that costs nothing and is never wrong in
    # the dangerous direction: a real internal host resolves, a typo does not.
    # Dotted names are left alone - they are unambiguous in shape, and a
    # not-yet-registered or split-horizon domain is a legitimate target.
    if [[ "$hostname" != *.* ]]; then
        if command -v getent >/dev/null 2>&1; then
            getent hosts "$hostname" >/dev/null 2>&1 && return 0
        elif command -v host >/dev/null 2>&1; then
            host "$hostname" >/dev/null 2>&1 && return 0
        elif command -v nslookup >/dev/null 2>&1; then
            nslookup "$hostname" >/dev/null 2>&1 && return 0
        else
            # No resolver available: cannot discriminate, so do not block.
            return 0
        fi
        echo "ERROR: '$hostname' is a single-label name that does not resolve."
        echo "  If you meant an IP or domain, pass it directly:"
        echo "    /clicky:pentest 10.10.10.10 \"optional context\""
        echo "  Do not type the argument-hint brackets themselves - '<IP or domain>'"
        echo "  and '[\"additional context\"]' are placeholders to replace, and typing"
        echo "  them literally can bind a word from your sentence as the target."
        echo "  If this really is an internal host, make it resolvable (or use its IP)."
        return 1
    fi

    return 0
}

# Validate a single target (no comma-splitting). Prints one of
# VALID_IP / VALID_RANGE / VALID_CIDR / VALID_HOSTNAME (optionally preceded
# by a WARNING line for private IPs/ranges, which is not itself a failure),
# or an ERROR line, and returns 0/1 accordingly. Does not exit - callers
# (main, and the comma-separated-list loop below) decide what to do with
# the result so one bad target in a list doesn't short-circuit the rest.
validate_single_target() {
    local target="$1"

    # Remove any shell metacharacters for safety
    target=$(echo "$target" | sed 's/[;&|`$()<>]//g')

    if [ -z "$target" ]; then
        echo "ERROR: Empty target"
        return 1
    fi

    # Check if it's an IP address
    if validate_ip "$target"; then
        # It's a valid IP, check if dangerous
        if is_dangerous_ip "$target"; then
            return 1
        fi

        # Warn about private IPs
        if is_private_ip "$target"; then
            echo "WARNING: Targeting private IP address: $target"
        fi

        echo "VALID_IP: $target"
        return 0
    fi

    # Check if it's range-shaped (e.g. 10.10.10.1-254) - this whole branch,
    # not just the valid case, must run before the hostname check below
    # (F4): any input shaped like an IP range is handled and returned on
    # here, valid or not, so a malformed range (e.g. bad octet, or an
    # out-of-bounds "127.0.0.1-999") can never fall through to
    # validate_hostname and get silently accepted as VALID_HOSTNAME,
    # bypassing is_dangerous_ip()/is_private_ip().
    if looks_like_ip_range "$target"; then
        if ! validate_ip_range "$target"; then
            echo "ERROR: Invalid IP range format: $target"
            return 1
        fi

        local base_ip="${target%-*}"

        if is_dangerous_ip "$base_ip"; then
            return 1
        fi

        if is_private_ip "$base_ip"; then
            echo "WARNING: Targeting private IP range: $target"
        fi

        echo "VALID_RANGE: $target"
        return 0
    fi

    # Reject dotted-quad-shaped input that validate_ip already rejected
    # (e.g. "300.300.300.300" - out-of-range octet) before it can reach
    # validate_hostname, whose regex would otherwise accept a numeric-only
    # dotted string as a valid hostname (see looks_like_ipv4).
    if looks_like_ipv4 "$target"; then
        echo "ERROR: Invalid IP address format: $target"
        return 1
    fi

    # Check if it's a hostname
    if validate_hostname "$target"; then
        echo "VALID_HOSTNAME: $target"
        return 0
    fi

    # Check if it's a CIDR range
    if echo "$target" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
        # Extract the IP part
        local ip_part cidr_part
        ip_part=$(echo "$target" | cut -d'/' -f1)
        cidr_part=$(echo "$target" | cut -d'/' -f2)

        if validate_ip "$ip_part" && [ "$cidr_part" -ge 0 ] && [ "$cidr_part" -le 32 ]; then
            # Check if the base IP is dangerous
            if is_dangerous_ip "$ip_part"; then
                return 1
            fi

            echo "VALID_CIDR: $target"
            return 0
        fi
    fi

    echo "ERROR: Invalid target format: $target"
    return 1
}

# Main entry point. A single target is validated directly; a
# comma-separated list ("10.10.10.10,10.10.10.11,dc01") is split and each
# target validated independently via validate_single_target, failing the
# whole call if any single target in the list fails (L15).
main() {
    local input="${1:-}"

    if [ -z "$input" ]; then
        echo "ERROR: No target provided"
        exit 1
    fi

    if [[ "$input" == *,* ]]; then
        local overall_status=0
        local raw_target target
        IFS=',' read -r -a targets <<< "$input"
        for raw_target in "${targets[@]}"; do
            # Trim surrounding whitespace (e.g. "a, b, c")
            target=$(echo "$raw_target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -z "$target" ]; then
                echo "ERROR: Empty target in list: $input"
                overall_status=1
                continue
            fi
            validate_single_target "$target" || overall_status=1
        done
        exit "$overall_status"
    fi

    if validate_single_target "$input"; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"