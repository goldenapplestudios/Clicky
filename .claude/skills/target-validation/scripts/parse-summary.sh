#!/bin/bash
#
# Summary Parser for Penetration Testing
# Safely extracts credentials, hints, and vulnerabilities from user input
#

set -euo pipefail

# Function to extract passwords
extract_passwords() {
    local summary="$1"

    # Look for password patterns
    echo "$summary" | grep -oiE 'password[s]?\s*:\s*[^,]+' | \
        sed -E 's/password[s]?\s*:\s*//i' | \
        tr ',' '\n' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        sort -u
}

# Function to extract usernames
extract_usernames() {
    local summary="$1"

    # Look for username patterns
    echo "$summary" | grep -oiE 'user[s]?\s*:\s*[^,]+' | \
        sed -E 's/user[s]?\s*:\s*//i' | \
        tr ',' '\n' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        sort -u
}

# Function to extract credentials (user:pass format)
extract_credentials() {
    local summary="$1"

    # Look for credential patterns
    echo "$summary" | grep -oiE 'cred[s]?\s*:\s*[^:,]+:[^,]+' | \
        sed -E 's/cred[s]?\s*:\s*//i' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        sort -u
}

# Function to extract domain
extract_domain() {
    local summary="$1"

    # Look for domain pattern
    echo "$summary" | grep -oiE 'domain\s*:\s*[^,]+' | \
        sed -E 's/domain\s*:\s*//i' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        head -1
}

# Function to extract hints
extract_hints() {
    local summary="$1"

    # Look for hint patterns
    echo "$summary" | grep -oiE 'hint[s]?\s*:\s*[^,]+' | \
        sed -E 's/hint[s]?\s*:\s*//i' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$'
}

# Function to extract notes
extract_notes() {
    local summary="$1"

    # Look for note patterns
    echo "$summary" | grep -oiE 'note[s]?\s*:\s*[^,]+' | \
        sed -E 's/note[s]?\s*:\s*//i' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$'
}

# Function to extract vulnerabilities
extract_vulnerabilities() {
    local summary="$1"

    # Look for vulnerability patterns
    echo "$summary" | grep -oiE '(vuln|vulnerable|CVE-[0-9]{4}-[0-9]+)[^,]*' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        sort -u
}

# Function to extract tokens
extract_tokens() {
    local summary="$1"

    # Look for JWT tokens
    echo "$summary" | grep -oiE 'jwt\s*:\s*[A-Za-z0-9._-]+' | \
        sed -E 's/jwt\s*:\s*//i' | \
        grep -v '^$'

    # Look for API keys
    echo "$summary" | grep -oiE 'api[_-]?key\s*:\s*[A-Za-z0-9_-]+' | \
        sed -E 's/api[_-]?key\s*:\s*//i' | \
        grep -v '^$'

    # Look for general tokens
    echo "$summary" | grep -oiE 'token\s*:\s*[A-Za-z0-9._-]+' | \
        sed -E 's/token\s*:\s*//i' | \
        grep -v '^$'
}

# Function to extract services
extract_services() {
    local summary="$1"

    # Look for service patterns
    echo "$summary" | grep -oiE 'service[s]?\s*:\s*[^,]+' | \
        sed -E 's/service[s]?\s*:\s*//i' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$'
}

# Function to extract ports
extract_ports() {
    local summary="$1"

    # Look for port patterns
    echo "$summary" | grep -oiE 'port[s]?\s*:\s*[0-9]+' | \
        sed -E 's/port[s]?\s*:\s*//i' | \
        grep -v '^$'
}

# Main function to parse and save all extracted data
parse_and_save() {
    local summary="$1"
    local output_dir="${2:-.}"

    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"

    # Extract and save each type of data
    echo "=== Parsing Summary ===" >&2

    # Passwords
    local passwords=$(extract_passwords "$summary")
    if [ -n "$passwords" ]; then
        echo "$passwords" > "$output_dir/passwords.txt"
        echo "[+] Passwords extracted: $(echo "$passwords" | wc -l)" >&2
    fi

    # Usernames
    local usernames=$(extract_usernames "$summary")
    if [ -n "$usernames" ]; then
        echo "$usernames" > "$output_dir/users.txt"
        echo "[+] Usernames extracted: $(echo "$usernames" | wc -l)" >&2
    fi

    # Credentials
    local credentials=$(extract_credentials "$summary")
    if [ -n "$credentials" ]; then
        echo "$credentials" > "$output_dir/credentials.txt"
        echo "[+] Credentials extracted: $(echo "$credentials" | wc -l)" >&2
    fi

    # Domain
    local domain=$(extract_domain "$summary")
    if [ -n "$domain" ]; then
        echo "$domain" > "$output_dir/domain.txt"
        echo "[+] Domain extracted: $domain" >&2
    fi

    # Hints
    local hints=$(extract_hints "$summary")
    if [ -n "$hints" ]; then
        echo "$hints" > "$output_dir/hints.txt"
        echo "[+] Hints extracted: $(echo "$hints" | wc -l)" >&2
    fi

    # Notes
    local notes=$(extract_notes "$summary")
    if [ -n "$notes" ]; then
        echo "$notes" > "$output_dir/notes.txt"
        echo "[+] Notes extracted: $(echo "$notes" | wc -l)" >&2
    fi

    # Vulnerabilities
    local vulns=$(extract_vulnerabilities "$summary")
    if [ -n "$vulns" ]; then
        echo "$vulns" > "$output_dir/vulns.txt"
        echo "[+] Vulnerabilities extracted: $(echo "$vulns" | wc -l)" >&2
    fi

    # Tokens
    local tokens=$(extract_tokens "$summary")
    if [ -n "$tokens" ]; then
        echo "$tokens" > "$output_dir/tokens.txt"
        echo "[+] Tokens extracted: $(echo "$tokens" | wc -l)" >&2
    fi

    # Services
    local services=$(extract_services "$summary")
    if [ -n "$services" ]; then
        echo "$services" > "$output_dir/services.txt"
        echo "[+] Services extracted: $(echo "$services" | wc -l)" >&2
    fi

    # Ports
    local ports=$(extract_ports "$summary")
    if [ -n "$ports" ]; then
        echo "$ports" > "$output_dir/ports.txt"
        echo "[+] Ports extracted: $(echo "$ports" | wc -l)" >&2
    fi

    echo "=== Parsing Complete ===" >&2
    return 0
}

# Main function for CLI usage
main() {
    local summary="${1:-}"
    local output_dir="${2:-.}"

    if [ -z "$summary" ]; then
        echo "Usage: $0 <summary> [output_dir]" >&2
        echo "" >&2
        echo "Example:" >&2
        echo '  $0 "user: admin, password: Password123, hint: check FTP" ./extracted/' >&2
        exit 1
    fi

    parse_and_save "$summary" "$output_dir"
}

# Only run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi