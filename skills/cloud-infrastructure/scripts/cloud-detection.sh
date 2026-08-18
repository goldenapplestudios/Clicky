#!/bin/bash
#
# Cloud Provider Detection Script
# Identifies cloud infrastructure and services
#

set -euo pipefail

# Function to detect cloud provider from IP
detect_cloud_by_ip() {
    local target="$1"
    local ip=$(dig +short "$target" 2>/dev/null | head -1)

    if [ -z "$ip" ]; then
        ip="$target"
    fi

    # Check AWS IP ranges - real CIDR-containment check against each
    # published ip_prefix, not a literal-substring grep over the raw
    # JSON (which only ever matches the rare /32 entries and misses the
    # vast majority of real AWS-hosted targets). Same
    # ipaddress-module-via-python3 pattern used in
    # target-validation/scripts/scope-validator.sh.
    if command -v python3 >/dev/null 2>&1 && \
       curl -s --max-time 10 https://ip-ranges.amazonaws.com/ip-ranges.json 2>/dev/null | python3 -c '
import ipaddress
import json
import sys

ip = sys.argv[1]
try:
    addr = ipaddress.ip_address(ip)
except ValueError:
    sys.exit(1)

try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(1)

for entry in data.get("prefixes", []):
    cidr = entry.get("ip_prefix")
    if not cidr:
        continue
    try:
        if addr in ipaddress.ip_network(cidr, strict=False):
            sys.exit(0)
    except ValueError:
        continue

sys.exit(1)
' "$ip" 2>/dev/null; then
        echo "AWS"
        return 0
    fi

    # Check Azure IP ranges (simplified check)
    if nslookup "$ip" 2>/dev/null | grep -q "azure\|microsoft"; then
        echo "Azure"
        return 0
    fi

    # Check GCP IP ranges
    if nslookup "$ip" 2>/dev/null | grep -q "google\|googleusercontent"; then
        echo "GCP"
        return 0
    fi

    echo "Unknown"
}

# Function to check for S3 buckets
check_s3_buckets() {
    local domain="$1"
    local keywords=("www" "data" "backup" "logs" "assets" "static" "uploads" "files" "documents" "media")

    echo "[*] Checking for S3 buckets..." >&2

    for keyword in "${keywords[@]}"; do
        local bucket_name="${keyword}-${domain}"
        local bucket_url="https://${bucket_name}.s3.amazonaws.com"

        # Check if bucket exists - status code via -w, not grep over raw
        # header text: a plain `grep -q "200\|403"` over -I output also
        # matches e.g. a "Content-Length: 1200" or "x-amz-id-2: ...403..."
        # header that has nothing to do with the actual HTTP status line.
        local status_code
        status_code=$(curl -s --max-time 10 -I -o /dev/null -w "%{http_code}" "$bucket_url" 2>/dev/null)
        if [ "$status_code" = "200" ] || [ "$status_code" = "403" ]; then
            echo "[+] Potential S3 bucket found: $bucket_url (HTTP $status_code)"

            # Check if publicly accessible
            if curl -s --max-time 10 "$bucket_url" 2>/dev/null | grep -q "ListBucketResult"; then
                echo "[!] PUBLIC S3 BUCKET: $bucket_url"
            fi
        fi
    done
}

# Function to check for Azure storage
check_azure_storage() {
    local domain="$1"
    local storage_accounts=("storage" "data" "backup" "files" "blob")

    echo "[*] Checking for Azure storage accounts..." >&2

    for account in "${storage_accounts[@]}"; do
        local storage_url="https://${account}${domain//./}.blob.core.windows.net"

        # "200\|403\|404" via grep over -I output was really just asking
        # "did the vhost resolve and answer HTTP at all" - curl's %{http_code}
        # gives that directly (and "000" specifically means no HTTP response
        # was received), without the same raw-header substring-collision risk.
        local status_code
        status_code=$(curl -s --max-time 10 -I -o /dev/null -w "%{http_code}" "$storage_url" 2>/dev/null)
        if [ -n "$status_code" ] && [ "$status_code" != "000" ]; then
            echo "[+] Potential Azure storage: $storage_url (HTTP $status_code)"
        fi
    done
}

# Function to check whether the LOCAL machine this script is running on
# (not the remote $target) can reach a cloud instance metadata service.
#
# This is deliberately a local self-check, not a target probe: AWS/Azure/GCP
# instance metadata lives at the link-local address 169.254.169.254, which is
# only routable from inside the cloud instance itself - it is never reachable
# by remotely curling $target from the operator's machine. So there is no
# "$target's metadata endpoint" to check over the network; the only
# meaningful thing to test here is "is *this* machine (e.g. because we've
# landed a shell inside a cloud instance/container during the engagement)
# sitting on a cloud instance with its own metadata service exposed" -
# mirroring the local-environment fingerprint pattern used by
# detect_container() in container-security.sh.
check_local_cloud_metadata() {
    echo "[*] Checking for locally-accessible cloud metadata service..." >&2

    # AWS metadata
    if curl -s --max-time 2 "http://169.254.169.254/latest/meta-data/" 2>/dev/null | grep -q "ami-id"; then
        echo "[!] AWS METADATA ACCESSIBLE (this machine appears to be an AWS instance)"
    fi

    # Azure metadata
    if curl -s --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-01-01" 2>/dev/null | grep -q "compute"; then
        echo "[!] AZURE METADATA ACCESSIBLE (this machine appears to be an Azure instance)"
    fi

    # GCP metadata
    if curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/" 2>/dev/null | grep -q "instance"; then
        echo "[!] GCP METADATA ACCESSIBLE (this machine appears to be a GCP instance)"
    fi
}

# Function to check for Kubernetes API
check_kubernetes() {
    local target="$1"
    local k8s_ports=(6443 8443 443 8001 10250)

    echo "[*] Checking for Kubernetes API..." >&2

    for port in "${k8s_ports[@]}"; do
        if nc -zv -w2 "$target" "$port" 2>&1 | grep -q "succeeded\|open"; then
            # Check for K8s API
            if curl -sk --max-time 10 "https://${target}:${port}/api" 2>/dev/null | grep -q "kubernetes"; then
                echo "[!] KUBERNETES API FOUND on port $port"

                # Check if unauthenticated
                if curl -sk --max-time 10 "https://${target}:${port}/api/v1/namespaces" 2>/dev/null | grep -q "namespace"; then
                    echo "[!] UNAUTHENTICATED KUBERNETES API!"
                fi
            fi
        fi
    done
}

# Function to check for container registries
check_container_registries() {
    local domain="$1"

    echo "[*] Checking for container registries..." >&2

    # Docker Hub - a v2 registry API answers 200 (anonymous access allowed)
    # or 401 (auth required, but the registry is definitely there) at this
    # path; checking the status code directly rather than grepping the
    # response body for those digits (which normally isn't even present).
    local docker_registry="registry.${domain}"
    local status_code
    status_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "https://${docker_registry}/v2/" 2>/dev/null)
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        echo "[+] Docker registry found: $docker_registry (HTTP $status_code)"
    fi

    # AWS ECR
    local ecr_registry="${domain}.dkr.ecr.us-east-1.amazonaws.com"
    if nslookup "$ecr_registry" 2>/dev/null | grep -q "Address"; then
        echo "[+] AWS ECR registry possible: $ecr_registry"
    fi
}

# Function to check for exposed Terraform state files
#
# Terraform state (.tfstate) routinely embeds plaintext secrets (cloud
# access keys, DB passwords, private keys) inlined into resource
# attributes - an exposed one is a near-guaranteed critical finding, not
# just an info leak. Reuses check_s3_buckets's candidate-bucket-name
# pattern (same keyword list, same reasoning: teams often dump Terraform
# state into the same buckets they use for other backups) then probes
# common state object paths against both S3 and the Azure Blob
# equivalent. HTTP 200 alone isn't proof it's a real state file (could be
# an empty object, a custom 200 error page, etc.), so this only reports a
# hit once a body-level "terraform_version" key confirms it's genuinely
# Terraform state - then greps the body against the same secret-shape
# patterns used elsewhere in this repo (AWS access key, PEM private key
# header, inline password/secret_key JSON fields) to distinguish
# "exposed, no visible secrets yet" from "exposed, CRITICAL."
check_terraform_state_exposure() {
    local domain="$1"
    local keywords=("www" "data" "backup" "logs" "assets" "static" "uploads" "files" "documents" "media")
    local state_paths=("terraform.tfstate" "terraform.tfstate.backup" "env:/prod/terraform.tfstate")

    echo "[*] Checking for exposed Terraform state files..." >&2

    for keyword in "${keywords[@]}"; do
        local bucket_name="${keyword}-${domain}"

        for state_path in "${state_paths[@]}"; do
            local s3_url="https://${bucket_name}.s3.amazonaws.com/${state_path}"
            local azure_url="https://${bucket_name//./}.blob.core.windows.net/${bucket_name}/${state_path}"

            for state_url in "$s3_url" "$azure_url"; do
                # Status code first (cheap), same %{http_code} convention as
                # check_s3_buckets/check_azure_storage - a raw grep over -I
                # header text has the same false-positive risk documented
                # there.
                local status_code
                status_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$state_url" 2>/dev/null)
                if [ "$status_code" = "200" ]; then
                    local body
                    body=$(curl -s --max-time 10 "$state_url" 2>/dev/null)
                    if echo "$body" | grep -q '"terraform_version"'; then
                        echo "[!] EXPOSED TERRAFORM STATE: $state_url"

                        if echo "$body" | grep -qE 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"(password|secret_key|private_key)"[[:space:]]*:[[:space:]]*"[^"]+"'; then
                            echo "[!] CRITICAL: Terraform state contains embedded secrets: $state_url"
                        else
                            echo "[+] Terraform state exposed but no obvious embedded secrets found: $state_url"
                        fi
                    fi
                fi
            done
        done
    done
}

# Function to check for exposed CI/CD configuration files
#
# CI/CD config files (GitHub Actions workflows, GitLab CI, Jenkinsfiles,
# CircleCI config) routinely embed secrets (API tokens, deploy keys,
# cloud credentials) directly in YAML env:/with: blocks, even though the
# platform's own secrets manager exists specifically to avoid that. This
# probes the target's own web root first, the same exposed-deployment-
# artifact class as an exposed .git directory. The optional second pass
# fetches a public repo's raw CI config directly from
# github.com/gitlab.com if osint-gathering already identified one for
# this engagement - a convenience path on an already-in-scope repo, not
# a second discovery mechanism, and it is never invoked without a
# repo_slug explicitly supplied by the caller.
check_cicd_config_exposure() {
    local domain="$1"
    local repo_slug="${2:-}"   # optional "org/repo" already discovered via osint-gathering
    local cicd_paths=(
        ".github/workflows/"
        ".github/workflows/ci.yml"
        ".github/workflows/deploy.yml"
        ".gitlab-ci.yml"
        "Jenkinsfile"
        ".circleci/config.yml"
    )

    echo "[*] Checking for exposed CI/CD configuration files..." >&2

    for path in "${cicd_paths[@]}"; do
        local url="https://${domain}/${path}"

        # Same %{http_code} convention as check_s3_buckets - status code
        # first, body only fetched once we know something is actually there.
        local status_code
        status_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        if [ "$status_code" = "200" ]; then
            echo "[+] Potential exposed CI/CD config: $url (HTTP $status_code)"

            local body
            body=$(curl -s --max-time 10 "$url" 2>/dev/null)
            if echo "$body" | grep -qE 'AKIA[0-9A-Z]{16}|gh[po]_[A-Za-z0-9]{22,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20}|atlasv1\.[A-Za-z0-9_-]{40,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' \
               || echo "$body" | grep -qiE '(password|secret|api[_-]?key)[[:space:]]*[:=]'; then
                echo "[!] CRITICAL: CI/CD config appears to expose credentials: $url"
            fi
        fi
    done

    if [ -n "$repo_slug" ]; then
        echo "[*] Checking raw CI/CD config on already-in-scope public repo: $repo_slug" >&2
        local raw_urls=(
            "https://raw.githubusercontent.com/${repo_slug}/main/.github/workflows/ci.yml"
            "https://raw.githubusercontent.com/${repo_slug}/master/.github/workflows/ci.yml"
            "https://gitlab.com/${repo_slug}/-/raw/main/.gitlab-ci.yml"
        )
        for raw_url in "${raw_urls[@]}"; do
            local raw_status
            raw_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$raw_url" 2>/dev/null)
            if [ "$raw_status" = "200" ]; then
                echo "[+] Public repo CI/CD config found: $raw_url"
            fi
        done
    fi
}

# Function to check for exposed Ansible vault / inventory files
#
# Deliberately low-yield: an Ansible vault file is primarily a white-box
# concern (skills/source-code-analysis's source_taint_scan.py scans a
# checked-out source tree for these directly) - it has no meaningful
# black-box network presence unless the target is inadvertently serving
# its own deployment tree from its web root, the same misconfiguration
# class as an exposed .git directory. Kept intentionally narrow: four
# well-known paths, no bucket-name guessing.
check_ansible_vault_exposure() {
    local domain="$1"
    local vault_paths=("ansible/" "inventory.ini" "group_vars/all/vault.yml" ".vault_pass")

    echo "[*] Checking for exposed Ansible vault/inventory files (low-yield, black-box only - see header comment)..." >&2

    for path in "${vault_paths[@]}"; do
        local url="https://${domain}/${path}"

        local status_code
        status_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        if [ "$status_code" = "200" ]; then
            echo "[+] Potential exposed Ansible file: $url (HTTP $status_code)"

            local body
            body=$(curl -s --max-time 10 "$url" 2>/dev/null)
            if echo "$body" | grep -q '\$ANSIBLE_VAULT'; then
                echo "[!] CRITICAL: Ansible Vault-encrypted file confirmed exposed: $url"
            fi
        fi
    done
}

# Function to generate cloud detection report
generate_cloud_report() {
    local target="$1"
    local output_dir="${2:-.}"

    mkdir -p "$output_dir"

    {
        echo "=== Cloud Infrastructure Detection Report ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo ""

        echo "=== Cloud Provider ==="
        detect_cloud_by_ip "$target"
        echo ""

        echo "=== Storage Services ==="
        check_s3_buckets "$target"
        check_azure_storage "$target"
        echo ""

        echo "=== Metadata Endpoints (local machine self-check, not $target) ==="
        check_local_cloud_metadata
        echo ""

        echo "=== Container Services ==="
        check_kubernetes "$target"
        check_container_registries "$target"
        echo ""

        echo "=== Infrastructure-as-Code / CI-CD Exposure ==="
        check_terraform_state_exposure "$target"
        check_cicd_config_exposure "$target"
        check_ansible_vault_exposure "$target"
        echo ""

    } | tee "$output_dir/cloud_detection.txt"
}

# Main function
main() {
    local target="${1:-}"
    local output_dir="${2:-.}"

    if [ -z "$target" ]; then
        echo "Usage: $0 <target> [output_dir]" >&2
        echo "" >&2
        echo "Example:" >&2
        echo "  $0 example.com ./cloud_results/" >&2
        exit 1
    fi

    echo "[*] Starting cloud detection for: $target" >&2
    generate_cloud_report "$target" "$output_dir"
    echo "[*] Cloud detection complete" >&2
}

# Only run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi