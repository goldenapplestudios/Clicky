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

    # Check AWS IP ranges
    if curl -s https://ip-ranges.amazonaws.com/ip-ranges.json 2>/dev/null | grep -q "$ip"; then
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

        # Check if bucket exists
        if curl -s -I "$bucket_url" 2>/dev/null | grep -q "200\|403"; then
            echo "[+] Potential S3 bucket found: $bucket_url"

            # Check if publicly accessible
            if curl -s "$bucket_url" 2>/dev/null | grep -q "ListBucketResult"; then
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

        if curl -s -I "$storage_url" 2>/dev/null | grep -q "200\|403\|404"; then
            echo "[+] Potential Azure storage: $storage_url"
        fi
    done
}

# Function to check for exposed metadata endpoints
check_metadata_endpoints() {
    local target="$1"

    echo "[*] Checking for metadata endpoints..." >&2

    # AWS metadata
    local aws_metadata="http://${target}/latest/meta-data/"
    if curl -s --max-time 2 "http://169.254.169.254/latest/meta-data/" 2>/dev/null | grep -q "ami-id"; then
        echo "[!] AWS METADATA ACCESSIBLE"
    fi

    # Azure metadata
    local azure_metadata="http://${target}/metadata/instance"
    if curl -s --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-01-01" 2>/dev/null | grep -q "compute"; then
        echo "[!] AZURE METADATA ACCESSIBLE"
    fi

    # GCP metadata
    local gcp_metadata="http://metadata.google.internal/computeMetadata/v1/"
    if curl -s --max-time 2 -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/" 2>/dev/null | grep -q "instance"; then
        echo "[!] GCP METADATA ACCESSIBLE"
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
            if curl -sk "https://${target}:${port}/api" 2>/dev/null | grep -q "kubernetes"; then
                echo "[!] KUBERNETES API FOUND on port $port"

                # Check if unauthenticated
                if curl -sk "https://${target}:${port}/api/v1/namespaces" 2>/dev/null | grep -q "namespace"; then
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

    # Docker Hub
    local docker_registry="registry.${domain}"
    if curl -s "https://${docker_registry}/v2/" 2>/dev/null | grep -q "200\|401"; then
        echo "[+] Docker registry found: $docker_registry"
    fi

    # AWS ECR
    local ecr_registry="${domain}.dkr.ecr.us-east-1.amazonaws.com"
    if nslookup "$ecr_registry" 2>/dev/null | grep -q "Address"; then
        echo "[+] AWS ECR registry possible: $ecr_registry"
    fi
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

        echo "=== Metadata Endpoints ==="
        check_metadata_endpoints "$target"
        echo ""

        echo "=== Container Services ==="
        check_kubernetes "$target"
        check_container_registries "$target"
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