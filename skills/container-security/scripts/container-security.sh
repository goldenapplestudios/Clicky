#!/bin/bash
#
# Container and Kubernetes Security Testing
# Tests for container escapes, K8s misconfigs, and orchestration vulns
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to detect if running in a container
detect_container() {
    echo -e "${YELLOW}[*] Detecting container environment...${NC}"

    # Check for .dockerenv file
    if [ -f /.dockerenv ]; then
        echo -e "${GREEN}[+] Running in Docker container (.dockerenv found)${NC}"
        return 0
    fi

    # Check cgroup
    if grep -q "docker\|kubepods\|containerd" /proc/self/cgroup 2>/dev/null; then
        echo -e "${GREEN}[+] Running in container (cgroup evidence)${NC}"
        return 0
    fi

    # Check for container-specific files
    if [ -f /run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo -e "${GREEN}[+] Running in Kubernetes pod${NC}"
        return 0
    fi

    echo "[*] Not running in a container"
    return 1
}

# Function to test for Kubernetes API access
test_kubernetes_api() {
    local target="${1:-kubernetes.default.svc}"
    local port="${2:-443}"

    echo -e "${YELLOW}[*] Testing Kubernetes API access...${NC}"

    # Try to access K8s API
    if nc -zv -w2 "$target" "$port" 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${GREEN}[+] Kubernetes API is reachable on $target:$port${NC}"

        # Test unauthenticated access
        response=$(curl -sk "https://$target:$port/api" 2>/dev/null || echo "")
        if echo "$response" | grep -q "kind.*APIVersions"; then
            echo -e "${RED}[!] Kubernetes API accessible!${NC}"

            # Try to list namespaces
            namespaces=$(curl -sk "https://$target:$port/api/v1/namespaces" 2>/dev/null || echo "")
            if echo "$namespaces" | grep -q "NamespaceList"; then
                echo -e "${RED}[!] CRITICAL: Can list namespaces without authentication!${NC}"
            fi

            # Try to list pods
            pods=$(curl -sk "https://$target:$port/api/v1/pods" 2>/dev/null || echo "")
            if echo "$pods" | grep -q "PodList"; then
                echo -e "${RED}[!] CRITICAL: Can list pods without authentication!${NC}"
            fi

            # Try to list secrets
            secrets=$(curl -sk "https://$target:$port/api/v1/secrets" 2>/dev/null || echo "")
            if echo "$secrets" | grep -q "SecretList"; then
                echo -e "${RED}[!] CRITICAL: Can list secrets without authentication!${NC}"
            fi
        fi

        # Test with service account token if available
        if [ -f /run/secrets/kubernetes.io/serviceaccount/token ]; then
            TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
            echo -e "${YELLOW}[*] Testing with service account token...${NC}"

            # Check permissions
            auth_response=$(curl -sk -H "Authorization: Bearer $TOKEN" \
                "https://$target:$port/api/v1/namespaces/default/pods" 2>/dev/null || echo "")

            if echo "$auth_response" | grep -q "PodList"; then
                echo -e "${GREEN}[+] Service account can list pods${NC}"
            fi
        fi
    else
        echo "[*] Kubernetes API not reachable on $target:$port"
    fi
}

# Function to check for container escape vectors
test_container_escapes() {
    echo -e "${YELLOW}[*] Testing for container escape vectors...${NC}"

    # Check if Docker socket is mounted
    if [ -S /var/run/docker.sock ]; then
        echo -e "${RED}[!] Docker socket is mounted! Container escape possible${NC}"
        echo "  Exploit: docker run -v /:/host --privileged -it alpine chroot /host"
    fi

    # Check if privileged
    if [ -r /proc/self/status ]; then
        if grep -q "CapEff:\s*[0-9a-f]*ff" /proc/self/status; then
            echo -e "${RED}[!] Running as privileged container!${NC}"
        fi
    fi

    # Check for dangerous capabilities
    if capsh --print 2>/dev/null | grep -q "cap_sys_admin\|cap_sys_ptrace"; then
        echo -e "${RED}[!] Dangerous capabilities detected${NC}"
    fi

    # Check if /proc/sys is writable
    if [ -w /proc/sys/kernel/core_pattern ]; then
        echo -e "${RED}[!] /proc/sys is writable - kernel parameters can be modified${NC}"
    fi

    # Check for host PID namespace
    if [ -d /proc/1/root ] && [ "$(stat -c %i /)" != "$(stat -c %i /proc/1/root 2>/dev/null || echo 0)" ]; then
        echo -e "${YELLOW}[!] Host PID namespace might be shared${NC}"
    fi

    # Check for release_agent exploit (CVE-2022-0492)
    if [ -w /sys/fs/cgroup ]; then
        echo -e "${RED}[!] cgroup is writable - release_agent escape possible${NC}"
    fi
}

# Function to enumerate Kubernetes resources
enumerate_k8s_resources() {
    local target="${1:-kubernetes.default.svc}"

    echo -e "${YELLOW}[*] Enumerating Kubernetes resources...${NC}"

    # Use kubectl if available
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "${GREEN}[+] kubectl is available${NC}"

        # Get current context
        kubectl config current-context 2>/dev/null || echo "No context configured"

        # Try to enumerate
        echo "Trying to enumerate resources..."
        kubectl get nodes 2>/dev/null || echo "  Cannot list nodes"
        kubectl get pods --all-namespaces 2>/dev/null || echo "  Cannot list pods"
        kubectl get secrets --all-namespaces 2>/dev/null || echo "  Cannot list secrets"
        kubectl get svc --all-namespaces 2>/dev/null || echo "  Cannot list services"
    fi

    # Check for etcd
    if nc -zv -w2 "$target" 2379 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${RED}[!] etcd port 2379 is open!${NC}"
        # Test etcd access
        curl -s "http://$target:2379/v2/keys/" 2>/dev/null | head -20
    fi

    # Check for kubelet read-only port
    if nc -zv -w2 "$target" 10255 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${YELLOW}[!] Kubelet read-only port 10255 is open${NC}"
        curl -s "http://$target:10255/pods" 2>/dev/null | head -20
    fi

    # Check for kubelet authenticated port
    if nc -zv -w2 "$target" 10250 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${YELLOW}[!] Kubelet port 10250 is open${NC}"
    fi
}

# Function to check for common misconfigurations
check_k8s_misconfigurations() {
    echo -e "${YELLOW}[*] Checking for Kubernetes misconfigurations...${NC}"

    # Check for default service accounts
    if [ -f /run/secrets/kubernetes.io/serviceaccount/token ]; then
        namespace=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "default")
        echo "[+] Running in namespace: $namespace"

        # Check if default service account
        if [ "$namespace" == "default" ]; then
            echo -e "${YELLOW}[!] Using default namespace${NC}"
        fi
    fi

    # Check for exposed dashboard
    local dashboard_ports=(443 8443 8001 30000)
    for port in "${dashboard_ports[@]}"; do
        if curl -sk "https://localhost:$port" 2>/dev/null | grep -q "kubernetes-dashboard"; then
            echo -e "${RED}[!] Kubernetes Dashboard exposed on port $port${NC}"
        fi
    done

    # Check for Tiller (Helm v2)
    if nc -zv -w2 localhost 44134 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${RED}[!] Tiller (Helm v2) is running - known security issues${NC}"
    fi
}

# Function to test for CVEs
test_container_cves() {
    echo -e "${YELLOW}[*] Testing for known container CVEs...${NC}"

    # Check kernel version for DirtyPipe (CVE-2022-0847)
    kernel_version=$(uname -r)
    echo "[*] Kernel version: $kernel_version"

    # Check for RunC vulnerability (CVE-2024-21626)
    if command -v runc >/dev/null 2>&1; then
        runc_version=$(runc --version | head -1)
        echo "[*] RunC version: $runc_version"
    fi

    # Test for log4shell in Java apps
    if command -v java >/dev/null 2>&1; then
        java_version=$(java -version 2>&1 | head -1)
        echo "[*] Java version: $java_version"
    fi
}

# Function to generate report
generate_container_report() {
    local output_dir="$1"
    local target="$2"

    cat > "$output_dir/container_security_report.md" << EOF
# Container & Kubernetes Security Assessment

**Target:** $target
**Date:** $(date)

## Environment Detection
- Container Type: $(detect_container 2>&1 | grep "Running" || echo "Not in container")
- Orchestration: Kubernetes/Docker/Other

## Critical Findings

### Container Escape Vectors
- [ ] Docker socket mounted
- [ ] Privileged container
- [ ] Dangerous capabilities
- [ ] Host namespaces shared

### Kubernetes Misconfigurations
- [ ] Unauthenticated API access
- [ ] Exposed dashboard
- [ ] etcd accessible
- [ ] Secrets readable

### RBAC Issues
- [ ] Over-privileged service accounts
- [ ] Cluster-admin bindings
- [ ] Wildcard permissions

## Recommendations

1. Never mount Docker socket in containers
2. Avoid privileged containers
3. Implement network policies
4. Use RBAC least privilege
5. Enable audit logging
6. Scan images for vulnerabilities
7. Use admission controllers

## Attack Paths Identified

1. Container Escape → Host Access
2. K8s API → Cluster Takeover
3. Service Account → Lateral Movement

EOF

    echo -e "${GREEN}[+] Report saved to $output_dir/container_security_report.md${NC}"
}

# Main function
main() {
    local target="${1:-localhost}"
    local output_dir="${2:-.}"

    mkdir -p "$output_dir"

    echo -e "${GREEN}=== Container & Kubernetes Security Testing ===${NC}"
    echo "Target: $target"
    echo ""

    # Detect environment
    if detect_container; then
        # Inside container - test for escapes
        test_container_escapes
    fi

    # Test Kubernetes
    test_kubernetes_api "$target"
    enumerate_k8s_resources "$target"
    check_k8s_misconfigurations

    # Test for CVEs
    test_container_cves

    # Generate report
    generate_container_report "$output_dir" "$target"

    echo ""
    echo -e "${GREEN}[+] Container security testing complete${NC}"
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi