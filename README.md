# awseasy

> AWS cloud provisioning for GenAI workloads — made easy.

## Install

```sh
pip install awseasy
```

## Overview

`awseasy` is the AWS sibling of [`azeasy`](https://github.com/vedicreader/azeasy) — thin, Pythonic wrappers over boto3 for provisioning enterprise GenAI infrastructure. Same design pattern across the `vedicreader` toolchain:

| Tool | Purpose |
|---|---|
| dockeasy | Docker/Compose config generation |
| cfeasy | Cloudflare DNS + Zero Trust tunnels |
| vpseasy | Hetzner VPS provisioning + deployment |
| fastops | DevOps toolkit — containers, reverse proxies, VMs |
| azeasy | Azure cloud provisioning for GenAI workloads |
| **awseasy** | **AWS cloud provisioning for GenAI workloads** |

**Design principles:**
- Standalone functions for stateless ops, thin classes only when needed
- All `create_*` functions use create-or-update semantics (idempotent)
- Compliance as composable dict profiles — pass `**HIPAA` to any `create_*` call
- No hardcoded credentials anywhere — standard boto3 credential chain
- Built with [nbdev](https://nbdev.fast.ai/) — notebooks are the source of truth

## Authentication

`AWSAuth` wraps `boto3.Session` and supports the full credential chain with no configuration required in typical AWS environments:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. AWS shared credentials file (`~/.aws/credentials`)
3. EC2/ECS instance profile (IAM role attached to the compute resource)
4. EKS pod identity / IRSA (IAM Roles for Service Accounts)
5. AWS SSO via IAM Identity Center


```
#| eval: false
from awseasy import *

auth = AWSAuth()                                   # uses AWS_DEFAULT_REGION env var
auth = AWSAuth(region='eu-west-1')                 # explicit region
auth = AWSAuth(profile='staging')                  # named AWS profile
auth = AWSAuth(role_arn='arn:aws:iam::123:role/x') # cross-account assume-role

print(auth.region, auth.account_id)
```

## Compliance Profiles

Compliance requirements are plain dicts — pass them as `**kwargs` to any `create_*` function. Mix and match or compose them:


```
#| eval: false
from awseasy import HIPAA, ISO27001, SOC2

print(HIPAA)
# {'encryption': True, 'tls_min': '1.2', 'audit': True, 'multi_az': True,
#  'backup_retention': 35, 'deletion_protection': True, 'tags': {'compliance': 'hipaa'}}

# Apply a compliance profile to any resource
bucket = create_bucket(auth, 'phi-data-bucket', **HIPAA)
db     = create_postgres(auth, 'prod-db', **HIPAA)
cache  = create_redis(auth, 'prod-cache', **ISO27001)
```

## One-call GenAI Stack

`GenAIStack` provisions a complete enterprise GenAI infrastructure in one call:
IAM role → Secrets Manager → S3 → OpenSearch → Bedrock Knowledge Base → DynamoDB → ElastiCache Redis.


```
#| eval: false
auth  = AWSAuth(region='us-east-1')
stack = GenAIStack(auth, 'myapp', compliance=HIPAA)
stack.provision()         # provisions all components
print(stack.summary())    # returns resource IDs, no raw secrets
# {'role': 'arn:aws:iam::...', 'secret': 'arn:aws:secretsmanager::...',
#  's3': 'myapp-123456789-data', 'opensearch': 'myapp-search',
#  'kb': 'ABCD1234', 'dynamodb': 'myapp-table', 'redis': 'myapp-redis'}
```

## Module Reference

| Module | Azure equivalent | Key functions |
|---|---|---|
| `awseasy.core` | Core + resource groups | `AWSAuth`, `resource_group`, compliance profiles, `GenAIStack` |
| `awseasy.ai` | Azure OpenAI + AI Search | `invoke_model`, `create_kb`, `create_opensearch` |
| `awseasy.data` | Blob, Cosmos, Postgres, Redis | `create_bucket`, `create_table`, `create_postgres`, `create_redis` |
| `awseasy.compute` | VM, AKS, ACR | `create_instance`, `create_eks`, `create_ecr` |
| `awseasy.network` | VNet, Key Vault, Identity, PE, CDN | `create_vpc`, `create_secret`, `create_role`, `create_distribution` |

## AI: Amazon Bedrock + OpenSearch

Bedrock is serverless — foundation models require no provisioning. Invoke any model with a single call, or build a full RAG pipeline with a Bedrock Knowledge Base.


```
#| eval: false
from awseasy.ai import invoke_model, list_bedrock_models, create_opensearch

# Invoke Claude 3.5 Sonnet
answer = invoke_model(auth, prompt='What is RAG?')
print(answer)

# List available foundation models
models = list_bedrock_models(auth)
for m in models[:5]:
    print(m['modelId'])

# Create OpenSearch domain for vector search
domain = create_opensearch(auth, 'my-vectors', **ISO27001)
print(opensearch_endpoint(auth, 'my-vectors'))
```


```
#| eval: false
from awseasy.ai import create_kb, kb_data_source
from awseasy.network import create_role, attach_policy

# Create IAM role for Bedrock KB
role = create_role(auth, 'kb-role', service='bedrock.amazonaws.com')
attach_policy(auth, 'kb-role', 'arn:aws:iam::aws:policy/AmazonBedrockFullAccess')

# Create S3 bucket as the data source
create_bucket(auth, 'my-docs-bucket')

# Create Bedrock Knowledge Base (RAG pipeline: S3 → OpenSearch → Bedrock)
kb = create_kb(auth, 'my-kb', bucket='my-docs-bucket',
               role_arn=role['Role']['Arn'])
print(kb['knowledgeBaseId'])
```

## Data: S3, DynamoDB, RDS, ElastiCache


```
#| eval: false
from awseasy.data import create_bucket, presigned_url, create_table, create_postgres, create_redis

# S3 — public access blocked, SSE-S3, versioning on by default
create_bucket(auth, 'my-docs', **HIPAA)
url = presigned_url(auth, 'my-docs', 'report.pdf', hours=2)

# DynamoDB — PAY_PER_REQUEST, PITR enabled
create_table(auth, 'sessions', partition_key='user_id', sort_key='ts', **ISO27001)

# RDS PostgreSQL — encryption at rest, configurable Multi-AZ
create_postgres(auth, 'app-db', multi_az=True, **HIPAA)
print(postgres_conn(auth, 'app-db'))   # postgresql://pgadmin@host:5432/postgres

# ElastiCache Redis — TLS + at-rest encryption enforced
create_redis(auth, 'llm-cache', **SOC2)
print(redis_conn(auth, 'llm-cache'))   # rediss://host:6379
```

## Compute: EC2, EKS, ECR


```
#| eval: false
from awseasy.compute import create_instance, instance_ip, create_eks, eks_kubeconfig, create_ecr

# EC2 — IMDSv2 enforced, latest Ubuntu 22.04 LTS AMI auto-selected
inst = create_instance(auth, 'my-vm', instance_type='t3.medium')
print(instance_ip(auth, inst['InstanceId']))

# EKS — cluster + managed node group, IAM roles created automatically
cluster = create_eks(auth, 'my-cluster', node_type='m5.large', node_count=3)
print(eks_kubeconfig(auth, 'my-cluster'))   # kubeconfig YAML

# ECR — scan-on-push, AES256 encryption
create_ecr(auth, 'my-app')
print(ecr_login_url(auth, 'my-app'))   # 123456789.dkr.ecr.us-east-1.amazonaws.com/my-app
attach_ecr_to_eks(auth, 'my-app', 'my-cluster')   # grant pull access
```

## Network: VPC, Secrets Manager, IAM, VPC Endpoints, CloudFront, ALB


```
#| eval: false
from awseasy.network import (
    create_vpc, add_subnet, create_security_group, sg_rule,
    create_secret, get_secret,
    create_role, attach_policy, role_arn,
    create_vpc_endpoint, create_distribution, create_alb,
)

# VPC with subnets
vpc    = create_vpc(auth, 'prod-vpc')
subnet = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', az='us-east-1a', public=True)
sg     = create_security_group(auth, 'web-sg', vpc['VpcId'])
sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 443)

# Secrets Manager (Key Vault equivalent)
create_secret(auth, 'prod/openai-key', 'sk-...')
key = get_secret(auth, 'prod/openai-key')

# IAM role (Managed Identity equivalent)
r = create_role(auth, 'my-app-role', service='ec2.amazonaws.com')
attach_policy(auth, 'my-app-role', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
print(role_arn(auth, 'my-app-role'))

# Private VPC endpoint — keeps S3 traffic off public internet
create_vpc_endpoint(auth, vpc['VpcId'],
                    f'com.amazonaws.{auth.region}.s3',
                    endpoint_type='Gateway')

# CloudFront distribution with WAF
dist = create_distribution(auth, 'my-cdn', origin_domain='api.example.com')

# ALB (regional load balancer)
alb = create_alb(auth, 'my-alb', vpc['VpcId'], [subnet['SubnetId']])
```

## Resource Groups

AWS Resource Groups provide tag-based logical grouping — the closest equivalent to Azure Resource Groups.


```
#| eval: false
from awseasy.core import resource_group, list_resource_groups, delete_resource_group

# Create a resource group that captures all HIPAA-tagged resources
rg = resource_group(auth, 'prod-hipaa', tags={'compliance': 'hipaa'})

# List all resource groups
for g in list_resource_groups(auth):
    print(g['GroupName'])

# Delete a resource group (resources themselves are NOT deleted)
delete_resource_group(auth, 'prod-hipaa')
```

## Security Defaults

Every `create_*` function applies secure defaults without any extra configuration:

| Control | How applied |
|---|---|
| Encryption at rest | S3 (SSE-S3), DynamoDB, RDS, ElastiCache, ECR — all on by default |
| Encryption in transit | ElastiCache Redis (`TransitEncryptionEnabled=True`), OpenSearch TLS 1.2, ALB/CloudFront HTTPS-only |
| No public S3 access | `BlockPublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` all enabled |
| IMDSv2 on EC2 | `HttpTokens=required` — prevents SSRF-based metadata theft |
| IAM roles over keys | `create_role()` + `attach_policy()`; long-lived keys never created |
| Secret management | `create_secret()` / `get_secret()` via Secrets Manager — never hardcode |
| Idempotency | All `create_*` safe to run multiple times — create-or-update semantics |
| PITR | DynamoDB point-in-time recovery enabled by default |
| Scan on push | ECR image vulnerability scanning enabled by default |
