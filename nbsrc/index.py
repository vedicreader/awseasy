# %% hide
from awseasy.core import *
from awseasy.network import *
from awseasy.data import *
from awseasy.ai import *
from awseasy.compute import *
from awseasy.auth import *
from awseasy.cdn import *
from awseasy.images import *

# %% md
# # awseasy
#
# > AWS provisioning for enterprise GenAI stacks — Bedrock, Cognito SSO, CloudFront, and compliance by default.

# %% md
# `awseasy` provisions the AWS resources an enterprise GenAI application actually needs, from
# Python, with the security controls already switched on. It is a thin, Pythonic layer over
# `boto3` — not an IaC runtime, so there is no CLI to install, no state file to manage, and no
# DSL to learn. Every function is an ordinary Python function you can call from a notebook, a
# script, a FastAPI app, or from inside CDK or Terraform.
#
# It is the AWS member of the same family as
# [`vpseasy`](https://github.com/vedicreader/vpseasy) (Hetzner VPS),
# [`dockeasy`](https://github.com/vedicreader/dockeasy) (containers), and
# [`cfeasy`](https://github.com/vedicreader/cfeasy) (Cloudflare) — same shape, same conventions.
#
# ## What makes it different
#
# **Security defaults you would otherwise have to remember.** Buckets block all four kinds of
# public access and deny non-TLS requests. EC2 instances require IMDSv2 and encrypt their root
# volume. EKS encrypts Kubernetes secrets with your own KMS key. RDS never returns a master
# password, because it never generates one in Python. `sg_rule` has no `0.0.0.0/0` default and
# refuses to guess.
#
# **Enterprise sign-in is a first-class module.** Cognito user pools federated to Entra ID, Okta,
# Google Workspace, or any SAML 2.0 IdP; app clients locked to the authorization-code flow; JWT
# verification; and load-balancer-enforced SSO that needs no application code at all.
#
# **Compliance profiles that actually reach the resources.** `HIPAA`, `ISO27001`, and `SOC2` are
# plain dicts you splat into any call. Unknown keys raise — a typo in a security library should
# not be a silent no-op.
#
# **Idempotent everywhere.** Every `create_*` is create-or-update, so provisioning code doubles
# as a reconciler you can re-run after changing a profile.

# %% md
# ## Install
#
# ```sh
# pip install awseasy
# ```
#
# Credentials come from the standard AWS chain — environment variables, `~/.aws/credentials`,
# an EC2/ECS instance profile, EKS pod identity, or IAM Identity Center SSO. Nothing is ever
# hardcoded.
#
# ```python
# from awseasy import *
#
# auth = AWSAuth()                                   # region from AWS_DEFAULT_REGION
# auth = AWSAuth(region='eu-west-1', profile='prod')  # or be explicit
# auth = AWSAuth(role_arn='arn:aws:iam::222:role/deploy')   # or cross-account
# ```

# %% md
# ## The whole stack in one call
#
# ```python
# stack = GenAIStack(auth, 'acme-copilot', compliance=HIPAA)
# stack.provision(sso=True, cdn=True,
#                 domains=['copilot.acme.com'],
#                 callback_urls=['https://copilot.acme.com/oauth2/idpresponse'])
# stack.summary()
# ```
#
# That gives you a customer-managed KMS key, a least-privilege Bedrock role, an encrypted
# private document bucket, a Bedrock guardrail, an OpenSearch Serverless vector store behind a
# Knowledge Base, a session table with point-in-time recovery, a Cognito user pool with a hosted
# UI, and a CloudFront distribution behind AWS WAF.
#
# `provision()` is safe to re-run: every step reconciles rather than duplicating.

# %% md
# ## Compliance profiles
#
# A profile is a dict of controls. Splat it into any `create_*` call and the function applies the
# controls it can enforce.
#
# ```python
# create_bucket(auth, 'phi-documents', **HIPAA)     # SSE-KMS, versioned, TLS-only, private
# create_postgres(auth, 'app-db', **HIPAA)          # multi-AZ, 35-day backups, deletion protection
# create_eks(auth, 'inference', subnets, **HIPAA)   # private endpoint, secrets encryption, audit logs
# create_vpc(auth, 'app-vpc', **ISO27001)           # flow logs to CloudWatch
# ```
#
# | Control | `HIPAA` | `ISO27001` | `SOC2` |
# |---|---|---|---|
# | Encryption at rest | ✅ | ✅ | ✅ |
# | Customer-managed KMS key | ✅ | ✅ | — |
# | TLS 1.2 minimum | ✅ | ✅ | ✅ |
# | Audit logging | ✅ | ✅ | ✅ |
# | Multi-AZ | ✅ | — | — |
# | Backup retention | 35 days | 14 days | 7 days |
# | Deletion protection | ✅ | — | — |
# | MFA required | — | — | ✅ |
# | Least privilege IAM | ✅ | ✅ | ✅ |
# | No public access | ✅ | ✅ | ✅ |
#
# Layer an override with `|`, and mistype a key at your peril:
#
# ```python
# strict = SOC2 | dict(backup_retention=30, multi_az=True)
# Compliance(encryptoin=True)     # ValueError: unknown compliance keys ['encryptoin']
# ```

# %% md
# ## Enterprise sign-in
#
# Federate the identity provider the company already runs, then put the whole application behind
# it at the load balancer — no login code, no session store, no secret handling in the app.
#
# ```python
# pool = create_user_pool(auth, 'acme-users', **ISO27001)
# create_pool_domain(auth, pool['Id'], f'acme-{auth.account_id}')
#
# add_entra_idp(auth, pool['Id'], tenant_id=TENANT, client_id=APP_ID, client_secret=SECRET,
#               attr_map={**OIDC_ATTRS, 'custom:groups': 'groups'})
# # or add_okta_idp(...) / add_google_idp(...) / add_saml_idp(..., metadata_url=...)
#
# client = create_app_client(auth, pool['Id'], 'acme-web',
#                            callback_urls=['https://acme.example.com/oauth2/idpresponse'])
#
# protect_listener(auth, listener_arn, target_group_arn,
#                  user_pool_arn(auth, pool['Id']), client['ClientId'], domain)
# ```
#
# For an API that receives tokens directly:
#
# ```python
# claims = verify_jwt(auth, pool['Id'], bearer_token, client_id=client['ClientId'])
# if 'platform-admins' not in token_groups(claims): raise PermissionError
# ```
#
# The app client is restricted to the authorization-code flow, rejects plaintext callbacks, and
# enables no password-based auth flow — so the application never handles a user's password.

# %% md
# ## Bedrock, with guardrails
#
# `converse()` uses the Converse API, so the same call works for Claude, Llama, Mistral, or any
# other Bedrock model — switching model is a change of `model_id` and nothing else.
#
# ```python
# guardrail = create_guardrail(auth, 'support-bot',
#                              denied_topics=[{'name': 'LegalAdvice',
#                                              'definition': 'Advice a licensed attorney should give.'}])
#
# answer = converse(auth, 'Summarise this contract', system='Be concise.',
#                   guardrail=guardrail_ref(guardrail))
# ```
#
# The guardrail masks PII in both directions, filters prompt-injection attempts, and blocks the
# topics you name — enforced by Bedrock, not by a prompt the user can talk their way around.
#
# For RAG, `create_aoss_collection` builds the vector store (encryption, network, and data-access
# policies included) and `create_kb` wires an S3 bucket of documents to it.

# %% md
# ## The public edge
#
# ```python
# cert = request_cert(auth, 'app.acme.com')       # us-east-1, as CloudFront requires
# waf = create_waf(auth, 'acme-waf', rate_limit=1000)
# dist = create_distribution(auth, 'acme', s3_bucket='acme-site',
#                            domains=['app.acme.com'], cert_arn=cert,
#                            waf_acl_arn=waf['ARN'], log_bucket='acme-logs')
# alias_record(auth, zone_id(auth, 'acme.com'), 'app.acme.com', dist['DomainName'])
# ```
#
# The bucket stays private: CloudFront reaches it through origin access control, and the bucket
# policy grants access to that one distribution only. The WAF applies AWS managed rule groups
# plus per-IP rate limiting — which for a GenAI app is a cost control as much as a security one.

# %% md
# ## Container images
#
# Build locally with [`dockeasy`](https://github.com/vedicreader/dockeasy):
#
# ```python
# create_ecr(auth, 'genai-api')                     # immutable tags, scan on push
# uri = build_push(auth, 'genai-api', path='.')     # Dockerfile inferred from the project
# ```
#
# Or build entirely inside AWS, with no Docker daemon anywhere:
#
# ```python
# upload_source(auth, 'build-source', 'api/src.zip', path='.')
# create_image_project(auth, 'genai-api-build', 'genai-api',
#                      source_bucket='build-source', source_key='api/src.zip')
# build = build_image_in_codebuild(auth, 'genai-api-build')
# ```

# %% md
# ## Modules
#
# | Module | Covers |
# |---|---|
# | [`core`](core.html) | `AWSAuth`, compliance profiles, tagging, KMS keys, resource groups, `GenAIStack` |
# | [`ai`](ai.html) | Bedrock inference and guardrails, OpenSearch Serverless, Knowledge Bases, managed domains |
# | [`data`](data.html) | S3, DynamoDB, RDS PostgreSQL, ElastiCache Redis |
# | [`compute`](compute.html) | EC2, EKS, ECR |
# | [`network`](network.html) | IAM, Secrets Manager, VPCs, security groups, flow logs, VPC endpoints, ALB |
# | [`auth`](auth.html) | Cognito user pools, SSO federation, app clients, JWT verification, ALB-enforced login |
# | [`cdn`](cdn.html) | CloudFront, AWS WAF, ACM, Route 53 |
# | [`images`](images.html) | ECR login, local builds via dockeasy, CodeBuild image pipelines |

# %% md
# ## Security posture
#
# | Control | How it is applied |
# |---|---|
# | No public S3 | All four public-access blocks on every `create_bucket`, on create *and* on re-run |
# | TLS enforced | Bucket policy denies `aws:SecureTransport=false` and TLS below 1.2 |
# | Encryption at rest | S3, DynamoDB, RDS, ElastiCache, EBS, ECR, EKS secrets, OpenSearch |
# | Customer-managed keys | `cmk=True` profiles route every resource through a rotating KMS key |
# | IMDSv2 required | `HttpTokens=required`, hop limit 1 — SSRF cannot reach instance credentials |
# | No stored DB password | RDS generates and holds the master secret; `awseasy` never sees it |
# | Least privilege | `bedrock_policy` / `ecr_push_policy` name exact resources; no `ecr:*`, no `Resource: *` |
# | No IAM users | Roles only. No long-lived access keys are ever created |
# | Confused-deputy guard | `aws:SourceAccount` on every service-principal trust policy |
# | Network audit trail | VPC flow logs to CloudWatch with a retention policy when `audit=True` |
# | Private egress | `private_endpoints()` keeps Bedrock, S3, KMS, and Secrets Manager off the internet |
# | Prompt-injection defence | Bedrock guardrails with `PROMPT_ATTACK` filtering and PII redaction |
# | Edge protection | AWS WAF managed rule groups plus per-IP rate limiting |
# | Immutable images | ECR `IMMUTABLE` tags — a reviewed digest cannot be swapped out |

# %% md
# ## Development
#
# Notebooks under `nbs/` are the source of truth; the `.py` files are generated. To keep the
# notebooks readable they are authored as plain Python under `nbsrc/` and compiled:
#
# ```sh
# python tools/nbbuild.py      # nbsrc/*.py  ->  nbs/*.ipynb
# nbdev-export                 # nbs/*.ipynb ->  awseasy/*.py
# nbdev-test                   # run every notebook as a test
# ```
#
# The test cells run against [`moto`](https://github.com/getmoto/moto), an in-process AWS mock, so
# the suite needs no credentials and makes no network calls. Where moto has gaps — Bedrock
# inference, Guardrails, OpenSearch Serverless collections — the tests use `botocore`'s `Stubber`
# to assert the exact request parameters being sent, which for a library like this is the
# assertion that matters most.
#
# Cells marked `#| eval: False` are integration tests against a real account; run them manually.
