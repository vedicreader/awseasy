# awseasy

`awseasy` provisions AWS resources for enterprise GenAI applications from Python — a thin layer
over boto3, not an IaC runtime. Every `create_*` is idempotent (create-or-update), so provisioning
code can be re-run as a reconciler.

```python
from awseasy import *

auth = AWSAuth()                                          # standard AWS credential chain
auth = AWSAuth(region='eu-west-1', profile='prod')
auth = AWSAuth(role_arn='arn:aws:iam::222:role/deploy')   # cross-account
```

`AWSAuth` makes no network calls on construction. `auth.client(svc, region=None)` returns a cached
client; `auth.account_id`, `auth.arn`, `auth.partition` come from one cached `GetCallerIdentity`.
`auth.arn_for(svc, resource, region=None, account=True)` builds partition-aware ARNs (pass
`region=''` for global services).

## Compliance profiles

Plain dicts. Splat into any `create_*` call; each function applies the controls it can enforce.
Unknown keys raise.

```python
create_bucket(auth, 'phi-docs', **HIPAA)
create_postgres(auth, 'app-db', **HIPAA)
strict = SOC2 | dict(backup_retention=30)     # `|` layers an override, returns a Compliance
```

Keys: `encryption`, `cmk`, `tls_min`, `audit`, `multi_az`, `backup_retention`,
`deletion_protection`, `mfa_required`, `least_privilege`, `public_access`, `tags`.
Profiles: `HIPAA`, `ISO27001`, `SOC2` (also `PROFILES` by lowercase name).

**Gotcha:** profiles carry `tags`, so `create_bucket(auth, 'b', tags={...}, **HIPAA)` is a
duplicate-keyword `TypeError`. Pass one or the other.

## Whole stack

```python
stack = GenAIStack(auth, 'acme-copilot', compliance=HIPAA)
stack.provision(s3=True, knowledge_base=True, guardrail=True, dynamodb=True,
                redis=False, sso=True, cdn=True,
                callback_urls=[...], domains=['copilot.acme.com'])
stack.summary()      # {resource: identifier}, never a secret value
```

## core

```python
tag_list(d, key='Key', value='Value')  # dict -> AWS tag list (KMS: 'TagKey'/'TagValue'; AOSS: 'key'/'value')
tag_dict(items)                        # inverse
named(name, tags)                      # {'Name': name, **tags}
create_kms_key(auth, alias, rotation=True, tags=None)   # idempotent by alias, annual rotation
kms_key_arn(auth, alias)
resource_group(auth, name, tags=None); list_resource_groups(auth); delete_resource_group(auth, name)
aws_policy(auth, 'AmazonEKSClusterPolicy')              # partition-aware managed-policy ARN
mv_skill_md(dry_run=True)                               # install this file for coding agents
```

## network — IAM, secrets, VPC, ALB

```python
create_role(auth, name, service='bedrock.amazonaws.com', source_account=auth.account_id)
put_role_policy(auth, role, policy_name, document)      # inline least-privilege
attach_policy(auth, role, aws_policy(auth, 'AmazonEKSClusterPolicy'))
role_arn(auth, role); create_instance_profile(auth, name, role_name)

create_secret(auth, name, value, kms_key_id=None)       # dict values are JSON-encoded
get_secret(auth, name)                                  # str, or dict if the value is JSON
update_secret / secret_arn / delete_secret(auth, name, force=False)

create_vpc(auth, name, cidr='10.0.0.0/16', audit=False) # audit=True -> flow logs + retention
add_subnet(auth, vpc_id, cidr, az, public=False)
create_security_group(auth, name, vpc_id)
sg_rule(auth, sg_id, 'ingress', 'tcp', 443, cidr=...)   # or source_sg=...; exactly one, no default
create_vpc_endpoint(auth, vpc_id, 'bedrock-runtime', subnet_ids=..., sg_ids=...)
private_endpoints(auth, vpc_id, subnet_ids, sg_ids)     # the full private-stack set

create_alb(auth, name, subnet_ids, sg_ids, log_bucket=..., **HIPAA)
target_group(auth, name, vpc_id, port=8000)
https_listener(auth, alb_arn, tg_arn, cert_arn)         # raises without a cert
redirect_http(auth, alb_arn)                            # 80 -> 443, HTTP 301
```

`sg_rule` requires exactly one of `cidr=` / `source_sg=` — there is deliberately no `0.0.0.0/0`
default. `port` may be an int or an inclusive `(lo, hi)` tuple.

## data — S3, DynamoDB, RDS, Redis

```python
create_bucket(auth, name, versioning=True, kms_key_id=None, tls_min='1.2', log_bucket=None)
bucket_url(name, key); presigned_url(auth, name, key, hours=1)

create_table(auth, name, partition_key, sort_key=None, kms_key_id=None, ttl_attr='expires_at')
table_resource(auth, name)                              # boto3 Table for get/put/query

create_postgres(auth, name, kms_key_id=..., subnet_group=..., sg_ids=..., **HIPAA)
postgres_conn(auth, name)                               # URL with no password in it
postgres_password(auth, name)                           # from the RDS-managed secret
postgres_iam_token(auth, name, user)                    # 15-minute IAM token, no stored credential

create_redis(auth, name, multi_az=False, kms_key_id=..., **ISO27001)
redis_conn(auth, name)                                  # rediss:// only
redis_auth_token(auth, name)                            # from Secrets Manager
```

`create_bucket` re-applies every control on an existing bucket, which is how drift is corrected.
`create_postgres` uses `ManageMasterUserPassword` — no password is ever generated in Python.

## ai — Bedrock and vector stores

```python
converse(auth, prompt, model_id=DEFAULT_MODEL, system=None, max_tokens=1024,
         temperature=None, guardrail=('gr-id', '1'))    # Converse API: model-agnostic
inference_profile(model_id, prefix='us')                # 'us.anthropic....' for newer models
list_bedrock_models(auth, provider=None)

create_guardrail(auth, name, strength='HIGH', pii=None, denied_topics=[...], blocked_words=[...])
guardrail_ref(g)                                        # -> (id, version) for converse()
bedrock_policy(auth, models=None, bucket=None, kms_key_arn=None, collection_arn=None)

create_aoss_collection(auth, name, role_arns=[...], kms_key_arn=None, public=False)
create_kb(auth, name, bucket, role_arn, collection_arn) # collection_arn is required, not inferred
kb_data_source(auth, kb_id, bucket, prefix='')
sync_kb(auth, kb_id, data_source_id)                    # ingestion is not automatic

create_opensearch(auth, name, kms_key_id=..., subnet_ids=..., audit=False)
opensearch_admin_creds(auth, name)                      # master user, from Secrets Manager
```

A guardrail only takes effect when passed to `converse(guardrail=...)`.

## auth — Cognito enterprise SSO

```python
pool = create_user_pool(auth, name, mfa_required=True, self_signup=False, threat_protection=True)
create_pool_domain(auth, pool['Id'], f'acme-{auth.account_id}', cert_arn=None)

add_entra_idp(auth, pid, tenant_id, client_id, client_secret)
add_okta_idp(auth, pid, 'acme.okta.com', client_id, client_secret)
add_google_idp(auth, pid, client_id, client_secret)
add_saml_idp(auth, pid, 'CorpADFS', metadata_url=..., attr_map={**SAML_ATTRS, 'custom:groups': ...})
add_oidc_idp(auth, pid, name, client_id, client_secret, issuer)
list_idps(auth, pid)

create_app_client(auth, pid, name, callback_urls=[...], logout_urls=[...], idps=None)
app_client_secret(auth, pid, client_id)
create_resource_server(auth, pid, 'https://api.acme.com', {'read': 'Read data'})

login_url / logout_url / token_url / domain_url(auth, domain, ...)
issuer_url(auth, pid); jwks_url(auth, pid); user_pool_arn(auth, pid); user_pool_id(auth, name)

verify_jwt(auth, pid, token, client_id=..., use='id', jwks=None)   # signature + iss + aud + exp
token_groups(claims)                                    # custom:groups, else cognito:groups

protect_listener(auth, listener_arn, tg_arn, pool_arn, client_id, domain)   # all requests
alb_cognito_rule(auth, listener_arn, tg_arn, pool_arn, client_id, domain, paths=['/app/*'])
alb_oidc_rule(auth, listener_arn, tg_arn, issuer, client_id, client_secret, endpoints)
```

`create_app_client` raises on the implicit flow and on non-HTTPS callbacks (localhost excepted),
and enables no password-based auth flow. `verify_jwt` rejects a wrong `token_use`: an access token
is not an identity.

## cdn — CloudFront, WAF, ACM, Route 53

```python
request_cert(auth, domain, alt_names=None, region='us-east-1')     # CloudFront requires us-east-1
cert_validation_records(auth, cert_arn); cert_status(auth, cert_arn)

create_waf(auth, name, scope='CLOUDFRONT', managed_rules=None, rate_limit=2000)
create_oac(auth, name); s3_oac_policy(auth, bucket, distribution_arn)   # merges, keeps TLS policy
security_headers_policy(auth, name, csp=None)

create_distribution(auth, name, s3_bucket=... | origin_domain=..., domains=[...], cert_arn=...,
                    waf_acl_arn=..., log_bucket=..., methods='read'|'all')
distribution_config(auth, ...)                          # pure; assert on it in tests
distribution_domain(auth, dist_id); invalidate(auth, dist_id, ['/*'])
zone_id(auth, 'acme.com'); alias_record(auth, zid, 'app.acme.com', dist['DomainName'])
```

`domains=` requires `cert_arn=`. `methods='all'` for APIs; the `'read'` default suits static sites.

## compute — EC2, EKS, ECR

```python
create_instance(auth, name, instance_type='t3.medium', ami=None, subnet_id=..., sg_ids=[...],
                iam_instance_profile=..., kms_key_id=..., volume_size=30)
latest_ubuntu_ami(auth, ver='22.04'); instance_ip / start_instance / stop_instance / terminate_instance

create_eks(auth, name, subnet_ids, node_type='m5.large', node_count=2, kms_key_id=...,
           public_access=True, **ISO27001)              # profiles set public_access=False
scale_eks(auth, name, node_count); eks_kubeconfig(auth, name)

create_ecr(auth, name, immutable=True, kms_key_id=..., max_untagged=10)
ecr_lifecycle(auth, name); ecr_uri(auth, name, tag=None); image_tags(auth, name)
```

EKS secrets encryption (`kms_key_id`) can only be set at cluster creation — never retrofitted.

## images — container builds

```python
ecr_credentials(auth); ecr_login(auth)                  # token piped over stdin
build_push(auth, repo, path='.', tag=None, dockerfile=None)    # local Docker + dockeasy
default_tag(); image_digest(auth, repo, tag); scan_findings(auth, repo, tag)

upload_source(auth, bucket, key, path='.')
create_image_project(auth, name, repo, source_bucket=..., source_key=... | github_url=...)
build_image_in_codebuild(auth, project, tag=None); build_status(auth, build_id)
buildspec(auth, repo); ecr_push_policy(auth, repo)
```

CodeBuild needs no local Docker. Repositories default to immutable tags, so pushing `latest`
twice fails — `default_tag()` returns a sortable UTC timestamp instead.

## Conventions

- Idempotent: re-running a `create_*` reconciles rather than duplicating.
- Declarative: dropping a compliance profile on a re-run relaxes the settings it had applied.
- Secrets go to Secrets Manager and are never returned in a resource dict.
- Roles only — no IAM users, no long-lived access keys.
- Regional pinning is automatic where AWS demands it (ACM/WAF/CloudFront in us-east-1).
