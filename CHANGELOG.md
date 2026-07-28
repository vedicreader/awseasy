# Release notes

<!-- do not remove -->

## 0.2.0

Closes the two gaps `0.1.0` documented as known: no teardown and no waiting.

### New module: `ledger`

Provisioning without an IaC engine normally means you cannot say what you created, so you cannot
tear it down or tell when it drifted. The answer here is to use AWS as the state store rather than
a file: every resource carries an `awseasy:stack` tag, and the Resource Groups Tagging API indexes
tags across every service in the account.

- `Ledger(auth, stack)` — `resources()`, `arns()`, `by_service()`, and `repr` for a quick read of
  what a stack consists of. `GenAIStack` exposes its own as `stack.ledger`.
- `audit()` re-reads live configuration and reports security findings, so it catches settings
  changed in the console after provisioning. Checks are limited to controls that are wrong under
  any policy — publicly reachable, unencrypted, no backups, mutable image tags. Choices that
  belong to a compliance profile are deliberately not reported, because an audit that flags things
  which are fine trains people to ignore it. Unknown resource types report as
  `<service>:unchecked`, never as passing.
- `destroy()` deletes dependents before dependencies, defaults to `dry_run=True`, and lists
  anything it has no deleter for under `unsupported` rather than skipping it. A teardown that
  quietly leaves resources behind is worse than one that refuses. One failed delete does not stop
  the rest. KMS keys are scheduled for deletion rather than deleted, and S3 buckets are emptied of
  every version and delete marker first.
- `adopt()` / `release()` bring resources created by the console, Terraform, or another script
  into the same inventory — so the audit and the teardown cover them too. This is something a
  state file cannot do.
- `@auditor` and `@deleter` register checks and deleters for further resource types.

### `wait=` on every slow creator

`create_postgres`, `create_redis`, `create_instance`, `create_eks`, `create_opensearch`,
`create_distribution`, `request_cert`, `build_image_in_codebuild`, and `GenAIStack.provision` now
take `wait=`. `build_image_in_codebuild(wait=True)` raises on a failed build rather than returning
a record that looks like success.

Two building blocks in `core`: `wait_for` wraps a boto3 waiter with a ceiling generous enough for
EKS and RDS (the `db_instance_available` default gives up too early), and `poll_until` covers
OpenSearch, CodeBuild, and Cognito, which have no waiter at all.

### Changed

- `GenAIStack.provision` tags every resource it creates into the stack ledger.
- `create_redis` no longer writes its AUTH token to Secrets Manager when the replication group
  already existed — the token it would have stored was never given to ElastiCache.

## 0.1.0

First release-shaped version. `awseasy` is now an enterprise GenAI provisioning library rather
than a boto3 sketch: enterprise SSO and CloudFront are first-class, the security defaults are
enforced and tested, and every notebook runs as a test suite against `moto`.

### New modules

- **`auth`** — Cognito user pools with enterprise defaults (no self-signup, MFA, threat
  protection, deletion protection); SAML and OIDC federation with named helpers for Microsoft
  Entra ID, Okta, and Google Workspace; app clients restricted to the authorization-code flow;
  resource servers for machine-to-machine scopes; JWT verification against the pool JWKS; and
  `protect_listener` / `alb_cognito_rule` / `alb_oidc_rule` to enforce SSO at the load balancer
  with no application code.
- **`cdn`** — CloudFront with origin access control, ACM certificates pinned to us-east-1, custom
  domains, security-headers policies, access logging, AWS WAF managed rule groups with per-IP rate
  limiting, Route 53 aliases, and invalidation. Replaces reaching for a third-party CDN.
- **`images`** — ECR login over stdin, local builds through `dockeasy`, and an AWS-native
  CodeBuild path that needs no Docker daemon anywhere.

### Fixed

- `create_kb` pointed at an OpenSearch Serverless collection ARN built by string convention from
  a *managed domain* name — two different services. Knowledge bases could never have worked.
  `create_aoss_collection` now creates a real collection with its encryption, network, and data
  access policies, and `create_kb` takes the collection ARN as a required argument.
- `create_postgres` generated a random master password and discarded it, leaving an unreachable
  database. It now uses `ManageMasterUserPassword`, so RDS generates, stores, and rotates the
  credential and no password ever exists in the Python process.
- `opensearch_admin_creds` read a Secrets Manager entry nothing ever wrote. `create_opensearch`
  now enables fine-grained access control and stores the generated master user credentials.
- `create_vpc`, `add_subnet`, `create_security_group`, `create_alb`, and `target_group` created
  duplicate resources on every run despite the documented idempotency. All are now keyed on name
  or CIDR.
- `create_bucket` caught only `BucketAlreadyOwnedByYou`, so re-running against a bucket in
  another region raised.
- `delete_resource_group` and `resource_group` used parameters the API does not accept.

### Security

- `sg_rule` no longer defaults to `0.0.0.0/0`; exactly one of `cidr=` or `source_sg=` is required.
- S3 buckets get a bucket policy denying non-TLS and sub-TLS-1.2 requests, plus SSE-KMS with a
  bucket key when a customer-managed key is supplied.
- EC2 root volumes are encrypted and `InstanceMetadataTags` is enabled alongside IMDSv2.
- EKS clusters support KMS envelope encryption of Kubernetes secrets, control-plane audit logging,
  and a private API endpoint (which every built-in profile now selects).
- ECR repositories default to immutable tags with an untagged-image lifecycle policy.
- ALBs drop invalid header fields, use the strictest desync mitigation, and can write access logs;
  `https_listener` refuses to bind without an ACM certificate.
- New `create_guardrail` applies Bedrock content filters, PII redaction, denied topics, and
  prompt-injection defence — enforced server-side rather than by prompt.
- New `bedrock_policy` and `ecr_push_policy` replace `AmazonBedrockFullAccess`-style grants with
  policies naming exact resources.
- Service-principal trust policies carry an `aws:SourceAccount` condition against confused-deputy
  attacks.
- VPC flow logs, with a retention policy and delivery role, when `audit=True`.
- New `create_kms_key` provides customer-managed keys with annual rotation; `HIPAA` and `ISO27001`
  now set `cmk=True` and route every encrypted resource through one.

### Changed

- `invoke_model` is now `converse`, implemented over the Bedrock Converse API so the same call
  works for every model family. It accepts `system=`, `temperature=`, and `guardrail=`.
- `Compliance` validates its keys on construction — a misspelled control raises instead of
  silently doing nothing. Profiles support `|` to layer overrides.
- `AWSAuth` no longer calls STS on construction; identity is lazy and cached, clients are cached
  per `(service, region)`, and `partition` / `arn_for` make ARNs GovCloud- and China-safe.
- `create_eks` takes `subnet_ids` positionally — a cluster without subnets was never valid.
- `attach_ecr_to_eks` removed: it re-attached a policy `create_eks` already attaches.
- `bucket_conn` and `dynamo_conn` removed: both returned their own argument.
- Package config moved from `settings.ini` to `pyproject.toml`, matching the sibling repos.

### Tests and docs

- Every notebook is an executable test suite: `moto` for the services it mocks, `botocore`'s
  `Stubber` for Bedrock inference, Guardrails, OpenSearch Serverless, and CloudFront response
  headers policies. `nbdev-test` runs the lot with no credentials and no network.
- Integration cells marked `#| eval: False` cover the paths that need a real account.
- `SKILL.md` documents the API for coding agents; `mv_skill_md()` installs it.
