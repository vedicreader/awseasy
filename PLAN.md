# awseasy — design notes

Why the library is shaped the way it is. For the API itself see [`README.md`](README.md), the
[docs site](https://vedicreader.github.io/awseasy/), or [`awseasy/SKILL.md`](awseasy/SKILL.md).

## Position

`awseasy` is the AWS member of the `vedicreader` toolchain — `dockeasy` (containers), `cfeasy`
(Cloudflare), `vpseasy` (Hetzner VPS). All of them are thin, Pythonic wrappers over a provider
SDK, built with nbdev and fastcore, functional where stateless and class-based only where a
connection is reused.

## Decisions

### A library, not an IaC runtime

CDK, Pulumi, and Terraform all bring a CLI, a state backend, and a language of their own. That is
the right trade for a platform team managing an estate; it is the wrong trade for an application
team that wants to create a bucket and a Bedrock guardrail from the same Python file that runs the
app. `awseasy` is importable, so it composes with whatever else you use — including being called
*from inside* a CDK or Terraform provider.

The cost of dropping a state file is that idempotency has to be earned per function. Every
`create_*` is create-or-update: it looks the resource up first, or catches the already-exists
error, and re-applies its settings either way. That makes `provision()` a reconciler rather than a
one-shot, and makes "run the script again" a safe instruction.

The consequence to know about is that re-running is **declarative, not additive**: calling
`create_alb(auth, name, subnets)` without a compliance profile after calling it with `**HIPAA`
relaxes the attributes the profile had set. That is the correct reading of a declarative call, and
the tests assert it explicitly so it cannot drift into a surprise.

### Compliance as validated dicts

A profile is a `Compliance` dict splatted into any call. The alternative designs were a class
hierarchy (too rigid — controls are not a taxonomy) and free-form kwargs (too loose). The dict
keeps the call site readable and lets one profile drive a whole stack.

The one hard rule is that unknown keys raise. In a security library, `Compliance(encryptoin=True)`
silently doing nothing is a vulnerability with a friendly face.

The known wart: profiles carry `tags`, so passing both `tags=` and `**HIPAA` is a duplicate-keyword
`TypeError`. That is explicit and loud, which is the right failure mode, but it is worth knowing.

### Security defaults over security options

Anything that is free to enable and expensive to retrofit is on by default rather than available
behind a flag:

- Encryption at rest cannot be added to an EBS volume, an EKS secrets store, or an RDS instance
  after creation — the resource has to be rebuilt. So creation is the only cheap moment.
- Public access blocks and TLS-only bucket policies are re-applied on every call, including
  against an existing bucket, which is how drift gets corrected rather than merely detected.
- `sg_rule` has no `0.0.0.0/0` default. A wrong default in that function is a public database, so
  it requires exactly one of `cidr=` or `source_sg=` and raises otherwise.
- `create_app_client` refuses the OAuth implicit flow and plaintext callbacks outright rather than
  documenting them as unwise.

Where a default would break first use — a private EKS API endpoint is unreachable without a
bastion — the default matches AWS, and every built-in compliance profile flips it.

### Secrets never round-trip through Python

`create_postgres` uses `ManageMasterUserPassword`, so RDS generates, stores, and rotates the
credential and it never exists in the process. Where a password genuinely has to be generated —
the ElastiCache AUTH token, the OpenSearch master user — it goes straight to Secrets Manager and
the create response is returned without it. `GenAIStack.summary()` returns identifiers only.

No IAM users and no access keys are created anywhere. Roles only.

### Enterprise SSO is a module, not an example

"Security is important, OAuth with enterprise login is important" is the requirement this library
exists to serve, so `auth` is a first-class module rather than a snippet in the README. It covers
the whole path: user pool, IdP federation, app client, token verification, and load-balancer
enforcement. `protect_listener` is the part most worth knowing about — it puts every request behind
the corporate IdP with no application code, no session store, and no secret handling in the app.

### CloudFront rather than a third-party CDN

`cfeasy` fronts services with Cloudflare. For an enterprise AWS stack, keeping the edge inside AWS
means one IAM boundary, one audit trail, WAF rules that can reference the same resources, and no
extra vendor in the compliance scope. `cdn` covers what fronting the stack actually needs: origin
access control so the bucket never goes public, ACM certificates pinned to us-east-1 (a rule AWS
enforces late and confusingly), managed WAF rule groups, and Route 53 aliases.

Rate limiting is in the default WAF rule set because for a GenAI application unmetered inference
is a financial risk, not only an availability one.

### Two paths for container images

`images` supports both, because teams are split. `dockeasy` generates the Dockerfile and builds it
locally when a daemon is available; CodeBuild does the same work inside AWS when there is not, which
is usually the better answer in an enterprise — the build runs on an AWS-managed image, under a role
scoped to one ECR repository, with a CloudWatch log of every build.

## Testing

Notebooks are the source of truth and every one of them is an executable test suite.

`moto` mocks most of what is used here, and its coverage is the reason the test cells look the way
they do. Where it has gaps — Bedrock inference, Guardrails, OpenSearch Serverless collections,
CloudFront response headers policies — the tests use `botocore`'s `Stubber`, which asserts the
exact request parameters being sent. For a library whose entire value is sending hardened
parameters, that is arguably the stronger assertion of the two.

Pure functions that build a policy or a config document — `distribution_config`, `waf_rules`,
`bedrock_policy`, `tls_only_policy`, `_aoss_policies`, `ecr_push_policy` — are separated from the
API calls that send them, so the security-relevant content can be asserted directly rather than
inferred from a mock's response.

Cells marked `#| eval: False` are integration tests against a real account.

## Authoring

Hand-editing `.ipynb` JSON is unpleasant, so notebooks are authored as plain Python under `nbsrc/`
with `# %%` cell markers and compiled by `tools/nbbuild.py`. Cell ids are content-hashed, so an
unchanged cell keeps its id and the generated `# %% ../nbs/...` comments stay stable across builds.

```sh
python tools/nbbuild.py     # nbsrc/*.py  -> nbs/*.ipynb
nbdev-export                # nbs/*.ipynb -> awseasy/*.py
nbdev-test                  # run every notebook
```

## Known gaps

- **No dependency graph.** `Ledger.destroy()` orders deletions by a hand-written service ranking,
  not by actual references between resources. It is right for the shapes this library builds and
  wrong for anything unusual, which is the honest cost of not having an engine.
- **No preview diff.** `destroy(dry_run=True)` shows what would be deleted, but there is no
  equivalent for changes — nothing tells you what `provision()` is about to alter.
- **The ledger is only as good as the tagging API.** It is eventually consistent, and it does not
  index every service — IAM roles and CloudFront distributions are notable absences, so they will
  not appear in an inventory and cannot be torn down by it.
- **No cross-region orchestration.** `GenAIStack` provisions into one region, with the specific
  exceptions AWS forces (ACM and WAF for CloudFront in us-east-1).
- **`create_kb` does not create the vector index.** Bedrock requires the OpenSearch index to exist
  with the right field mappings before the knowledge base will ingest; that needs a signed request
  to the collection endpoint, which is outside what boto3 offers.
- **Bedrock model ids move.** `DEFAULT_MODEL` is a starting point; availability is per-region and
  newer models need a cross-region inference profile. Use `list_bedrock_models()` and
  `inference_profile()` rather than trusting the constant.
