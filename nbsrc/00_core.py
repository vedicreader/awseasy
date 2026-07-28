# %% md
# # core
# > Credentials, compliance profiles, tagging, KMS keys, resource groups, and the `GenAIStack` orchestrator.

# %% code
#| default_exp core

# %% hide
from nbdev.showdoc import *

# %% export
import json, os, time, boto3
from fastcore.all import L, Path, first

# %% hide
# Every test cell in this project runs against `moto`, an in-process AWS mock. No real
# credentials are read and no API calls leave the machine.
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws

# %% md
# ## Compliance profiles
#
# A profile is a plain dict of controls, splatted into any `create_*` call as `**HIPAA`.
# Functions read the keys they can enforce and ignore the rest, so one profile drives an
# entire stack:
#
# ```python
# create_bucket(auth, 'phi-data', **HIPAA)
# create_postgres(auth, 'app-db', **HIPAA)
# ```
#
# Keys are validated on construction. A silent typo in a security library is a hole, not a
# no-op — `Compliance(encryptoin=True)` raises rather than quietly leaving encryption off.

# %% export
COMPLIANCE_KEYS = {'encryption', 'cmk', 'tls_min', 'audit', 'multi_az', 'backup_retention',
                   'deletion_protection', 'mfa_required', 'least_privilege', 'public_access', 'tags'}

class Compliance(dict):
    'Validated bundle of security controls. Unknown keys raise rather than silently doing nothing.'
    def __init__(self, **kw):
        bad = set(kw) - COMPLIANCE_KEYS
        if bad: raise ValueError(f'unknown compliance keys {sorted(bad)}; valid keys are {sorted(COMPLIANCE_KEYS)}')
        super().__init__(**kw)
    def __or__(self, other): return Compliance(**{**self, **other})
    def __repr__(self): return f'Compliance({", ".join(f"{k}={v!r}" for k,v in self.items())})'

HIPAA = Compliance(
    encryption=True, cmk=True, tls_min='1.2', audit=True, multi_az=True,
    backup_retention=35, deletion_protection=True, public_access=False,
    least_privilege=True, tags={'compliance': 'hipaa'})

ISO27001 = Compliance(
    encryption=True, cmk=True, tls_min='1.2', audit=True, least_privilege=True,
    backup_retention=14, public_access=False, tags={'compliance': 'iso27001'})

SOC2 = Compliance(
    encryption=True, tls_min='1.2', audit=True, mfa_required=True, least_privilege=True,
    backup_retention=7, public_access=False, tags={'compliance': 'soc2'})

PROFILES = dict(hipaa=HIPAA, iso27001=ISO27001, soc2=SOC2)

# %% code
# Profiles are dicts, so `**PROFILE` splats into any create_* signature.
assert HIPAA['backup_retention'] == 35 and HIPAA['multi_az'] is True
assert SOC2['mfa_required'] is True

# A misspelled control raises instead of silently leaving the control off.
try: Compliance(encryptoin=True); raise AssertionError('should have raised')
except ValueError as e: assert 'encryptoin' in str(e)

# `|` layers an override on top of a profile without mutating it.
strict = SOC2 | dict(backup_retention=30)
assert strict['backup_retention'] == 30 and SOC2['backup_retention'] == 7
assert isinstance(strict, Compliance)
print(strict)

# %% md
# ## Authentication
#
# `AWSAuth` wraps a `boto3.Session` and resolves credentials through the standard chain —
# environment variables, `~/.aws/credentials`, `~/.aws/config`, EC2/ECS instance profiles,
# EKS pod identity (IRSA), and IAM Identity Center SSO. Nothing is ever hardcoded, and
# `role_arn=` bridges to another account via `sts:AssumeRole`.
#
# Clients are cached per `(service, region)` and `get_caller_identity` is called at most once
# per object, so constructing an `AWSAuth` makes no network calls at all.

# %% export
class AWSAuth:
    'boto3 Session over the standard AWS credential chain, with cached per-service clients.'
    def __init__(self, region=None, profile=None, role_arn=None, session_name='awseasy'):
        region = region or os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION') or 'us-east-1'
        self.session = boto3.Session(profile_name=profile, region_name=region)
        if role_arn:
            c = self.session.client('sts').assume_role(
                RoleArn=role_arn, RoleSessionName=session_name)['Credentials']
            self.session = boto3.Session(
                aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'],
                aws_session_token=c['SessionToken'], region_name=region)
        self.region, self._clients, self._ident = region, {}, None

    def client(self, svc, region=None):
        'Cached client. Pass region to override — CloudFront certs and WAF ACLs must live in us-east-1.'
        k = (svc, region or self.region)
        if k not in self._clients: self._clients[k] = self.session.client(svc, region_name=k[1])
        return self._clients[k]

    def resource(self, svc): return self.session.resource(svc, region_name=self.region)

    @property
    def identity(self) -> dict:
        'sts:GetCallerIdentity, called once and cached.'
        if self._ident is None: self._ident = self.client('sts').get_caller_identity()
        return self._ident

    @property
    def account_id(self) -> str: return self.identity['Account']

    @property
    def arn(self) -> str: return self.identity['Arn']

    @property
    def partition(self) -> str:
        'ARN partition — aws, aws-us-gov, or aws-cn. GovCloud and China build different ARNs.'
        return self.arn.split(':')[1]

    def arn_for(self, svc, resource, region=None, account=True) -> str:
        'Build an ARN in this partition/account. region="" for global services (IAM, S3).'
        return f'arn:{self.partition}:{svc}:{self.region if region is None else region}:' \
               f'{self.account_id if account else ""}:{resource}'

    def __repr__(self): return f'AWSAuth(region={self.region!r})'

def aws_policy(auth, name) -> str:
    'ARN of an AWS-managed IAM policy, e.g. "AmazonBedrockFullAccess".'
    return f'arn:{auth.partition}:iam::aws:policy/{name}'

# %% code
with mock_aws():
    auth = AWSAuth(region='eu-west-1')
    assert auth.region == 'eu-west-1' and repr(auth) == "AWSAuth(region='eu-west-1')"
    assert auth.account_id == '123456789012'
    assert auth.partition == 'aws'

    # identity is fetched once, then served from cache
    assert auth._ident is not None and auth.identity is auth.identity

    # clients are cached per (service, region) — a region override is a distinct entry
    assert auth.client('s3') is auth.client('s3')
    assert auth.client('s3', region='us-east-1') is not auth.client('s3')

    assert auth.arn_for('sqs', 'myqueue') == 'arn:aws:sqs:eu-west-1:123456789012:myqueue'
    assert auth.arn_for('s3', 'mybucket/*', region='', account=False) == 'arn:aws:s3:::mybucket/*'
    assert aws_policy(auth, 'AmazonBedrockFullAccess') == 'arn:aws:iam::aws:policy/AmazonBedrockFullAccess'
    print(auth, auth.account_id)

# %% md
# ## Tagging
#
# AWS APIs disagree about tag shape: most want `[{'Key':..,'Value':..}]`, KMS wants
# `TagKey`/`TagValue`, and OpenSearch Serverless wants lowercase `key`/`value`. These two
# helpers convert in both directions so callers only ever deal in plain dicts.

# %% export
def tag_list(tags, key='Key', value='Value') -> list:
    'dict -> AWS tag list. Pass key/value for APIs that use TagKey/TagValue or key/value.'
    return [{key: k, value: str(v)} for k, v in (tags or {}).items()]

def tag_dict(items, key='Key', value='Value') -> dict:
    'AWS tag list -> dict. Inverse of `tag_list`.'
    return {i[key]: i[value] for i in (items or [])}

def named(name, tags=None) -> dict:
    'Tag dict with a Name tag merged in; explicit tags win.'
    return {'Name': name, **(tags or {})}

# %% code
assert tag_list({'env': 'prod'}) == [{'Key': 'env', 'Value': 'prod'}]
assert tag_list({'env': 'prod'}, 'TagKey', 'TagValue') == [{'TagKey': 'env', 'TagValue': 'prod'}]
assert tag_list(None) == []                      # None is a valid empty tag set everywhere
assert tag_list({'port': 8080})[0]['Value'] == '8080'   # AWS rejects non-string tag values
assert tag_dict(tag_list({'a': 'b', 'c': 'd'})) == {'a': 'b', 'c': 'd'}
assert named('web', {'env': 'prod'}) == {'Name': 'web', 'env': 'prod'}
assert named('web', {'Name': 'override'}) == {'Name': 'override'}
print('tag helpers OK')

# %% md
# ## KMS customer-managed keys
#
# The AWS-owned keys behind `SSEAlgorithm: AES256` cannot be audited, rotated on your
# schedule, or revoked. HIPAA and ISO 27001 both set `cmk=True`, which routes every
# encrypted resource in a stack through a customer-managed key created here with annual
# rotation on.

# %% export
def create_kms_key(auth, alias, description=None, rotation=True, tags=None) -> dict:
    'Create or fetch a customer-managed KMS key by alias, with annual rotation enabled.'
    kms = auth.client('kms')
    alias = alias if alias.startswith('alias/') else f'alias/{alias}'
    try: return kms.describe_key(KeyId=alias)['KeyMetadata']
    except kms.exceptions.NotFoundException: pass
    key = kms.create_key(Description=description or alias, KeyUsage='ENCRYPT_DECRYPT',
                         Tags=tag_list(tags, 'TagKey', 'TagValue'))['KeyMetadata']
    kms.create_alias(AliasName=alias, TargetKeyId=key['KeyId'])
    if rotation: kms.enable_key_rotation(KeyId=key['KeyId'])
    return key

def kms_key_arn(auth, alias) -> str:
    'ARN of a KMS key looked up by alias.'
    alias = alias if alias.startswith('alias/') else f'alias/{alias}'
    return auth.client('kms').describe_key(KeyId=alias)['KeyMetadata']['Arn']

def _cmk(auth, name, compliance) -> str:
    'Key ARN for a stack when the profile demands a CMK, else None (falls back to AWS-owned keys).'
    return kms_key_arn(auth, f'{name}-key') if compliance.get('cmk') else None

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    k = create_kms_key(auth, 'myapp-key', tags={'env': 'prod'})
    assert k['KeyId'] and k['Enabled']
    assert auth.client('kms').get_key_rotation_status(KeyId=k['KeyId'])['KeyRotationEnabled']

    # idempotent: a second call resolves the alias instead of creating a second key
    assert create_kms_key(auth, 'myapp-key')['KeyId'] == k['KeyId']
    assert create_kms_key(auth, 'alias/myapp-key')['KeyId'] == k['KeyId']  # alias/ prefix optional
    assert kms_key_arn(auth, 'myapp-key') == k['Arn']
    assert len(auth.client('kms').list_keys()['Keys']) == 1
    print(k['Arn'])

# %% md
# ## Waiting
#
# Most `create_*` calls return as soon as AWS accepts the request. An RDS instance takes minutes
# to become available, an EKS cluster ten or more, and a CloudFront distribution can take longer
# still — so anything that depends on the resource has to wait.
#
# Every slow creator takes `wait=False`. Set it to `True` and the call blocks until the resource
# is genuinely usable. The boto3 waiter defaults are usually too short for these resources
# (`db_instance_available` gives up after 60 attempts at 30s), so `wait_for` raises the ceiling.
#
# `poll_until` covers the services with no waiter at all — OpenSearch, CodeBuild, Cognito.

# %% export
def wait_for(client, waiter, delay=15, attempts=120, **kw):
    'Block on a boto3 waiter, with a ceiling generous enough for EKS and RDS (default 30 minutes).'
    client.get_waiter(waiter).wait(WaiterConfig={'Delay': delay, 'MaxAttempts': attempts}, **kw)

def poll_until(fn, ready, delay=15, timeout=1800, desc='resource'):
    'Poll fn() until ready(result). For services boto3 gives no waiter for. Returns the last result.'
    deadline = time.monotonic() + timeout
    while True:
        r = fn()
        if ready(r): return r
        if time.monotonic() >= deadline:
            raise TimeoutError(f'{desc} was still not ready after {timeout}s')
        time.sleep(delay)

# %% code
# poll_until is a plain loop, so drive it with a counter rather than a cloud resource.
calls = []
def flaky():
    calls.append(1)
    return {'Status': 'AVAILABLE' if len(calls) >= 3 else 'CREATING'}

r = poll_until(flaky, lambda x: x['Status'] == 'AVAILABLE', delay=0)
assert r['Status'] == 'AVAILABLE' and len(calls) == 3

# a resource that never becomes ready raises rather than hanging forever
try:
    poll_until(lambda: {'Status': 'CREATING'}, lambda x: False, delay=0, timeout=0, desc='test db')
    raise AssertionError('should have timed out')
except TimeoutError as e: assert 'test db' in str(e)
print('poll_until OK')

# %% code
with mock_aws():
    # wait_for drives a real boto3 waiter; under moto the resource is immediately available.
    auth = AWSAuth(region='us-east-1')
    auth.client('rds').create_db_instance(
        DBInstanceIdentifier='waiter-db', DBInstanceClass='db.t3.micro', Engine='postgres',
        MasterUsername='pgadmin', ManageMasterUserPassword=True, AllocatedStorage=20)
    wait_for(auth.client('rds'), 'db_instance_available', delay=1, attempts=3,
             DBInstanceIdentifier='waiter-db')
    print('wait_for OK')

# %% md
# ## Resource groups
#
# AWS has no folder-like container equivalent to an Azure resource group. The closest
# primitive is a tag-based Resource Group: a saved query over every resource carrying a
# given tag. `resource_group()` is create-or-update, so re-running it is safe.

# %% export
def resource_group(auth, name, tags=None) -> dict:
    'Create or update a tag-query Resource Group. Defaults to querying tag ResourceGroup=<name>.'
    tags = tags or {'ResourceGroup': name}
    query = json.dumps({'ResourceTypeFilters': ['AWS::AllSupported'],
                        'TagFilters': [{'Key': k, 'Values': [str(v)]} for k, v in tags.items()]})
    rq = {'Type': 'TAG_FILTERS_1_0', 'Query': query}
    c = auth.client('resource-groups')
    found = first(g for g in list_resource_groups(auth) if g['GroupName'] == name)
    if found is None:
        g = c.create_group(Name=name, ResourceQuery=rq,
                           Tags={**tags, 'ResourceGroup': name})['Group']
        return {'Name': g['Name'], 'GroupArn': g['GroupArn']}
    # The saved query has its own call — update_group only edits the description.
    c.update_group_query(Group=name, ResourceQuery=rq)
    return {'Name': found['GroupName'], 'GroupArn': found['GroupArn']}

def resource_group_query(auth, name) -> dict:
    'The saved tag query behind a resource group.'
    q = auth.client('resource-groups').get_group_query(Group=name)['GroupQuery']
    return json.loads(q['ResourceQuery']['Query'])

def list_resource_groups(auth) -> list:
    'All resource groups in the account/region.'
    p = auth.client('resource-groups').get_paginator('list_groups')
    return [g for pg in p.paginate() for g in pg['GroupIdentifiers']]

def delete_resource_group(auth, name):
    'Delete a resource group. The resources it selected are left untouched.'
    auth.client('resource-groups').delete_group(Group=name)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    g = resource_group(auth, 'myapp', tags={'project': 'myapp'})
    assert g['Name'] == 'myapp' and g['GroupArn'].endswith(':group/myapp')
    keys = [f['Key'] for f in resource_group_query(auth, 'myapp')['TagFilters']]
    assert keys == ['project']

    # create-or-update: re-running rewrites the saved query rather than raising
    resource_group(auth, 'myapp', tags={'project': 'myapp', 'env': 'prod'})
    assert sorted(f['Key'] for f in resource_group_query(auth, 'myapp')['TagFilters']) == \
        ['env', 'project']
    names = L(list_resource_groups(auth)).attrgot('GroupName')
    assert names.filter(lambda n: n == 'myapp'), names
    assert len(list_resource_groups(auth)) == 1, 'update must not create a second group'

    delete_resource_group(auth, 'myapp')
    assert not list_resource_groups(auth)
    print('resource_group create/update/delete OK')

# %% md
# ## GenAIStack
#
# One call stands up the pieces an enterprise GenAI app actually needs, wired together and
# hardened by the compliance profile: a customer-managed key, a least-privilege Bedrock
# role, a private document bucket, a Bedrock guardrail, an OpenSearch Serverless vector
# store fronting a Bedrock Knowledge Base, a session table, and optionally Cognito SSO and
# a CloudFront front door.
#
# Every step is idempotent, so `provision()` doubles as a reconciler — re-run it after
# changing the profile and only the drifted settings are rewritten.

# %% export
class GenAIStack:
    'Provision a compliance-hardened enterprise GenAI stack on AWS in one call.'
    def __init__(self, auth, name, compliance=None):
        self.auth, self.name = auth, name
        self.compliance = Compliance(**(compliance if compliance is not None else ISO27001))
        self.resources = {}

    @property
    def bucket(self) -> str:
        'Document bucket name — account id included because S3 names are globally unique.'
        return f'{self.name}-{self.auth.account_id}-data'

    @property
    def ledger(self):
        'Tag-based inventory of everything this stack provisioned: `.audit()`, `.destroy()`.'
        from awseasy.ledger import Ledger
        return Ledger(self.auth, self.name)

    def provision(self, s3=True, knowledge_base=True, guardrail=True, dynamodb=True,
                  redis=False, sso=False, cdn=False, callback_urls=None, domains=None,
                  wait=False) -> dict:
        'Create every enabled resource. Safe to re-run: each step is create-or-update.'
        from awseasy.ai import create_guardrail, create_kb, create_aoss_collection, bedrock_policy
        from awseasy.auth import create_app_client, create_pool_domain, create_user_pool
        from awseasy.cdn import create_distribution, create_waf
        from awseasy.data import create_bucket, create_redis, create_table
        from awseasy.ledger import ledger_tags
        from awseasy.network import attach_policy, create_role, put_role_policy

        auth, name, r = self.auth, self.name, self.resources
        # Every resource carries the stack tag, which is what makes `self.ledger` work.
        c = self.compliance | dict(tags=ledger_tags(name, self.compliance.get('tags')))
        if c.get('cmk'): r['kms'] = create_kms_key(auth, f'{name}-key', tags=c.get('tags'))
        key_arn = r['kms']['Arn'] if 'kms' in r else None

        # Bedrock service role, scoped to this stack's bucket and key rather than a wildcard.
        r['role'] = create_role(auth, f'{name}-role', service='bedrock.amazonaws.com',
                                source_account=auth.account_id, tags=c.get('tags'))
        if c.get('least_privilege'):
            put_role_policy(auth, f'{name}-role', f'{name}-bedrock',
                            bedrock_policy(auth, bucket=self.bucket if s3 else None, kms_key_arn=key_arn))
        else:
            attach_policy(auth, f'{name}-role', aws_policy(auth, 'AmazonBedrockFullAccess'))
        role = r['role']['Role']['Arn']

        if s3: r['s3'] = create_bucket(auth, self.bucket, kms_key_id=key_arn, **c)
        if guardrail: r['guardrail'] = create_guardrail(auth, f'{name}-guardrail', kms_key_arn=key_arn, **c)
        if knowledge_base and s3:
            r['vectors'] = create_aoss_collection(auth, f'{name}-vectors', role_arns=[role], **c)
            r['kb'] = create_kb(auth, f'{name}-kb', bucket=self.bucket, role_arn=role,
                                collection_arn=r['vectors']['arn'], **c)
        if dynamodb: r['dynamodb'] = create_table(auth, f'{name}-sessions', 'id', kms_key_id=key_arn, **c)
        if redis: r['redis'] = create_redis(auth, f'{name}-cache', kms_key_id=key_arn,
                                            wait=wait, **c)

        if sso:
            r['user_pool'] = create_user_pool(auth, f'{name}-users', **c)
            pool_id = r['user_pool']['Id']
            r['sso_domain'] = create_pool_domain(auth, pool_id, f'{name}-{auth.account_id}')
            r['app_client'] = create_app_client(auth, pool_id, f'{name}-web',
                                                callback_urls=callback_urls or [])
        if cdn:
            r['waf'] = create_waf(auth, f'{name}-waf', scope='CLOUDFRONT', tags=c.get('tags'))
            r['cdn'] = create_distribution(auth, name, s3_bucket=self.bucket if s3 else None,
                                           domains=domains, waf_acl_arn=r['waf']['ARN'],
                                           wait=wait, **c)
        return r

    def summary(self) -> dict:
        'Identifiers for everything provisioned. Never contains a secret value.'
        return {k: _resource_id(v) for k, v in self.resources.items()}

    def __repr__(self): return f'GenAIStack({self.name!r}, {len(self.resources)} resources)'

_ID_KEYS = ('knowledgeBaseId', 'guardrailId', 'collectionEndpoint', 'DomainName', 'BucketName',
            'ReplicationGroupId', 'TableName', 'DistributionArn', 'ARN', 'Arn', 'arn', 'Id', 'Name', 'name')

def _resource_id(v):
    'Best-effort single identifier for a resource dict, checking the most specific keys first.'
    if not isinstance(v, dict): return str(v)
    for k in _ID_KEYS:
        if k in v and isinstance(v[k], str): return v[k]
    for k in ('Role', 'Group', 'Secret', 'UserPool'):
        if k in v and isinstance(v[k], dict): return _resource_id(v[k])
    return str(v)

# %% code
# `_resource_id` picks the most specific identifier available, and unwraps the response
# envelopes that boto3 puts around IAM roles and Cognito user pools.
assert _resource_id({'BucketName': 'b', 'Arn': 'a'}) == 'b'
assert _resource_id({'Role': {'Arn': 'arn:aws:iam::1:role/r'}}) == 'arn:aws:iam::1:role/r'
assert _resource_id({'Arn': 'arn:x'}) == 'arn:x'
assert _resource_id('plain') == 'plain'
print('_resource_id OK')

# %% md
# ### End-to-end provisioning
#
# The stack is exercised against `moto` below. `redis`/`cdn` are covered in their own
# notebooks — ElastiCache and CloudFront are slow to mock and are tested directly there.

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    stack = GenAIStack(auth, 'demo', compliance=SOC2)
    assert stack.bucket == 'demo-123456789012-data'

    res = stack.provision(knowledge_base=False, guardrail=False, sso=True,
                          callback_urls=['https://demo.example.com/oauth2/idpresponse'])
    assert {'role', 's3', 'dynamodb', 'user_pool', 'app_client'} <= set(res)
    assert 'kms' not in res, 'SOC2 does not set cmk=True, so no customer key is created'

    s = stack.summary()
    assert s['s3'] == 'demo-123456789012-data'
    assert s['role'].endswith(':role/demo-role')
    assert all(isinstance(v, str) for v in s.values())

    # the bucket really is private and encrypted, not just recorded as provisioned
    s3 = auth.client('s3')
    pab = s3.get_public_access_block(Bucket=stack.bucket)['PublicAccessBlockConfiguration']
    assert all(pab.values()), pab
    print(stack, json.dumps(s, indent=1))

# %% code
with mock_aws():
    # A cmk=True profile creates the customer key first and threads it through every resource.
    auth = AWSAuth(region='us-east-1')
    stack = GenAIStack(auth, 'phi', compliance=HIPAA)
    res = stack.provision(knowledge_base=False, guardrail=False, dynamodb=True)
    assert 'kms' in res and res['kms']['Arn'].startswith('arn:aws:kms:')

    enc = auth.client('s3').get_bucket_encryption(Bucket=stack.bucket)
    rule = enc['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
    assert rule['SSEAlgorithm'] == 'aws:kms' and rule['KMSMasterKeyID'] == res['kms']['Arn']
    print('HIPAA stack routed S3 through the customer-managed key OK')

# %% code
with mock_aws():
    # provision() is a reconciler: running it twice must converge, not raise or duplicate.
    auth = AWSAuth(region='us-east-1')
    stack = GenAIStack(auth, 'twice', compliance=SOC2)
    a = stack.provision(knowledge_base=False, guardrail=False)
    b = stack.provision(knowledge_base=False, guardrail=False)
    assert stack.summary()['role'] == _resource_id(a['role']) == _resource_id(b['role'])
    assert len(auth.client('s3').list_buckets()['Buckets']) == 1
    print('re-provision converged OK')

# %% md
# ## Agent skill
#
# `awseasy` ships a `SKILL.md` describing its API for coding agents. `mv_skill_md()` installs it
# where Claude Code and other agents look, matching the rest of the toolchain.

# %% export
def repo_root(path=None) -> Path:
    'Nearest ancestor directory containing a .git, else the starting directory.'
    p = Path(path or '.').resolve()
    for d in [p, *p.parents]:
        if (d / '.git').exists(): return d
    return p

def mv_skill_md(dry_run=True, dir=None) -> None:
    'Copy the bundled SKILL.md to .agents/skills/awseasy/ and ~/.claude/skills/awseasy/.'
    base = Path(__file__).parent if '__file__' in globals() else Path.cwd()
    src = base / 'SKILL.md'
    if not src.exists(): return print(f'no SKILL.md alongside {base}')
    targets = [repo_root(dir) / '.agents/skills/awseasy/SKILL.md',
               Path.home() / '.claude/skills/awseasy/SKILL.md']
    if dry_run: return print(f'Would copy to: {[str(p) for p in targets]}')
    for p in targets: p.mk_write(src.read_text(encoding='utf-8'))
    print(f'Installed -> {[str(p) for p in targets]}')

# %% code
assert repo_root('.').name == 'awseasy'                 # this repo
assert (repo_root('.') / '.git').exists()
assert repo_root('/tmp') == Path('/tmp')                # no .git anywhere above: the path itself
mv_skill_md()                                           # dry run by default; prints, copies nothing

# %% hide
import nbdev; nbdev.nbdev_export()
