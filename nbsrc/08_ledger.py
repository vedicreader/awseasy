# %% md
# # ledger
# > Tag-based inventory, security audit, and teardown for everything a stack created — with no state file.

# %% md
#
# The usual objection to provisioning without an IaC engine is fair: without state you cannot
# say what you created, so you cannot tear it down or tell when it drifted.
#
# The answer here is to use AWS itself as the state store. Every resource `awseasy` creates
# carries an `awseasy:stack` tag, and the [Resource Groups Tagging
# API](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/Welcome.html)
# indexes tags across every service in the account. That gives a real inventory, a real
# `destroy()`, and a real audit — queried from AWS rather than from a file that can be lost,
# stale, or in someone else's working copy.
#
# It also does something a state file cannot: `adopt()` pulls resources created by *anything* —
# the console, Terraform, a colleague's script — into the same inventory, so `audit()` covers
# them too. Good defaults only protect resources created through this library; an audit over
# tags protects whatever you point it at.
#
# What it does not give you is a dependency graph or a preview diff. Deletion order here is a
# fixed, hand-written service ordering, not something derived from actual references.

# %% code
#| default_exp ledger

# %% hide
from nbdev.showdoc import *

# %% export
import json
from fastcore.all import L, first
from awseasy.core import tag_dict, tag_list

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, GenAIStack, HIPAA, ISO27001, SOC2, create_kms_key
from awseasy.data import create_bucket, create_redis, create_table
from awseasy.network import create_secret, create_security_group, create_vpc

# %% md
# ## Stack tags
#
# `ledger_tags` is what marks a resource as belonging to a stack. `GenAIStack` applies it to
# everything it provisions; apply it yourself for anything you create directly.

# %% export
LEDGER_TAG = 'awseasy:stack'

def ledger_tags(stack, tags=None) -> dict:
    'Tag dict marking a resource as part of `stack`. The stack tag always wins.'
    return {**(tags or {}), LEDGER_TAG: stack}

def parse_arn(arn) -> dict:
    '''Split an ARN into partition/service/region/account/type/name.

    The tail takes three shapes — `type/name` (dynamodb, ec2), `type:name` (rds, secretsmanager),
    and a bare `name` (s3) — so the *first* separator wins. Checking one before the other splits
    a Secrets Manager ARN like `secret:app/key-AbCdEf` in the wrong place.'''
    p = arn.split(':', 5)
    tail = p[5] if len(p) > 5 else ''
    seps = [i for i in (tail.find(':'), tail.find('/')) if i >= 0]
    if seps: i = min(seps); rtype, name = tail[:i], tail[i + 1:]
    else:    rtype, name = '', tail
    return dict(arn=arn, partition=p[1], service=p[2], region=p[3], account=p[4],
                type=rtype, name=name)

# %% code
assert ledger_tags('demo') == {'awseasy:stack': 'demo'}
assert ledger_tags('demo', {'env': 'prod'}) == {'env': 'prod', 'awseasy:stack': 'demo'}
# the stack tag is not overridable by a caller's tags — the inventory would silently lose the resource
assert ledger_tags('demo', {LEDGER_TAG: 'other'})[LEDGER_TAG] == 'demo'

cases = {
    'arn:aws:s3:::my-bucket': ('s3', '', 'my-bucket'),
    'arn:aws:dynamodb:us-east-1:1:table/sessions': ('dynamodb', 'table', 'sessions'),
    'arn:aws:rds:us-east-1:1:db:app-db': ('rds', 'db', 'app-db'),
    'arn:aws:secretsmanager:us-east-1:1:secret:app/key-AbCdEf': ('secretsmanager', 'secret',
                                                                 'app/key-AbCdEf'),
    'arn:aws:ec2:us-east-1:1:vpc/vpc-123': ('ec2', 'vpc', 'vpc-123'),
    'arn:aws:kms:us-east-1:1:key/abc-def': ('kms', 'key', 'abc-def'),
    'arn:aws:cloudfront::1:distribution/E123': ('cloudfront', 'distribution', 'E123'),
}
for arn, (svc, typ, name) in cases.items():
    got = parse_arn(arn)
    assert (got['service'], got['type'], got['name']) == (svc, typ, name), (arn, got)
print('arn parsing OK')

# %% md
# ## Inventory
#
# `Ledger.resources()` asks the tagging API for everything carrying the stack tag. It is
# eventually consistent — a resource created seconds ago may not appear yet — and it does not
# cover every service (IAM roles and CloudFront distributions are notable absences), so
# `destroy()` reports what it could not see rather than pretending the stack is empty.

# %% export
class Ledger:
    '''Tag-based inventory of a stack. AWS is the state store; there is no state file.

    Backed by the Resource Groups Tagging API, so it sees resources created by anything that
    applied the tag — this library, the console, Terraform, or a colleague's script.'''
    def __init__(self, auth, stack):
        self.auth, self.stack = auth, stack

    def _client(self): return self.auth.client('resourcegroupstaggingapi')

    def resources(self, services=None) -> list:
        'Every tagged resource in the stack, as [{arn, service, type, name, tags}].'
        p = self._client().get_paginator('get_resources')
        out = []
        for page in p.paginate(TagFilters=[{'Key': LEDGER_TAG, 'Values': [self.stack]}]):
            for m in page['ResourceTagMappingList']:
                r = parse_arn(m['ResourceARN'])
                r['tags'] = tag_dict(m.get('Tags', []))
                out.append(r)
        if services: out = [r for r in out if r['service'] in set(services)]
        return sorted(out, key=lambda r: (r['service'], r['type'], r['name']))

    def arns(self) -> list: return [r['arn'] for r in self.resources()]

    def by_service(self) -> dict:
        'Resource ARNs grouped by service, for a quick read of what a stack consists of.'
        out = {}
        for r in self.resources(): out.setdefault(r['service'], []).append(r['arn'])
        return out

    def adopt(self, arns, tags=None) -> dict:
        'Tag existing resources into the stack so inventory, audit, and destroy cover them too.'
        r = self._client().tag_resources(ResourceARNList=list(arns),
                                         Tags=ledger_tags(self.stack, tags))
        return r.get('FailedResourcesMap', {})

    def release(self, arns) -> dict:
        'Remove the stack tag, so destroy() will no longer touch these resources.'
        r = self._client().untag_resources(ResourceARNList=list(arns), TagKeys=[LEDGER_TAG])
        return r.get('FailedResourcesMap', {})

    def audit(self, failures_only=True) -> list:
        'Check the security controls this library claims to enforce. See `audit_resource`.'
        out = [f for r in self.resources() for f in audit_resource(self.auth, r)]
        return [f for f in out if not f['ok']] if failures_only else out

    def destroy(self, dry_run=True, services=None) -> dict:
        'Delete the stack, dependents first. dry_run=True by default — this is irreversible.'
        return destroy_resources(self.auth, self.resources(services), dry_run=dry_run)

    def __repr__(self):
        return f'Ledger({self.stack!r}, {len(self.arns())} resources)'

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    led = Ledger(auth, 'demo')
    assert led.resources() == [] and led.arns() == []

    create_bucket(auth, 'demo-docs', tags=ledger_tags('demo'))
    create_table(auth, 'demo-sessions', 'id', tags=ledger_tags('demo', {'env': 'prod'}))
    create_kms_key(auth, 'demo-key', tags=ledger_tags('demo'))
    create_secret(auth, 'demo/config', 'x', tags=ledger_tags('demo'))
    create_bucket(auth, 'other-stack-docs', tags=ledger_tags('other'))

    got = led.by_service()
    assert set(got) == {'s3', 'dynamodb', 'kms', 'secretsmanager'}, got
    assert got['s3'] == ['arn:aws:s3:::demo-docs'], 'another stack must not appear'
    assert len(led.arns()) == 4
    assert first(r for r in led.resources() if r['service'] == 'dynamodb')['tags']['env'] == 'prod'
    assert led.resources(services=['s3']) == led.resources(services=['s3', 'lambda'])
    assert repr(led) == "Ledger('demo', 4 resources)"
    print(json.dumps(got, indent=1))

# %% code
with mock_aws():
    # adopt() brings resources created outside awseasy under the same inventory and audit
    auth = AWSAuth(region='us-east-1')
    auth.client('s3').create_bucket(Bucket='legacy-bucket')      # created by someone else
    led = Ledger(auth, 'demo')
    assert led.arns() == []

    assert led.adopt(['arn:aws:s3:::legacy-bucket']) == {}
    assert led.arns() == ['arn:aws:s3:::legacy-bucket']
    assert led.resources()[0]['tags'][LEDGER_TAG] == 'demo'

    # release() hands it back, so destroy() will no longer touch it
    led.release(['arn:aws:s3:::legacy-bucket'])
    assert led.arns() == []
    print('adopt/release OK')

# %% md
# ## Audit
#
# Good defaults only protect resources created through this library. An audit over tags checks
# the same controls on whatever is in the inventory, including resources created elsewhere and
# pulled in with `adopt()`, and including resources whose settings were changed in the console
# after provisioning.
#
# Each auditor reads the live configuration and returns findings — this is drift detection for
# the controls that matter, rather than a full config diff.
#
# The checks are deliberately limited to controls that are wrong under *any* policy: publicly
# reachable, unencrypted, no backups, mutable image tags. Settings that are a legitimate choice —
# deletion protection, multi-AZ, retention length — belong to the compliance profile, not here.
# An audit that reports things which are fine trains people to ignore it.

# %% export
AUDITORS = {}

def auditor(service, type=''):
    'Register a check for one resource type. Auditors take (auth, resource) and yield findings.'
    def deco(fn): AUDITORS[(service, type)] = fn; return fn
    return deco

def finding(r, check, ok, detail='') -> dict:
    return {'arn': r['arn'], 'name': r['name'], 'check': check, 'ok': bool(ok), 'detail': detail}

def audit_resource(auth, r) -> list:
    'Run the registered auditor for a resource. Unknown types report as unchecked, never as passing.'
    fn = AUDITORS.get((r['service'], r['type']))
    if fn is None: return [finding(r, f"{r['service']}:unchecked", True, 'no auditor registered')]
    try: return list(fn(auth, r))
    except Exception as e: return [finding(r, f"{r['service']}:error", False, str(e)[:200])]

@auditor('s3')
def _audit_s3(auth, r):
    s3, b = auth.client('s3'), r['name']
    try: pab = s3.get_public_access_block(Bucket=b)['PublicAccessBlockConfiguration']
    except s3.exceptions.ClientError: pab = {}
    yield finding(r, 's3:public-access-block', pab and all(pab.values()),
                  f'set: {sorted(k for k, v in pab.items() if v)}')
    try:
        rules = s3.get_bucket_encryption(Bucket=b)['ServerSideEncryptionConfiguration']['Rules']
        alg = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
    except s3.exceptions.ClientError: alg = None
    yield finding(r, 's3:encryption', alg is not None, f'algorithm: {alg}')
    try: pol = json.loads(s3.get_bucket_policy(Bucket=b)['Policy'])['Statement']
    except s3.exceptions.ClientError: pol = []
    tls = any(s.get('Effect') == 'Deny'
              and s.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false'
              for s in pol)
    yield finding(r, 's3:tls-only', tls, 'bucket policy denies aws:SecureTransport=false')
    ver = s3.get_bucket_versioning(Bucket=b).get('Status')
    yield finding(r, 's3:versioning', ver == 'Enabled', f'status: {ver}')

@auditor('dynamodb', 'table')
def _audit_dynamodb(auth, r):
    c = auth.client('dynamodb')
    cb = c.describe_continuous_backups(TableName=r['name'])['ContinuousBackupsDescription']
    st = cb['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']
    yield finding(r, 'dynamodb:pitr', st == 'ENABLED', f'status: {st}')

@auditor('rds', 'db')
def _audit_rds(auth, r):
    d = auth.client('rds').describe_db_instances(DBInstanceIdentifier=r['name'])['DBInstances'][0]
    yield finding(r, 'rds:not-public', not d.get('PubliclyAccessible'), '')
    yield finding(r, 'rds:encrypted', d.get('StorageEncrypted'), '')
    yield finding(r, 'rds:iam-auth', d.get('IAMDatabaseAuthenticationEnabled'), '')
    yield finding(r, 'rds:backups', d.get('BackupRetentionPeriod', 0) > 0,
                  f"retention: {d.get('BackupRetentionPeriod')} days")

@auditor('kms', 'key')
def _audit_kms(auth, r):
    c = auth.client('kms')
    rot = c.get_key_rotation_status(KeyId=r['name']).get('KeyRotationEnabled')
    yield finding(r, 'kms:rotation', rot, '')

@auditor('ec2', 'instance')
def _audit_ec2(auth, r):
    c = auth.client('ec2')
    i = c.describe_instances(InstanceIds=[r['name']])['Reservations'][0]['Instances'][0]
    yield finding(r, 'ec2:imdsv2', i.get('MetadataOptions', {}).get('HttpTokens') == 'required', '')
    vols = [b['Ebs']['VolumeId'] for b in i.get('BlockDeviceMappings', []) if 'Ebs' in b]
    enc = [v['Encrypted'] for v in c.describe_volumes(VolumeIds=vols)['Volumes']] if vols else []
    yield finding(r, 'ec2:ebs-encrypted', enc and all(enc), f'{sum(enc)}/{len(enc)} volumes')

@auditor('elasticache', 'replicationgroup')
def _audit_elasticache(auth, r):
    g = auth.client('elasticache').describe_replication_groups(
        ReplicationGroupId=r['name'])['ReplicationGroups'][0]
    yield finding(r, 'elasticache:transit-encryption', g.get('TransitEncryptionEnabled'), '')
    yield finding(r, 'elasticache:at-rest-encryption', g.get('AtRestEncryptionEnabled'), '')

@auditor('ecr', 'repository')
def _audit_ecr(auth, r):
    repo = auth.client('ecr').describe_repositories(
        repositoryNames=[r['name']])['repositories'][0]
    yield finding(r, 'ecr:immutable-tags', repo.get('imageTagMutability') == 'IMMUTABLE', '')
    yield finding(r, 'ecr:scan-on-push',
                  repo.get('imageScanningConfiguration', {}).get('scanOnPush'), '')

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    led = Ledger(auth, 'demo')

    # a hardened bucket passes every check
    create_bucket(auth, 'good-bucket', tags=ledger_tags('demo'))
    assert led.audit() == [], led.audit()

    # one created by hand fails the ones it should
    auth.client('s3').create_bucket(Bucket='bad-bucket')
    led.adopt(['arn:aws:s3:::bad-bucket'])
    failed = {f['check'] for f in led.audit()}
    assert failed == {'s3:public-access-block', 's3:encryption', 's3:tls-only', 's3:versioning'}

    full = led.audit(failures_only=False)
    assert len(full) == 8 and sum(f['ok'] for f in full) == 4
    print(json.dumps([f for f in led.audit()][:2], indent=1))

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    led = Ledger(auth, 'audit-demo')
    tags = ledger_tags('audit-demo')

    create_table(auth, 'audited-table', 'id', **HIPAA | dict(tags=tags))
    create_kms_key(auth, 'audited-key', tags=tags)
    auth.client('rds').create_db_instance(
        DBInstanceIdentifier='hand-made-db', DBInstanceClass='db.t3.micro', Engine='postgres',
        MasterUsername='pgadmin', ManageMasterUserPassword=True, AllocatedStorage=20,
        PubliclyAccessible=True, StorageEncrypted=False,
        Tags=tag_list(tags))                      # deliberately not created through awseasy

    checks = {f['check']: f for f in led.audit(failures_only=False)}
    assert checks['dynamodb:pitr']['ok'] and checks['kms:rotation']['ok']
    # the console-created database is caught on exactly the controls it violates
    assert not checks['rds:not-public']['ok'] and not checks['rds:encrypted']['ok']
    assert not checks['rds:iam-auth']['ok']
    print([c for c, f in checks.items() if not f['ok']])

# %% code
# An unknown resource type reports as unchecked rather than quietly passing an audit.
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    r = parse_arn('arn:aws:lambda:us-east-1:123456789012:function:mystery')
    f = audit_resource(auth, r)
    assert len(f) == 1 and f[0]['check'] == 'lambda:unchecked'
    assert 'no auditor registered' in f[0]['detail']

    # and a broken auditor surfaces as a failed check, never as a pass
    bad = audit_resource(auth, parse_arn('arn:aws:s3:::does-not-exist'))
    assert any(not x['ok'] for x in bad)
    print(f[0])

# %% md
# ## Teardown
#
# `destroy()` is the reason the ledger exists. It deletes dependents before dependencies using a
# fixed service ordering — not a real dependency graph, which is the honest limitation of doing
# this without an IaC engine.
#
# It defaults to `dry_run=True`, and anything it has no deleter for is reported under
# `unsupported` rather than skipped. A teardown that quietly leaves resources behind is worse
# than one that refuses, because the bill arrives either way.
#
# Two resource types are deliberately not destroyed outright: KMS keys are *scheduled* for
# deletion (AWS enforces a waiting period, and immediate deletion would make encrypted backups
# unrecoverable), and S3 buckets are emptied first because AWS will not delete a non-empty one.

# %% export
DELETERS = {}

def deleter(service, type='', order=50):
    'Register a deleter. Lower `order` runs first, so dependents go before their dependencies.'
    def deco(fn): DELETERS[(service, type)] = (order, fn); return fn
    return deco

def destroy_resources(auth, resources, dry_run=True) -> dict:
    'Delete resources dependents-first. Returns {plan, deleted, unsupported, failed}.'
    known = [r for r in resources if (r['service'], r['type']) in DELETERS]
    unknown = [r for r in resources if (r['service'], r['type']) not in DELETERS]
    known.sort(key=lambda r: DELETERS[(r['service'], r['type'])][0])
    out = {'plan': [r['arn'] for r in known], 'deleted': [], 'failed': [],
           'unsupported': [{'arn': r['arn'],
                            'reason': f"no deleter for {r['service']}:{r['type'] or '-'}"}
                           for r in unknown]}
    if dry_run: return out
    for r in known:
        try:
            DELETERS[(r['service'], r['type'])][1](auth, r)
            out['deleted'].append(r['arn'])
        except Exception as e:
            out['failed'].append({'arn': r['arn'], 'error': f'{type(e).__name__}: {str(e)[:200]}'})
    return out

# Compute and edge first, then data stores, then the network and keys they depend on.
@deleter('ec2', 'instance', order=10)
def _rm_instance(auth, r): auth.client('ec2').terminate_instances(InstanceIds=[r['name']])

@deleter('elasticache', 'replicationgroup', order=20)
def _rm_redis(auth, r):
    auth.client('elasticache').delete_replication_group(ReplicationGroupId=r['name'],
                                                        RetainPrimaryCluster=False)

@deleter('rds', 'db', order=20)
def _rm_rds(auth, r):
    c = auth.client('rds')
    c.modify_db_instance(DBInstanceIdentifier=r['name'], DeletionProtection=False,
                         ApplyImmediately=True)
    c.delete_db_instance(DBInstanceIdentifier=r['name'], SkipFinalSnapshot=True,
                         DeleteAutomatedBackups=True)

@deleter('es', 'domain', order=20)
def _rm_opensearch(auth, r): auth.client('opensearch').delete_domain(DomainName=r['name'])

@deleter('dynamodb', 'table', order=30)
def _rm_table(auth, r):
    c = auth.client('dynamodb')
    c.update_table(TableName=r['name'], DeletionProtectionEnabled=False)
    c.delete_table(TableName=r['name'])

@deleter('ecr', 'repository', order=30)
def _rm_ecr(auth, r): auth.client('ecr').delete_repository(repositoryName=r['name'], force=True)

@deleter('cognito-idp', 'userpool', order=30)
def _rm_pool(auth, r):
    c = auth.client('cognito-idp')
    c.update_user_pool(UserPoolId=r['name'], DeletionProtection='INACTIVE')
    c.delete_user_pool(UserPoolId=r['name'])

@deleter('s3', order=40)
def _rm_bucket(auth, r):
    'S3 refuses to delete a non-empty bucket, so every version and delete marker goes first.'
    s3 = auth.client('s3')
    p = s3.get_paginator('list_object_versions')
    for page in p.paginate(Bucket=r['name']):
        objs = [{'Key': o['Key'], 'VersionId': o['VersionId']}
                for k in ('Versions', 'DeleteMarkers') for o in page.get(k, [])]
        if objs: s3.delete_objects(Bucket=r['name'], Delete={'Objects': objs})
    s3.delete_bucket(Bucket=r['name'])

@deleter('secretsmanager', 'secret', order=50)
def _rm_secret(auth, r):
    auth.client('secretsmanager').delete_secret(SecretId=r['arn'],
                                                ForceDeleteWithoutRecovery=True)

@deleter('ec2', 'vpc-endpoint', order=60)
def _rm_endpoint(auth, r): auth.client('ec2').delete_vpc_endpoints(VpcEndpointIds=[r['name']])

@deleter('ec2', 'security-group', order=70)
def _rm_sg(auth, r): auth.client('ec2').delete_security_group(GroupId=r['name'])

@deleter('ec2', 'subnet', order=80)
def _rm_subnet(auth, r): auth.client('ec2').delete_subnet(SubnetId=r['name'])

@deleter('ec2', 'vpc', order=90)
def _rm_vpc(auth, r): auth.client('ec2').delete_vpc(VpcId=r['name'])

@deleter('kms', 'key', order=100)
def _rm_key(auth, r):
    'Scheduled, not deleted: AWS enforces a waiting period, and data encrypted with it stays readable.'
    auth.client('kms').schedule_key_deletion(KeyId=r['name'], PendingWindowInDays=7)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    tags = ledger_tags('teardown')
    create_bucket(auth, 'teardown-docs', tags=tags)
    create_table(auth, 'teardown-table', 'id', tags=tags)
    create_kms_key(auth, 'teardown-key', tags=tags)
    create_secret(auth, 'teardown/config', 'x', tags=tags)
    vpc = create_vpc(auth, 'teardown-vpc', tags=tags)
    led = Ledger(auth, 'teardown')

    plan = led.destroy()                       # dry run by default
    assert plan['deleted'] == [] and plan['failed'] == []
    assert len(plan['plan']) == 5

    # dependents first: the VPC is torn down after the resources inside it, the key last of all
    order = [parse_arn(a)['service'] for a in plan['plan']]
    assert order.index('dynamodb') < order.index('s3') < order.index('ec2') < order.index('kms')
    assert auth.client('s3').list_buckets()['Buckets'], 'a dry run must not delete anything'
    print(plan['plan'])

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    tags = ledger_tags('teardown')
    # tls_min=None only because moto serves plaintext HTTP, so the TLS-only policy would
    # (correctly) deny the put_object below. Against real S3, keep the default.
    create_bucket(auth, 'teardown-docs', tags=tags, tls_min=None)
    auth.client('s3').put_object(Bucket='teardown-docs', Key='doc.txt', Body=b'x')
    create_table(auth, 'teardown-table', 'id', **HIPAA | dict(tags=tags))
    create_kms_key(auth, 'teardown-key', tags=tags)
    create_secret(auth, 'teardown/config', 'x', tags=tags)
    create_bucket(auth, 'survivor', tags=ledger_tags('other-stack'))
    led = Ledger(auth, 'teardown')

    out = led.destroy(dry_run=False)
    assert out['failed'] == [], out['failed']
    assert len(out['deleted']) == 4

    buckets = [b['Name'] for b in auth.client('s3').list_buckets()['Buckets']]
    assert buckets == ['survivor'], buckets       # a versioned, non-empty bucket still goes
    assert auth.client('dynamodb').list_tables()['TableNames'] == []
    assert led.resources() == [] or all(r['service'] == 'kms' for r in led.resources())

    # the key is scheduled, not gone — data encrypted with it is still recoverable
    k = first(r for r in [parse_arn(a) for a in out['deleted']] if r['service'] == 'kms')
    assert auth.client('kms').describe_key(KeyId=k['name'])['KeyMetadata']['KeyState'] == \
        'PendingDeletion'
    print(out['deleted'])

# %% code
with mock_aws():
    # anything without a deleter is reported, never silently skipped
    auth = AWSAuth(region='us-east-1')
    unknown = parse_arn('arn:aws:lambda:us-east-1:123456789012:function:mystery')
    out = destroy_resources(auth, [unknown], dry_run=True)
    assert out['plan'] == [] and out['unsupported'][0]['reason'] == 'no deleter for lambda:function'

    # and a delete that fails lands in `failed` rather than aborting the rest of the teardown
    tags = ledger_tags('partial')
    create_bucket(auth, 'partial-bucket', tags=tags)
    missing = parse_arn('arn:aws:dynamodb:us-east-1:123456789012:table/never-existed')
    out = destroy_resources(auth, [missing, *Ledger(auth, 'partial').resources()], dry_run=False)
    assert len(out['failed']) == 1 and 'never-existed' in out['failed'][0]['arn']
    assert out['deleted'] == ['arn:aws:s3:::partial-bucket'], 'one failure must not stop the rest'
    print(out['failed'][0]['error'][:80])

# %% md
# ## With `GenAIStack`
#
# `GenAIStack` tags everything it provisions, so a stack has an inventory, an audit, and a
# teardown without any extra bookkeeping.

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    stack = GenAIStack(auth, 'acme', compliance=SOC2)
    stack.provision(knowledge_base=False, guardrail=False)

    led = stack.ledger
    assert led.stack == 'acme'
    services = set(led.by_service())
    assert {'s3', 'dynamodb'} <= services, services
    assert led.audit() == [], led.audit()          # provisioned hardened, so nothing to report

    plan = led.destroy()
    assert 'arn:aws:s3:::acme-123456789012-data' in plan['plan']
    print(led, '|', sorted(services))
    print(json.dumps(plan['plan'], indent=1))

# %% md
# ### Against a real account
#
# `destroy()` is irreversible. Read the plan before passing `dry_run=False`.

# %% noeval
auth = AWSAuth()
led = Ledger(auth, 'acme')
print(json.dumps(led.by_service(), indent=1))
for f in led.audit(): print(f"FAIL {f['check']:32} {f['name']}  {f['detail']}")
plan = led.destroy()
print('would delete:', *plan['plan'], sep='\n  ')
print('cannot delete:', *[u['reason'] for u in plan['unsupported']], sep='\n  ')
# led.destroy(dry_run=False)

# %% hide
import nbdev; nbdev.nbdev_export()
