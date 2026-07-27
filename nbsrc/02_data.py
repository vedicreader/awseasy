# %% md
# # data
# > S3 document buckets, DynamoDB session tables, RDS PostgreSQL, and ElastiCache Redis — encrypted and private by default.

# %% code
#| default_exp data

# %% hide
from nbdev.showdoc import *

# %% export
import json, secrets
from awseasy.core import named, tag_list
from awseasy.network import create_secret, get_secret

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2, create_kms_key

# %% md
# ## S3
#
# `create_bucket` is the one function in this library most likely to be the difference
# between a private corpus and a public one, so all four public-access blocks, default
# encryption, versioning, and a TLS-only bucket policy are applied on every call — including
# calls against a bucket that already exists, which is how drift gets corrected.
#
# Passing `kms_key_id=` switches from SSE-S3 to SSE-KMS with a bucket key (which cuts KMS
# request costs by roughly 99% on read-heavy RAG workloads).

# %% export
def tls_only_policy(auth, bucket, tls_min='1.2') -> dict:
    'Bucket policy denying any request not made over TLS at or above `tls_min`.'
    b = auth.arn_for('s3', bucket, region='', account=False)
    res = [b, f'{b}/*']
    return {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'DenyInsecureTransport', 'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*',
         'Resource': res, 'Condition': {'Bool': {'aws:SecureTransport': 'false'}}},
        {'Sid': 'DenyOutdatedTLS', 'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*',
         'Resource': res, 'Condition': {'NumericLessThan': {'s3:TlsVersion': tls_min}}}]}

def create_bucket(auth, name, versioning=True, kms_key_id=None, tls_min='1.2', log_bucket=None,
                  tags=None, **compliance_opts) -> dict:
    'Create a private, encrypted, versioned S3 bucket. Re-applies every control on an existing bucket.'
    s3 = auth.client('s3')
    kw = {'Bucket': name}
    if auth.region != 'us-east-1': kw['CreateBucketConfiguration'] = {'LocationConstraint': auth.region}
    try: s3.create_bucket(**kw)
    except (s3.exceptions.BucketAlreadyOwnedByYou, s3.exceptions.BucketAlreadyExists): pass
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=dict(
        BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True))
    sse = ({'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': kms_key_id} if kms_key_id
           else {'SSEAlgorithm': 'AES256'})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        'Rules': [{'ApplyServerSideEncryptionByDefault': sse, 'BucketKeyEnabled': bool(kms_key_id)}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={
        'Status': 'Enabled' if versioning else 'Suspended'})
    if tls_min: s3.put_bucket_policy(Bucket=name, Policy=json.dumps(tls_only_policy(auth, name, tls_min)))
    if log_bucket:
        s3.put_bucket_logging(Bucket=name, BucketLoggingStatus={'LoggingEnabled': {
            'TargetBucket': log_bucket, 'TargetPrefix': f'{name}/'}})
    if tags: s3.put_bucket_tagging(Bucket=name, Tagging={'TagSet': tag_list(tags)})
    return {'BucketName': name, 'Region': auth.region,
            'Arn': auth.arn_for('s3', name, region='', account=False)}

def bucket_url(name, key='') -> str:
    'The s3:// URI for a bucket or object.'
    return f's3://{name}/{key}'

def presigned_url(auth, name, key, hours=1, method='get_object') -> str:
    'Time-limited URL for one object. Use this instead of ever making a bucket public.'
    return auth.client('s3').generate_presigned_url(
        method, Params={'Bucket': name, 'Key': key}, ExpiresIn=int(hours * 3600))

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    b = create_bucket(auth, 'docs-bucket', tags={'env': 'prod'})
    assert b['Arn'] == 'arn:aws:s3:::docs-bucket'
    s3 = auth.client('s3')

    # all four public-access blocks, not just the two people usually remember
    pab = s3.get_public_access_block(Bucket='docs-bucket')['PublicAccessBlockConfiguration']
    assert pab == dict(BlockPublicAcls=True, IgnorePublicAcls=True,
                       BlockPublicPolicy=True, RestrictPublicBuckets=True)

    rule = s3.get_bucket_encryption(Bucket='docs-bucket')['ServerSideEncryptionConfiguration']['Rules'][0]
    assert rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256'
    assert s3.get_bucket_versioning(Bucket='docs-bucket')['Status'] == 'Enabled'

    # plaintext and downlevel-TLS requests are denied by bucket policy, not just by convention
    pol = json.loads(s3.get_bucket_policy(Bucket='docs-bucket')['Policy'])
    sids = {s['Sid']: s for s in pol['Statement']}
    assert sids['DenyInsecureTransport']['Condition']['Bool']['aws:SecureTransport'] == 'false'
    assert sids['DenyOutdatedTLS']['Condition']['NumericLessThan']['s3:TlsVersion'] == '1.2'
    assert all(s['Effect'] == 'Deny' for s in pol['Statement'])
    print(json.dumps(pol['Statement'][0], indent=1))

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    key = create_kms_key(auth, 'data-key')

    # a customer-managed key switches S3 to SSE-KMS and turns on the S3 bucket key
    create_bucket(auth, 'phi-bucket', kms_key_id=key['Arn'], **HIPAA)
    rule = auth.client('s3').get_bucket_encryption(
        Bucket='phi-bucket')['ServerSideEncryptionConfiguration']['Rules'][0]
    assert rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms'
    assert rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] == key['Arn']
    assert rule['BucketKeyEnabled'] is True

    # re-running on an existing bucket is how drift gets corrected, so it must not raise
    create_bucket(auth, 'phi-bucket', kms_key_id=key['Arn'], **HIPAA)
    assert len(auth.client('s3').list_buckets()['Buckets']) == 1

    assert bucket_url('phi-bucket', 'docs/a.pdf') == 's3://phi-bucket/docs/a.pdf'
    # sharing an object is a signed, expiring URL — never a public bucket or object ACL
    url = presigned_url(auth, 'phi-bucket', 'docs/a.pdf', hours=0.25)
    assert 'phi-bucket' in url and 'docs/a.pdf' in url and 'Signature' in url
    assert 'Expires' in url   # SigV4 spells it X-Amz-Expires; either way the URL is time-boxed
    print('SSE-KMS bucket OK')

# %% code
with mock_aws():
    # buckets outside us-east-1 need an explicit LocationConstraint or the call fails
    auth = AWSAuth(region='eu-central-1')
    create_bucket(auth, 'eu-bucket')
    loc = auth.client('s3').get_bucket_location(Bucket='eu-bucket')['LocationConstraint']
    assert loc == 'eu-central-1', loc
    print('regional bucket OK')

# %% md
# ## DynamoDB
#
# The default table is on-demand billing with point-in-time recovery on. For chat and agent
# workloads, `ttl_attr=` sets an expiry attribute so old sessions delete themselves rather
# than accumulating as a growing pile of retained user data.

# %% export
def create_table(auth, name, partition_key, sort_key=None, billing_mode='PAY_PER_REQUEST',
                 kms_key_id=None, ttl_attr=None, deletion_protection=False, tags=None,
                 **compliance_opts) -> dict:
    'Create a DynamoDB table with point-in-time recovery. Idempotent by name.'
    c = auth.client('dynamodb')
    keys = [{'AttributeName': partition_key, 'KeyType': 'HASH'}]
    attrs = [{'AttributeName': partition_key, 'AttributeType': 'S'}]
    if sort_key:
        keys.append({'AttributeName': sort_key, 'KeyType': 'RANGE'})
        attrs.append({'AttributeName': sort_key, 'AttributeType': 'S'})
    sse = ({'Enabled': True, 'SSEType': 'KMS', 'KMSMasterKeyId': kms_key_id} if kms_key_id
           else {'Enabled': False})   # Enabled=False still encrypts, using the AWS-owned key
    try:
        t = c.create_table(TableName=name, KeySchema=keys, AttributeDefinitions=attrs,
                           BillingMode=billing_mode, SSESpecification=sse,
                           DeletionProtectionEnabled=deletion_protection,
                           Tags=tag_list(tags))['TableDescription']
    except c.exceptions.ResourceInUseException:
        t = c.describe_table(TableName=name)['Table']
    c.update_continuous_backups(TableName=name,
                                PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True})
    if ttl_attr:
        c.update_time_to_live(TableName=name,
                              TimeToLiveSpecification={'Enabled': True, 'AttributeName': ttl_attr})
    return t

def table_resource(auth, name):
    'boto3 DynamoDB Table resource, for get_item/put_item/query against the provisioned table.'
    return auth.resource('dynamodb').Table(name)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    key = create_kms_key(auth, 'sessions-key')
    t = create_table(auth, 'sessions', 'session_id', sort_key='ts', kms_key_id=key['Arn'],
                     ttl_attr='expires_at', **HIPAA)
    assert t['TableName'] == 'sessions'
    c = auth.client('dynamodb')

    desc = c.describe_table(TableName='sessions')['Table']
    assert [k['AttributeName'] for k in desc['KeySchema']] == ['session_id', 'ts']
    assert desc['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST'
    assert desc['SSEDescription']['KMSMasterKeyArn'] == key['Arn']
    assert desc['DeletionProtectionEnabled'] is True, 'HIPAA sets deletion_protection'

    pitr = c.describe_continuous_backups(TableName='sessions')['ContinuousBackupsDescription']
    assert pitr['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED'
    ttl = c.describe_time_to_live(TableName='sessions')['TimeToLiveDescription']
    assert ttl['TimeToLiveStatus'] == 'ENABLED' and ttl['AttributeName'] == 'expires_at'

    assert create_table(auth, 'sessions', 'session_id')['TableName'] == 'sessions'   # idempotent
    assert len(c.list_tables()['TableNames']) == 1

    table_resource(auth, 'sessions').put_item(Item={'session_id': 's1', 'ts': '1'})
    assert table_resource(auth, 'sessions').get_item(
        Key={'session_id': 's1', 'ts': '1'})['Item']['session_id'] == 's1'
    print('DynamoDB OK')

# %% md
# ## RDS PostgreSQL
#
# The master password is never generated in Python and never returned. `ManageMasterUserPassword`
# hands generation, storage, and rotation to RDS, which keeps the credential in Secrets Manager
# — so there is no window in which the password exists in a process, a log, or a notebook output.
#
# Instances are created with `PubliclyAccessible=False` and IAM database authentication on, so
# applications can connect with short-lived IAM tokens instead of a shared password at all.

# %% export
def create_postgres(auth, name, instance_class='db.t3.medium', engine_version='16.4',
                    master_username='pgadmin', storage=20, kms_key_id=None, subnet_group=None,
                    sg_ids=None, multi_az=False, deletion_protection=False, backup_retention=7,
                    audit=False, tags=None, **compliance_opts) -> dict:
    'Create an encrypted, private RDS PostgreSQL instance. RDS generates and holds the master password.'
    c = auth.client('rds')
    kw = dict(DBInstanceIdentifier=name, DBInstanceClass=instance_class, Engine='postgres',
              EngineVersion=engine_version, MasterUsername=master_username,
              ManageMasterUserPassword=True,          # password lives in Secrets Manager, never here
              AllocatedStorage=storage, StorageEncrypted=True, StorageType='gp3',
              PubliclyAccessible=False, EnableIAMDatabaseAuthentication=True,
              MultiAZ=multi_az, DeletionProtection=deletion_protection,
              BackupRetentionPeriod=backup_retention, CopyTagsToSnapshot=True,
              AutoMinorVersionUpgrade=True, Tags=tag_list(named(name, tags)))
    if kms_key_id: kw.update(KmsKeyId=kms_key_id, MasterUserSecretKmsKeyId=kms_key_id)
    if subnet_group: kw['DBSubnetGroupName'] = subnet_group
    if sg_ids: kw['VpcSecurityGroupIds'] = sg_ids
    if audit: kw['EnableCloudwatchLogsExports'] = ['postgresql', 'upgrade']
    try: return c.create_db_instance(**kw)['DBInstance']
    except c.exceptions.DBInstanceAlreadyExistsFault:
        return c.describe_db_instances(DBInstanceIdentifier=name)['DBInstances'][0]

def postgres_conn(auth, name, db='postgres') -> str:
    'A postgresql:// URL with no password in it. Fetch the password separately, or use an IAM token.'
    i = auth.client('rds').describe_db_instances(DBInstanceIdentifier=name)['DBInstances'][0]
    e = i['Endpoint']
    return f"postgresql://{i['MasterUsername']}@{e['Address']}:{e['Port']}/{db}?sslmode=require"

def postgres_password(auth, name) -> str:
    'Read the RDS-managed master password out of Secrets Manager.'
    i = auth.client('rds').describe_db_instances(DBInstanceIdentifier=name)['DBInstances'][0]
    arn = i.get('MasterUserSecret', {}).get('SecretArn')
    if not arn: raise ValueError(f'{name} has no RDS-managed master secret')
    v = auth.client('secretsmanager').get_secret_value(SecretId=arn)['SecretString']
    return json.loads(v)['password']

def postgres_iam_token(auth, name, user, db='postgres') -> str:
    'A 15-minute IAM auth token to use as the password — no stored credential at all.'
    i = auth.client('rds').describe_db_instances(DBInstanceIdentifier=name)['DBInstances'][0]
    return auth.client('rds').generate_db_auth_token(
        DBHostname=i['Endpoint']['Address'], Port=i['Endpoint']['Port'], DBUsername=user)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    key = create_kms_key(auth, 'db-key')
    db = create_postgres(auth, 'app-db', kms_key_id=key['Arn'], **HIPAA)

    assert db['StorageEncrypted'] is True and db['KmsKeyId'] == key['Arn']
    assert db['PubliclyAccessible'] is False, 'an RDS instance must never be reachable from the internet'
    assert db['IAMDatabaseAuthenticationEnabled'] is True
    assert db['MultiAZ'] is True and db['DeletionProtection'] is True
    assert db['BackupRetentionPeriod'] == 35, 'HIPAA sets a 35-day retention window'
    assert 'postgresql' in db.get('EnabledCloudwatchLogsExports', [])

    # the master password is held by RDS in Secrets Manager and is never returned by create_postgres
    assert 'MasterUserPassword' not in db
    assert db['MasterUserSecret']['SecretArn'].startswith('arn:aws:secretsmanager:')
    assert isinstance(postgres_password(auth, 'app-db'), str)

    conn = postgres_conn(auth, 'app-db')
    assert conn.startswith('postgresql://pgadmin@') and 'sslmode=require' in conn
    assert ':pgadmin@' not in conn.replace('postgresql://pgadmin@', '')   # no password in the URL

    assert create_postgres(auth, 'app-db')['DBInstanceIdentifier'] == 'app-db'   # idempotent
    print(conn)

# %% md
# ## ElastiCache Redis
#
# Encryption in transit and at rest are both on, and an AUTH token is generated and stored in
# Secrets Manager under `elasticache/<name>/auth-token`. `redis_conn` returns a `rediss://`
# URL — the extra `s` is TLS, and connecting without it will simply fail rather than silently
# downgrade.

# %% export
def create_redis(auth, name, node_type='cache.t4g.micro', num_shards=1, replicas=0,
                 engine_version='7.1', kms_key_id=None, subnet_group=None, sg_ids=None,
                 multi_az=False, backup_retention=0, tags=None, **compliance_opts) -> dict:
    'Create an encrypted ElastiCache Redis replication group; the AUTH token goes to Secrets Manager.'
    c = auth.client('elasticache')
    if multi_az: replicas = max(replicas, 1)      # automatic failover needs at least one replica
    token = secrets.token_urlsafe(32)
    kw = dict(ReplicationGroupId=name, ReplicationGroupDescription=name, CacheNodeType=node_type,
              Engine='redis', EngineVersion=engine_version, NumNodeGroups=num_shards,
              ReplicasPerNodeGroup=replicas, TransitEncryptionEnabled=True,
              AtRestEncryptionEnabled=True, AuthToken=token,
              AutomaticFailoverEnabled=bool(replicas), MultiAZEnabled=multi_az,
              SnapshotRetentionLimit=backup_retention, Tags=tag_list(named(name, tags)))
    if kms_key_id: kw['KmsKeyId'] = kms_key_id
    if subnet_group: kw['CacheSubnetGroupName'] = subnet_group
    if sg_ids: kw['SecurityGroupIds'] = sg_ids
    try:
        rg = c.create_replication_group(**kw)['ReplicationGroup']
    except c.exceptions.ReplicationGroupAlreadyExistsFault:
        return c.describe_replication_groups(ReplicationGroupId=name)['ReplicationGroups'][0]
    create_secret(auth, f'elasticache/{name}/auth-token', token, kms_key_id=kms_key_id,
                  description=f'ElastiCache AUTH token for {name}')
    return rg

def redis_auth_token(auth, name) -> str:
    'The AUTH token for a cluster created by `create_redis`.'
    return get_secret(auth, f'elasticache/{name}/auth-token')

def redis_conn(auth, name) -> str:
    'A rediss:// URL for the primary endpoint. TLS-only; there is no plaintext variant.'
    rg = auth.client('elasticache').describe_replication_groups(
        ReplicationGroupId=name)['ReplicationGroups'][0]
    ng = rg['NodeGroups'][0]
    ep = ng.get('PrimaryEndpoint') or ng['NodeGroupMembers'][0]['ReadEndpoint']
    return f"rediss://{ep['Address']}:{ep['Port']}"

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    rg = create_redis(auth, 'app-cache', **ISO27001)
    assert rg['TransitEncryptionEnabled'] is True and rg['AtRestEncryptionEnabled'] is True

    # the token is generated once, handed to ElastiCache, and stored — never printed or returned
    token = redis_auth_token(auth, 'app-cache')
    assert isinstance(token, str) and len(token) >= 32
    assert redis_auth_token(auth, 'app-cache') == token

    assert redis_conn(auth, 'app-cache').startswith('rediss://'), 'plaintext redis:// is not offered'
    assert create_redis(auth, 'app-cache')['ReplicationGroupId'] == 'app-cache'   # idempotent
    print(redis_conn(auth, 'app-cache'))

# %% code
with mock_aws():
    # multi_az implies a replica: automatic failover with zero replicas is a silent no-op on AWS
    auth = AWSAuth(region='us-east-1')
    rg = create_redis(auth, 'ha-cache', multi_az=True)
    assert rg['AutomaticFailover'] in ('enabled', 'enabling'), rg['AutomaticFailover']
    assert len(rg['NodeGroups'][0]['NodeGroupMembers']) == 2
    print('multi-AZ Redis OK')

# %% hide
import nbdev; nbdev.nbdev_export()
