"""Unit tests for awseasy.data — S3, DynamoDB, RDS, ElastiCache using moto."""

import boto3
from moto import mock_aws

from awseasy.data import (
    bucket_conn,
    bucket_url,
    create_bucket,
    create_postgres,
    create_redis,
    create_table,
    dynamo_conn,
    postgres_conn,
    presigned_url,
    table_resource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth(region='us-east-1'):
    """Return a lightweight auth mock backed by a real moto session."""
    session = boto3.Session(
        aws_access_key_id='testing',
        aws_secret_access_key='testing',
        aws_session_token='testing',
        region_name=region,
    )

    class _Auth:
        pass

    auth = _Auth()
    auth.session = session
    auth.region = region
    auth.account_id = '123456789012'
    return auth


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

@mock_aws
def test_create_bucket_basic():
    auth = _auth()
    result = create_bucket(auth, 'test-bucket')
    assert result['BucketName'] == 'test-bucket'
    assert result['Region'] == 'us-east-1'


@mock_aws
def test_create_bucket_idempotent():
    auth = _auth()
    create_bucket(auth, 'test-bucket')
    # second call should not raise
    result = create_bucket(auth, 'test-bucket')
    assert result['BucketName'] == 'test-bucket'


@mock_aws
def test_create_bucket_non_us_east():
    auth = _auth('eu-west-1')
    result = create_bucket(auth, 'eu-bucket')
    assert result['Region'] == 'eu-west-1'


def test_bucket_url():
    assert bucket_url('my-bucket', 'path/file.txt') == 's3://my-bucket/path/file.txt'


def test_bucket_conn():
    assert bucket_conn('my-bucket') == 'my-bucket'


@mock_aws
def test_presigned_url_returns_string():
    auth = _auth()
    create_bucket(auth, 'presign-bucket')
    url = presigned_url(auth, 'presign-bucket', 'doc.pdf', hours=2)
    assert url.startswith('https://')


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

@mock_aws
def test_create_table_basic():
    auth = _auth()
    result = create_table(auth, 'test-table', partition_key='id')
    assert result['TableName'] == 'test-table'


@mock_aws
def test_create_table_with_sort_key():
    auth = _auth()
    result = create_table(auth, 'test-table', partition_key='pk', sort_key='sk')
    assert result['TableName'] == 'test-table'


@mock_aws
def test_create_table_idempotent():
    auth = _auth()
    create_table(auth, 'test-table', partition_key='id')
    result = create_table(auth, 'test-table', partition_key='id')
    assert result['TableName'] == 'test-table'


@mock_aws
def test_dynamo_conn():
    auth = _auth()
    assert dynamo_conn(auth, 'my-table') == 'my-table'


@mock_aws
def test_table_resource():
    auth = _auth()
    create_table(auth, 'test-table', partition_key='id')
    table = table_resource(auth, 'test-table')
    assert table.name == 'test-table'


# ---------------------------------------------------------------------------
# RDS PostgreSQL
# ---------------------------------------------------------------------------

@mock_aws
def test_create_postgres_basic():
    auth = _auth()
    result = create_postgres(auth, 'test-db')
    assert result['DBInstanceIdentifier'] == 'test-db'
    assert result['StorageEncrypted'] is True
    # secret stored
    assert 'MasterSecretArn' in result


@mock_aws
def test_create_postgres_hipaa_opts():
    from awseasy.core import HIPAA
    auth = _auth()
    result = create_postgres(auth, 'hipaa-db', **HIPAA)
    assert result['DBInstanceIdentifier'] == 'hipaa-db'
    assert result['BackupRetentionPeriod'] == 35


@mock_aws
def test_create_postgres_idempotent():
    auth = _auth()
    create_postgres(auth, 'test-db')
    result = create_postgres(auth, 'test-db')
    assert result['DBInstanceIdentifier'] == 'test-db'


@mock_aws
def test_postgres_conn_format():
    auth = _auth()
    create_postgres(auth, 'test-db')
    conn = postgres_conn(auth, 'test-db')
    assert conn.startswith('postgresql://')
    assert 'pgadmin' in conn


# ---------------------------------------------------------------------------
# ElastiCache Redis
# ---------------------------------------------------------------------------

@mock_aws
def test_create_redis_basic():
    auth = _auth()
    result = create_redis(auth, 'test-redis')
    assert result['ReplicationGroupId'] == 'test-redis'
    assert result['TransitEncryptionEnabled'] is True
    assert result['AtRestEncryptionEnabled'] is True


@mock_aws
def test_create_redis_hipaa_multi_az():
    from awseasy.core import HIPAA
    auth = _auth()
    # moto doesn't validate ReplicasPerNodeGroup deeply, just check no exception
    result = create_redis(auth, 'ha-redis', **HIPAA)
    assert result['ReplicationGroupId'] == 'ha-redis'


@mock_aws
def test_create_redis_idempotent():
    auth = _auth()
    create_redis(auth, 'test-redis')
    result = create_redis(auth, 'test-redis')
    assert result['ReplicationGroupId'] == 'test-redis'
