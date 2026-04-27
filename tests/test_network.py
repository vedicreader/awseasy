"""Unit tests for awseasy.network — VPC, SG, IAM, Secrets Manager using moto."""

import json

import boto3
from moto import mock_aws

from awseasy.network import (
    add_subnet,
    attach_policy,
    create_role,
    create_secret,
    create_security_group,
    create_vpc,
    get_secret,
    role_arn,
    secret_arn,
    sg_rule,
    update_secret,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth(region='us-east-1'):
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
# VPC / Subnet / Security Group
# ---------------------------------------------------------------------------

@mock_aws
def test_create_vpc_basic():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    assert 'VpcId' in vpc
    assert vpc['CidrBlock'] == '10.0.0.0/16'


@mock_aws
def test_create_vpc_idempotent():
    auth = _auth()
    vpc1 = create_vpc(auth, 'test-vpc')
    vpc2 = create_vpc(auth, 'test-vpc')
    assert vpc1['VpcId'] == vpc2['VpcId']


@mock_aws
def test_add_subnet_basic():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    subnet = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', az='us-east-1a')
    assert 'SubnetId' in subnet
    assert subnet['CidrBlock'] == '10.0.1.0/24'


@mock_aws
def test_add_subnet_idempotent():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    s1 = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', az='us-east-1a')
    s2 = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', az='us-east-1a')
    assert s1['SubnetId'] == s2['SubnetId']


@mock_aws
def test_create_security_group_basic():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    sg = create_security_group(auth, 'web-sg', vpc['VpcId'])
    assert 'GroupId' in sg
    assert sg['GroupName'] == 'web-sg'


@mock_aws
def test_create_security_group_idempotent():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    sg1 = create_security_group(auth, 'web-sg', vpc['VpcId'])
    sg2 = create_security_group(auth, 'web-sg', vpc['VpcId'])
    assert sg1['GroupId'] == sg2['GroupId']


@mock_aws
def test_sg_rule_idempotent():
    auth = _auth()
    vpc = create_vpc(auth, 'test-vpc')
    sg = create_security_group(auth, 'web-sg', vpc['VpcId'])
    sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 443)
    # second call must not raise
    sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 443)


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------

@mock_aws
def test_create_secret_basic():
    auth = _auth()
    result = create_secret(auth, 'test/secret', 'my-value')
    assert 'ARN' in result or 'Name' in result


@mock_aws
def test_create_secret_idempotent():
    auth = _auth()
    create_secret(auth, 'test/secret', 'val1')
    create_secret(auth, 'test/secret', 'val2')
    # second call should not raise; value updated
    assert get_secret(auth, 'test/secret') == 'val2'


@mock_aws
def test_get_secret():
    auth = _auth()
    create_secret(auth, 'test/key', 'hello')
    assert get_secret(auth, 'test/key') == 'hello'


@mock_aws
def test_update_secret():
    auth = _auth()
    create_secret(auth, 'test/key', 'original')
    update_secret(auth, 'test/key', 'updated')
    assert get_secret(auth, 'test/key') == 'updated'


@mock_aws
def test_secret_arn():
    auth = _auth()
    create_secret(auth, 'test/key', 'value')
    arn = secret_arn(auth, 'test/key')
    assert 'secretsmanager' in arn


# ---------------------------------------------------------------------------
# IAM roles
# ---------------------------------------------------------------------------

@mock_aws
def test_create_role_basic():
    auth = _auth()
    result = create_role(auth, 'test-role', service='ec2.amazonaws.com')
    assert 'Role' in result
    assert result['Role']['RoleName'] == 'test-role'


@mock_aws
def test_create_role_idempotent():
    auth = _auth()
    r1 = create_role(auth, 'test-role', service='ec2.amazonaws.com')
    r2 = create_role(auth, 'test-role', service='ec2.amazonaws.com')
    assert r1['Role']['Arn'] == r2['Role']['Arn']


@mock_aws
def test_create_role_normalized_return():
    """Both new and existing roles must return {'Role': {...}} with no ResponseMetadata."""
    auth = _auth()
    r1 = create_role(auth, 'norm-role', service='ec2.amazonaws.com')
    assert set(r1.keys()) == {'Role'}
    r2 = create_role(auth, 'norm-role', service='ec2.amazonaws.com')
    assert set(r2.keys()) == {'Role'}


@mock_aws
def test_attach_policy():
    auth = _auth()
    # create a customer managed policy first (moto doesn't pre-seed AWS managed policies)
    iam = boto3.client('iam', region_name='us-east-1',
                       aws_access_key_id='testing',
                       aws_secret_access_key='testing',
                       aws_session_token='testing')
    policy = iam.create_policy(
        PolicyName='TestPolicy',
        PolicyDocument=json.dumps({'Version': '2012-10-17',
                                   'Statement': [{'Effect': 'Allow',
                                                  'Action': 's3:GetObject',
                                                  'Resource': '*'}]}),
    )
    create_role(auth, 'test-role', service='lambda.amazonaws.com')
    # should not raise
    attach_policy(auth, 'test-role', policy['Policy']['Arn'])


@mock_aws
def test_role_arn():
    auth = _auth()
    create_role(auth, 'test-role', service='ec2.amazonaws.com')
    arn = role_arn(auth, 'test-role')
    assert 'arn:aws:iam' in arn
    assert 'test-role' in arn
