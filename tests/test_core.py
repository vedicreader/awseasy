"""Unit tests for awseasy.core — compliance profiles, AWSAuth, resource groups, _resource_id."""

from unittest.mock import MagicMock, patch

from awseasy.core import (
    HIPAA,
    ISO27001,
    SOC2,
    AWSAuth,
    _bedrock_trust_policy,
    _resource_id,
    delete_resource_group,
    list_resource_groups,
    resource_group,
)

# ---------------------------------------------------------------------------
# Compliance profiles
# ---------------------------------------------------------------------------

def test_hipaa_keys():
    assert HIPAA['encryption'] is True
    assert HIPAA['tls_min'] == '1.2'
    assert HIPAA['multi_az'] is True
    assert HIPAA['backup_retention'] == 35
    assert HIPAA['deletion_protection'] is True
    assert HIPAA['tags']['compliance'] == 'hipaa'


def test_iso27001_keys():
    assert ISO27001['encryption'] is True
    assert ISO27001['tls_min'] == '1.2'
    assert ISO27001['audit'] is True
    assert ISO27001['tags']['compliance'] == 'iso27001'


def test_soc2_keys():
    assert SOC2['encryption'] is True
    assert SOC2['tls_min'] == '1.2'
    assert SOC2['backup_retention'] == 7
    assert SOC2['tags']['compliance'] == 'soc2'


# ---------------------------------------------------------------------------
# _resource_id
# ---------------------------------------------------------------------------

def test_resource_id_simple_keys():
    assert _resource_id({'knowledgeBaseId': 'KB123'}) == 'KB123'
    assert _resource_id({'BucketName': 'my-bucket'}) == 'my-bucket'
    assert _resource_id({'ARN': 'arn:aws:s3:::x'}) == 'arn:aws:s3:::x'
    assert _resource_id({'Name': 'foo'}) == 'foo'


def test_resource_id_nested_role():
    v = {'Role': {'Arn': 'arn:aws:iam::123:role/x'}}
    assert _resource_id(v) == 'arn:aws:iam::123:role/x'


def test_resource_id_string_fallback():
    assert _resource_id('plain') == 'plain'
    assert _resource_id(42) == '42'


# ---------------------------------------------------------------------------
# _bedrock_trust_policy
# ---------------------------------------------------------------------------

def test_bedrock_trust_policy_structure():
    policy = _bedrock_trust_policy('123456789012')
    assert policy['Version'] == '2012-10-17'
    stmt = policy['Statement'][0]
    assert stmt['Effect'] == 'Allow'
    assert stmt['Principal']['Service'] == 'bedrock.amazonaws.com'
    assert stmt['Condition']['StringEquals']['aws:SourceAccount'] == '123456789012'


# ---------------------------------------------------------------------------
# AWSAuth (mocked STS)
# ---------------------------------------------------------------------------

def _make_auth(region='us-east-1'):
    """Return an AWSAuth with mocked boto3 session."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    mock_session.client.return_value = mock_sts
    mock_session.region_name = region

    with patch('boto3.Session', return_value=mock_session):
        auth = AWSAuth(region=region)
    return auth


def test_awsauth_region_and_account():
    auth = _make_auth('eu-west-1')
    assert auth.region == 'eu-west-1'
    assert auth.account_id == '123456789012'


# ---------------------------------------------------------------------------
# resource_group (mocked client)
# ---------------------------------------------------------------------------

def _rg_auth():
    auth = MagicMock()
    return auth


def test_resource_group_creates_new():
    auth = _rg_auth()
    client = MagicMock()

    class FakeNotFound(Exception):
        pass

    # Wire the client so the except clause catches correctly
    client.exceptions.NotFoundException = FakeNotFound
    client.update_group.side_effect = FakeNotFound('not found')
    client.create_group.return_value = {'Group': {'GroupName': 'test-rg'}}
    auth.session.client.return_value = client

    result = resource_group(auth, 'test-rg', tags={'env': 'prod'})
    assert result == {'GroupName': 'test-rg'}
    client.create_group.assert_called_once()


def test_resource_group_updates_existing():
    auth = _rg_auth()
    client = MagicMock()
    client.update_group.return_value = {'Group': {'GroupName': 'test-rg'}}
    auth.session.client.return_value = client

    result = resource_group(auth, 'test-rg')
    assert result['GroupName'] == 'test-rg'
    client.update_group.assert_called_once()
    client.create_group.assert_not_called()


def test_list_resource_groups():
    auth = _rg_auth()
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {'GroupIdentifiers': [{'GroupName': 'a'}, {'GroupName': 'b'}]}
    ]
    client.get_paginator.return_value = paginator
    auth.session.client.return_value = client

    groups = list_resource_groups(auth)
    assert len(groups) == 2
    assert groups[0]['GroupName'] == 'a'


def test_delete_resource_group():
    auth = _rg_auth()
    client = MagicMock()
    auth.session.client.return_value = client

    delete_resource_group(auth, 'test-rg')
    client.delete_group.assert_called_once_with(GroupName='test-rg')
