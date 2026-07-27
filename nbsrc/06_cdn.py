# %% md
# # cdn
# > CloudFront distributions, AWS WAF, ACM certificates, and Route 53 aliases — the public edge of a GenAI app.

# %% md
#
# This is the AWS-native replacement for putting a third-party CDN in front of the stack: origin
# access control instead of a public bucket, a managed WAF rule set instead of hand-written
# filters, and ACM certificates that renew themselves.

# %% code
#| default_exp cdn

# %% hide
from nbdev.showdoc import *

# %% export
import json, time
from fastcore.all import L, first
from awseasy.core import tag_list

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from botocore.stub import ANY, Stubber
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2
from awseasy.data import create_bucket

def stub_auth(region='us-east-1'):
    'AWSAuth with its identity pre-seeded, for use with botocore Stubber.'
    a = AWSAuth(region=region)
    a._ident = {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/test'}
    return a

# %% md
# ## Certificates
#
# **A certificate for CloudFront must live in us-east-1**, whatever region the rest of the stack
# runs in — a cert requested in eu-west-1 simply cannot be attached to a distribution, and the
# error arrives late. `request_cert` defaults to us-east-1 for that reason; pass `region=` when
# the certificate is for a regional ALB instead.
#
# DNS validation is the default because it renews automatically. Email validation needs a human
# every 13 months.

# %% export
CF_HOSTED_ZONE = 'Z2FDTNDATAQYW2'   # fixed, global: every CloudFront alias target uses this

def request_cert(auth, domain, alt_names=None, region='us-east-1', validation='DNS',
                 tags=None) -> str:
    'Request an ACM certificate and return its ARN. Defaults to us-east-1, as CloudFront requires.'
    kw = dict(DomainName=domain, ValidationMethod=validation,
              Options={'CertificateTransparencyLoggingPreference': 'ENABLED'},
              Tags=tag_list(tags) or [{'Key': 'Name', 'Value': domain}])
    if alt_names: kw['SubjectAlternativeNames'] = list(alt_names)
    return auth.client('acm', region=region).request_certificate(**kw)['CertificateArn']

def cert_validation_records(auth, cert_arn, region='us-east-1') -> list:
    'CNAME records to publish so ACM can validate the certificate. Empty until ACM populates them.'
    c = auth.client('acm', region=region).describe_certificate(CertificateArn=cert_arn)['Certificate']
    return [v['ResourceRecord'] for v in c.get('DomainValidationOptions', [])
            if v.get('ResourceRecord')]

def cert_status(auth, cert_arn, region='us-east-1') -> str:
    'PENDING_VALIDATION, ISSUED, FAILED, ...'
    return auth.client('acm', region=region).describe_certificate(
        CertificateArn=cert_arn)['Certificate']['Status']

# %% code
with mock_aws():
    auth = AWSAuth(region='eu-west-1')
    arn = request_cert(auth, 'app.example.com', alt_names=['www.example.com'])
    # the stack is in eu-west-1, but a CloudFront certificate has to be in us-east-1
    assert ':us-east-1:' in arn, arn
    assert cert_status(auth, arn) in ('PENDING_VALIDATION', 'ISSUED')

    regional = request_cert(auth, 'api.example.com', region='eu-west-1')
    assert ':eu-west-1:' in regional
    print(arn)

# %% md
# ## Origin access control
#
# The wrong way to serve a bucket through CloudFront is to make the bucket public: the origin
# stays reachable directly, so the WAF, the logging, and the TLS policy at the edge can all be
# bypassed by requesting the S3 URL.
#
# Origin access control is the right way. CloudFront signs each origin request with SigV4, and the
# bucket policy grants access only to that one distribution — the bucket stays fully private.
# `s3_oac_policy` merges its statement into whatever policy is already on the bucket, so the
# TLS-only policy written by `create_bucket` survives.

# %% export
def create_oac(auth, name, kind='s3') -> str:
    'Create (or find) an origin access control and return its id.'
    c = auth.client('cloudfront', region='us-east-1')
    found = first(o for o in c.list_origin_access_controls().get(
        'OriginAccessControlList', {}).get('Items', []) if o['Name'] == name)
    if found: return found['Id']
    return c.create_origin_access_control(OriginAccessControlConfig={
        'Name': name, 'Description': f'awseasy OAC for {name}',
        'SigningProtocol': 'sigv4', 'SigningBehavior': 'always',
        'OriginAccessControlOriginType': kind})['OriginAccessControl']['Id']

def s3_oac_policy(auth, bucket, distribution_arn, sid='AllowCloudFrontOAC'):
    'Let one CloudFront distribution — and nothing else — read the bucket. Merges with any existing policy.'
    s3 = auth.client('s3')
    try: policy = json.loads(s3.get_bucket_policy(Bucket=bucket)['Policy'])
    except s3.exceptions.ClientError: policy = {'Version': '2012-10-17', 'Statement': []}
    stmt = {'Sid': sid, 'Effect': 'Allow',
            'Principal': {'Service': 'cloudfront.amazonaws.com'},
            'Action': 's3:GetObject',
            'Resource': f"{auth.arn_for('s3', bucket, region='', account=False)}/*",
            'Condition': {'StringEquals': {'AWS:SourceArn': distribution_arn}}}
    policy['Statement'] = [s for s in policy['Statement'] if s.get('Sid') != sid] + [stmt]
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return policy

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    oac = create_oac(auth, 'docs-oac')
    assert create_oac(auth, 'docs-oac') == oac         # idempotent

    create_bucket(auth, 'site-bucket')                 # already carries the TLS-only policy
    dist_arn = 'arn:aws:cloudfront::123456789012:distribution/E123'
    pol = s3_oac_policy(auth, 'site-bucket', dist_arn)
    sids = {s['Sid']: s for s in pol['Statement']}

    # the TLS-only deny statements survive the merge
    assert {'DenyInsecureTransport', 'DenyOutdatedTLS', 'AllowCloudFrontOAC'} == set(sids)
    grant = sids['AllowCloudFrontOAC']
    assert grant['Principal'] == {'Service': 'cloudfront.amazonaws.com'}
    # scoped to one distribution: another account's CloudFront cannot read this bucket
    assert grant['Condition']['StringEquals']['AWS:SourceArn'] == dist_arn
    assert grant['Action'] == 's3:GetObject', 'read-only; CloudFront never writes to the origin'

    # re-running replaces its own statement instead of stacking duplicates
    pol = s3_oac_policy(auth, 'site-bucket', dist_arn)
    assert len([s for s in pol['Statement'] if s['Sid'] == 'AllowCloudFrontOAC']) == 1

    # the bucket itself is still fully private
    pab = auth.client('s3').get_public_access_block(
        Bucket='site-bucket')['PublicAccessBlockConfiguration']
    assert all(pab.values())
    print(json.dumps(grant, indent=1))

# %% md
# ## Security headers
#
# A response headers policy applies HSTS, `X-Content-Type-Options`, frame denial, and a referrer
# policy at the edge, so every response carries them regardless of what the origin returns.
# Pass `csp=` to add a Content-Security-Policy.

# %% export
def security_headers_policy(auth, name, csp=None, hsts_seconds=63072000,
                            frame_option='DENY', referrer='strict-origin-when-cross-origin') -> str:
    'Create a response headers policy with the standard security headers. Returns its id.'
    c = auth.client('cloudfront', region='us-east-1')
    found = first(p for p in c.list_response_headers_policies().get(
        'ResponseHeadersPolicyList', {}).get('Items', [])
        if p['ResponseHeadersPolicy']['ResponseHeadersPolicyConfig']['Name'] == name)
    if found: return found['ResponseHeadersPolicy']['Id']
    sec = {
        'StrictTransportSecurity': {'Override': True, 'AccessControlMaxAgeSec': hsts_seconds,
                                    'IncludeSubdomains': True, 'Preload': True},
        'ContentTypeOptions': {'Override': True},
        'FrameOptions': {'Override': True, 'FrameOption': frame_option},
        'ReferrerPolicy': {'Override': True, 'ReferrerPolicy': referrer},
        'XSSProtection': {'Override': True, 'Protection': True, 'ModeBlock': True}}
    if csp: sec['ContentSecurityPolicy'] = {'Override': True, 'ContentSecurityPolicy': csp}
    return c.create_response_headers_policy(ResponseHeadersPolicyConfig={
        'Name': name, 'Comment': f'awseasy security headers for {name}',
        'SecurityHeadersConfig': sec})['ResponseHeadersPolicy']['Id']

# %% code
from datetime import datetime

RHP_REPLY = {'ResponseHeadersPolicy': {
    'Id': 'RHP123', 'LastModifiedTime': datetime(2026, 1, 1),
    'ResponseHeadersPolicyConfig': {'Name': 'app-headers'}}}
EMPTY_LIST = {'ResponseHeadersPolicyList': {'MaxItems': 100, 'Quantity': 0, 'Items': []}}

# Stubber validates the request we send, so the expected config below *is* the assertion:
# two-year HSTS including subdomains, frame denial, and nosniff on every response.
EXPECTED = {'ResponseHeadersPolicyConfig': {
    'Name': 'app-headers', 'Comment': ANY,
    'SecurityHeadersConfig': {
        'StrictTransportSecurity': {'Override': True, 'AccessControlMaxAgeSec': 63072000,
                                    'IncludeSubdomains': True, 'Preload': True},
        'ContentTypeOptions': {'Override': True},
        'FrameOptions': {'Override': True, 'FrameOption': 'DENY'},
        'ReferrerPolicy': {'Override': True, 'ReferrerPolicy': 'strict-origin-when-cross-origin'},
        'XSSProtection': {'Override': True, 'Protection': True, 'ModeBlock': True},
        'ContentSecurityPolicy': {'Override': True, 'ContentSecurityPolicy': "default-src 'self'"}}}}

auth = stub_auth()
with Stubber(auth.client('cloudfront', region='us-east-1')) as stub:
    stub.add_response('list_response_headers_policies', EMPTY_LIST, {})
    stub.add_response('create_response_headers_policy', RHP_REPLY, EXPECTED)
    assert security_headers_policy(auth, 'app-headers', csp="default-src 'self'") == 'RHP123'
    stub.assert_no_pending_responses()

# an existing policy of the same name is reused instead of duplicated
auth = stub_auth()
with Stubber(auth.client('cloudfront', region='us-east-1')) as stub:
    stub.add_response('list_response_headers_policies', {'ResponseHeadersPolicyList': {
        'MaxItems': 100, 'Quantity': 1,
        'Items': [{'Type': 'custom', **RHP_REPLY}]}}, {})
    assert security_headers_policy(auth, 'app-headers') == 'RHP123'
    stub.assert_no_pending_responses()
print('security headers OK')

# %% md
# ## AWS WAF
#
# `create_waf` applies AWS-managed rule groups — the common rule set, known-bad inputs, the
# Amazon IP reputation list, and SQL injection — plus a rate-based rule that blocks any single IP
# exceeding `rate_limit` requests in five minutes. For a GenAI app the rate rule matters as much
# as the injection rules: unmetered inference is a direct financial risk, not just an availability one.
#
# A `CLOUDFRONT`-scoped web ACL must be created in us-east-1; `REGIONAL` is for ALBs and API Gateway.

# %% export
MANAGED_RULES = ['AWSManagedRulesCommonRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet',
                 'AWSManagedRulesAmazonIpReputationList', 'AWSManagedRulesSQLiRuleSet']

def _vis(name): return {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
                        'MetricName': name.replace('_', '-')}

def waf_rules(managed_rules=None, rate_limit=2000) -> list:
    'Managed rule groups plus a rate-based rule, numbered in priority order.'
    rules = [{'Name': r, 'Priority': i,
              'Statement': {'ManagedRuleGroupStatement': {'VendorName': 'AWS', 'Name': r}},
              'OverrideAction': {'None': {}}, 'VisibilityConfig': _vis(r)}
             for i, r in enumerate(managed_rules if managed_rules is not None else MANAGED_RULES)]
    if rate_limit:
        rules.append({'Name': 'RateLimit', 'Priority': len(rules),
                      'Statement': {'RateBasedStatement': {'Limit': rate_limit,
                                                           'AggregateKeyType': 'IP'}},
                      'Action': {'Block': {}}, 'VisibilityConfig': _vis('RateLimit')})
    return rules

def create_waf(auth, name, scope='CLOUDFRONT', managed_rules=None, rate_limit=2000,
               tags=None) -> dict:
    'Create a web ACL with AWS managed rule groups and per-IP rate limiting. Idempotent by name.'
    region = 'us-east-1' if scope == 'CLOUDFRONT' else auth.region
    c = auth.client('wafv2', region=region)
    found = first(w for w in c.list_web_acls(Scope=scope)['WebACLs'] if w['Name'] == name)
    if found: return found
    kw = dict(Name=name, Scope=scope, DefaultAction={'Allow': {}},
              Description=f'awseasy web ACL for {name}',
              Rules=waf_rules(managed_rules, rate_limit), VisibilityConfig=_vis(name))
    if tags: kw['Tags'] = tag_list(tags)   # wafv2 rejects an empty tag list
    return c.create_web_acl(**kw)['Summary']

# %% code
rules = waf_rules()
names = [r['Name'] for r in rules]
assert names[:-1] == MANAGED_RULES and names[-1] == 'RateLimit'
assert [r['Priority'] for r in rules] == list(range(len(rules))), 'priorities must be unique and ordered'
# managed groups only count/override; the rate rule actively blocks
assert all('OverrideAction' in r for r in rules[:-1])
assert rules[-1]['Action'] == {'Block': {}}
assert rules[-1]['Statement']['RateBasedStatement'] == {'Limit': 2000, 'AggregateKeyType': 'IP'}
assert all(r['VisibilityConfig']['CloudWatchMetricsEnabled'] for r in rules)
assert len(waf_rules(managed_rules=[], rate_limit=0)) == 0
print([r['Name'] for r in rules])

# %% code
with mock_aws():
    auth = AWSAuth(region='eu-west-1')
    acl = create_waf(auth, 'app-waf')
    # a CLOUDFRONT web ACL is global and lives in us-east-1, whatever region the stack uses
    assert ':us-east-1:' in acl['ARN'] and ':global/' in acl['ARN'], acl['ARN']

    again = create_waf(auth, 'app-waf')
    assert again['ARN'] == acl['ARN']          # idempotent by name

    regional = create_waf(auth, 'alb-waf', scope='REGIONAL', rate_limit=500)
    assert ':eu-west-1:' in regional['ARN'] and ':regional/' in regional['ARN']
    print(acl['ARN'])

# %% md
# ## Distributions
#
# One call builds the distribution, with the pieces that are painful to add afterwards already in
# place: TLS 1.2 as the floor, HTTP/3, IPv6, compression, and an origin reached only over HTTPS.
#
# - `s3_bucket=` gives an S3 origin behind origin access control (created for you unless you pass
#   `oac_id=`); `origin_domain=` gives a custom origin such as an ALB.
# - `domains=` requires `cert_arn=` — an alias without a matching certificate is a distribution
#   that serves TLS errors, so it raises instead.
# - `methods='all'` allows POST/PUT/DELETE, which an API or chat backend needs; the default
#   `'read'` is right for a static site.
#
# `CallerReference` is derived from `name`, so a repeated call returns the existing distribution
# rather than creating a second one.

# %% export
CACHE_OPTIMIZED = '658327ea-f89d-4fab-a63d-7e88639e58f6'   # AWS managed: CachingOptimized
CACHE_DISABLED = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad'    # AWS managed: CachingDisabled
ALL_VIEWER_EXCEPT_HOST = 'b689b0a8-53d0-40ab-baf2-68738e2966ac'   # managed origin request policy
READ_METHODS = ['GET', 'HEAD', 'OPTIONS']
ALL_METHODS = ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE']

def _methods(kind):
    items = ALL_METHODS if kind == 'all' else READ_METHODS
    return {'Quantity': len(items), 'Items': items,
            'CachedMethods': {'Quantity': 2, 'Items': ['GET', 'HEAD']}}

def distribution_config(auth, name, origin_domain=None, s3_bucket=None, oac_id=None, domains=None,
                        cert_arn=None, waf_acl_arn=None, headers_policy_id=None,
                        cache_policy=CACHE_OPTIMIZED, origin_request_policy_id=None,
                        log_bucket=None, price_class='PriceClass_100', methods='read',
                        default_root='index.html', comment=None, **compliance_opts) -> dict:
    'Build the DistributionConfig. Separated out so the security settings can be asserted directly.'
    if bool(origin_domain) == bool(s3_bucket):
        raise ValueError('pass exactly one of origin_domain= or s3_bucket=')
    if domains and not cert_arn:
        raise ValueError('domains= needs cert_arn= (an ACM certificate in us-east-1)')
    origin = {'Id': 'origin-1'}
    if s3_bucket:
        origin['DomainName'] = f'{s3_bucket}.s3.{auth.region}.amazonaws.com'
        origin['S3OriginConfig'] = {'OriginAccessIdentity': ''}
        origin['OriginAccessControlId'] = oac_id
    else:
        origin['DomainName'] = origin_domain
        origin['CustomOriginConfig'] = {
            'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'https-only',
            'OriginSslProtocols': {'Quantity': 1, 'Items': ['TLSv1.2']},
            'OriginReadTimeout': 60, 'OriginKeepaliveTimeout': 5}
    behavior = {'TargetOriginId': 'origin-1', 'ViewerProtocolPolicy': 'redirect-to-https',
                'CachePolicyId': cache_policy, 'AllowedMethods': _methods(methods),
                'Compress': True}
    if headers_policy_id: behavior['ResponseHeadersPolicyId'] = headers_policy_id
    if origin_request_policy_id: behavior['OriginRequestPolicyId'] = origin_request_policy_id
    cfg = {
        'CallerReference': f'awseasy-{name}', 'Comment': comment or name, 'Enabled': True,
        'Origins': {'Quantity': 1, 'Items': [origin]},
        'DefaultCacheBehavior': behavior,
        'HttpVersion': 'http2and3', 'IsIPV6Enabled': True, 'PriceClass': price_class,
        'ViewerCertificate': {'CloudFrontDefaultCertificate': True},
        'Logging': {'Enabled': False, 'IncludeCookies': False, 'Bucket': '', 'Prefix': ''}}
    if default_root: cfg['DefaultRootObject'] = default_root
    if domains:
        cfg['Aliases'] = {'Quantity': len(domains), 'Items': list(domains)}
        cfg['ViewerCertificate'] = {'ACMCertificateArn': cert_arn, 'SSLSupportMethod': 'sni-only',
                                    'MinimumProtocolVersion': 'TLSv1.2_2021',
                                    'CertificateSource': 'acm'}
    if waf_acl_arn: cfg['WebACLId'] = waf_acl_arn
    if log_bucket:
        cfg['Logging'] = {'Enabled': True, 'IncludeCookies': False,
                          'Bucket': f'{log_bucket}.s3.amazonaws.com', 'Prefix': f'{name}/'}
    return cfg

def _find_distribution(client, caller_ref):
    '''Find the distribution holding a CallerReference.

    Only runs on the collision path, so the extra get_distribution per distribution is paid once
    on a re-run rather than on every call. CallerReference is the exact thing that collided, which
    makes it a more reliable key than comparing comments or origin domains.'''
    for s in client.list_distributions()['DistributionList'].get('Items', []):
        d = client.get_distribution(Id=s['Id'])['Distribution']
        if d['DistributionConfig']['CallerReference'] == caller_ref: return d
    raise ValueError(f'CallerReference {caller_ref!r} is in use by a distribution this account '
                     'cannot see; pass a different name')

def create_distribution(auth, name, origin_domain=None, s3_bucket=None, oac_id=None, tags=None,
                        **kw) -> dict:
    'Create a hardened CloudFront distribution. Idempotent by name; wires OAC for S3 origins.'
    c = auth.client('cloudfront', region='us-east-1')
    if s3_bucket and not oac_id: oac_id = create_oac(auth, f'{name}-oac')
    cfg = distribution_config(auth, name, origin_domain=origin_domain, s3_bucket=s3_bucket,
                              oac_id=oac_id, **kw)
    try:
        dist = c.create_distribution_with_tags(DistributionConfigWithTags={
            'DistributionConfig': cfg, 'Tags': {'Items': tag_list(tags)}})['Distribution']
    except c.exceptions.DistributionAlreadyExists:
        dist = _find_distribution(c, cfg['CallerReference'])
    if s3_bucket: s3_oac_policy(auth, s3_bucket, dist['ARN'])
    return dist

def distribution_domain(auth, dist_id) -> str:
    'The *.cloudfront.net domain of a distribution.'
    return auth.client('cloudfront', region='us-east-1').get_distribution(
        Id=dist_id)['Distribution']['DomainName']

def invalidate(auth, dist_id, paths=('/*',)) -> dict:
    'Invalidate cached paths. The first 1,000 paths each month are free.'
    return auth.client('cloudfront', region='us-east-1').create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={'Paths': {'Quantity': len(paths), 'Items': list(paths)},
                           'CallerReference': f'awseasy-{int(time.time() * 1000)}'})['Invalidation']

# %% code
# The config is a pure function of its arguments, so every security setting can be asserted here.
auth = stub_auth()
cfg = distribution_config(auth, 'site', s3_bucket='site-bucket', oac_id='OAC1',
                          domains=['app.example.com'], cert_arn='arn:aws:acm:us-east-1:1:cert/c',
                          waf_acl_arn='arn:aws:wafv2:us-east-1:1:global/webacl/w',
                          headers_policy_id='RHP1', log_bucket='logs-bucket')

assert cfg['ViewerCertificate']['MinimumProtocolVersion'] == 'TLSv1.2_2021'
assert cfg['ViewerCertificate']['ACMCertificateArn'].endswith('cert/c')
assert cfg['DefaultCacheBehavior']['ViewerProtocolPolicy'] == 'redirect-to-https'
assert cfg['Aliases']['Items'] == ['app.example.com']
assert cfg['WebACLId'].endswith('webacl/w')
assert cfg['Logging']['Enabled'] and cfg['Logging']['Bucket'] == 'logs-bucket.s3.amazonaws.com'
assert cfg['HttpVersion'] == 'http2and3' and cfg['IsIPV6Enabled']
assert cfg['DefaultCacheBehavior']['Compress'] and cfg['DefaultCacheBehavior']['ResponseHeadersPolicyId'] == 'RHP1'

# an S3 origin goes through OAC, never a public bucket URL
o = cfg['Origins']['Items'][0]
assert o['OriginAccessControlId'] == 'OAC1' and 'S3OriginConfig' in o
assert o['DomainName'] == 'site-bucket.s3.us-east-1.amazonaws.com'
# read-only methods by default: a static site has no reason to accept POST
assert cfg['DefaultCacheBehavior']['AllowedMethods']['Items'] == READ_METHODS

# a custom origin is reached over HTTPS with TLS 1.2 only — never plaintext back to the ALB
api = distribution_config(auth, 'api', origin_domain='alb.example.com', methods='all',
                          cache_policy=CACHE_DISABLED)
co = api['Origins']['Items'][0]['CustomOriginConfig']
assert co['OriginProtocolPolicy'] == 'https-only'
assert co['OriginSslProtocols']['Items'] == ['TLSv1.2']
assert set(api['DefaultCacheBehavior']['AllowedMethods']['Items']) == set(ALL_METHODS)
print(json.dumps(cfg['ViewerCertificate'], indent=1))

# %% code
auth = stub_auth()
# exactly one origin kind, and no alias without a certificate to serve it
for bad, msg in [(dict(), 'exactly one'),
                 (dict(origin_domain='a.example.com', s3_bucket='b'), 'exactly one'),
                 (dict(s3_bucket='b', domains=['app.example.com']), 'cert_arn')]:
    try: distribution_config(auth, 'x', **bad); raise AssertionError(f'accepted {bad}')
    except ValueError as e: assert msg in str(e), e
print('distribution guards OK')

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    create_bucket(auth, 'site-bucket')
    waf = create_waf(auth, 'site-waf')
    dist = create_distribution(auth, 'site', s3_bucket='site-bucket', waf_acl_arn=waf['ARN'],
                               **SOC2)
    assert dist['DomainName'].endswith('.cloudfront.net')

    # the OAC bucket policy was written as part of provisioning, not as a follow-up step
    pol = json.loads(auth.client('s3').get_bucket_policy(Bucket='site-bucket')['Policy'])
    grant = first(s for s in pol['Statement'] if s['Sid'] == 'AllowCloudFrontOAC')
    assert grant['Condition']['StringEquals']['AWS:SourceArn'] == dist['ARN']

    # idempotent: a repeated call returns the same distribution rather than a second one
    again = create_distribution(auth, 'site', s3_bucket='site-bucket')
    assert again['Id'] == dist['Id']
    assert len(auth.client('cloudfront').list_distributions()['DistributionList']['Items']) == 1

    assert distribution_domain(auth, dist['Id']) == dist['DomainName']
    inv = invalidate(auth, dist['Id'], ['/index.html', '/api/*'])
    assert inv['InvalidationBatch']['Paths']['Quantity'] == 2
    print(dist['Id'], dist['DomainName'])

# %% md
# ## Route 53
#
# An alias record points a domain at CloudFront with no CNAME and no per-query charge, and works
# at the zone apex where a CNAME is not allowed. The target hosted zone id is the same global
# constant for every CloudFront distribution.

# %% export
def alias_record(auth, zone_id, name, target, target_zone=CF_HOSTED_ZONE, kind='A') -> dict:
    'Point a name at CloudFront (or an ALB) with an alias record. Upsert, so it is safe to re-run.'
    return auth.client('route53').change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={'Comment': f'awseasy alias for {name}', 'Changes': [{
            'Action': 'UPSERT',
            'ResourceRecordSet': {'Name': name, 'Type': kind,
                                  'AliasTarget': {'HostedZoneId': target_zone, 'DNSName': target,
                                                  'EvaluateTargetHealth': False}}}]})['ChangeInfo']

def zone_id(auth, domain) -> str:
    'Hosted zone id for a domain.'
    domain = domain if domain.endswith('.') else f'{domain}.'
    z = first(z for z in auth.client('route53').list_hosted_zones()['HostedZones']
              if z['Name'] == domain)
    if not z: raise ValueError(f'no Route 53 hosted zone for {domain!r}')
    return z['Id'].split('/')[-1]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    auth.client('route53').create_hosted_zone(Name='example.com', CallerReference='z1')
    zid = zone_id(auth, 'example.com')

    ch = alias_record(auth, zid, 'app.example.com', 'd111.cloudfront.net')
    assert ch['Status'] in ('PENDING', 'INSYNC')
    # upsert, so re-running the whole provisioning flow does not fail on an existing record
    alias_record(auth, zid, 'app.example.com', 'd111.cloudfront.net')

    rrs = auth.client('route53').list_resource_record_sets(HostedZoneId=zid)['ResourceRecordSets']
    a = first(r for r in rrs if r['Name'].startswith('app.example.com') and r['Type'] == 'A')
    assert a['AliasTarget']['HostedZoneId'] == CF_HOSTED_ZONE
    assert len([r for r in rrs if r['Type'] == 'A']) == 1

    assert zone_id(auth, 'example.com.') == zid
    try: zone_id(auth, 'nope.com'); raise AssertionError('should raise')
    except ValueError as e: assert 'hosted zone' in str(e)
    print(zid, a['AliasTarget']['DNSName'])

# %% md
# ## The whole edge
#
# Certificate, WAF, distribution, and DNS, in the order you would run them. In a real account the
# certificate has to reach `ISSUED` — publish the records from `cert_validation_records()` — before
# the distribution will accept it.

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    create_bucket(auth, 'acme-site', **ISO27001)
    cert = request_cert(auth, 'app.acme.com')
    waf = create_waf(auth, 'acme-waf', rate_limit=1000)
    dist = create_distribution(auth, 'acme', s3_bucket='acme-site', waf_acl_arn=waf['ARN'],
                               log_bucket='acme-logs', **ISO27001)

    auth.client('route53').create_hosted_zone(Name='acme.com', CallerReference='z1')
    alias_record(auth, zone_id(auth, 'acme.com'), 'app.acme.com', dist['DomainName'])
    print(f"https://app.acme.com -> {dist['DomainName']} (waf={waf['ARN'].split('/')[-1]})")

# %% hide
import nbdev; nbdev.nbdev_export()
