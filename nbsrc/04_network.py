# %% md
# # network
# > IAM roles, Secrets Manager, VPCs, security groups, flow logs, VPC endpoints, and load balancers.

# %% code
#| default_exp network

# %% hide
from nbdev.showdoc import *

# %% export
import json
from botocore.exceptions import ClientError
from fastcore.all import L, first
from awseasy.core import named, tag_dict, tag_list

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2

# %% md
# ## IAM roles
#
# Roles only — `awseasy` never creates an IAM user or a long-lived access key. `service=`
# builds the trust policy for you, and `source_account=` adds the `aws:SourceAccount`
# condition that closes the [confused deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
# hole on service-principal trusts.

# %% export
def service_trust(service, source_account=None, source_arn=None) -> dict:
    'Trust policy for an AWS service principal, optionally pinned to one account/resource.'
    stmt = {'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': 'sts:AssumeRole'}
    cond = {}
    if source_account: cond['StringEquals'] = {'aws:SourceAccount': str(source_account)}
    if source_arn:     cond['ArnLike'] = {'aws:SourceArn': source_arn}
    if cond: stmt['Condition'] = cond
    return {'Version': '2012-10-17', 'Statement': [stmt]}

def create_role(auth, name, service=None, trust_policy=None, source_account=None, source_arn=None,
                permissions_boundary=None, max_session=3600, description='', tags=None) -> dict:
    'Create or fetch an IAM role. Give service= for a service principal, or trust_policy= for full control.'
    if trust_policy is None:
        if not service: raise ValueError('pass service= or trust_policy=')
        trust_policy = service_trust(service, source_account, source_arn)
    c = auth.client('iam')
    kw = dict(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy),
              MaxSessionDuration=max_session, Description=description, Tags=tag_list(tags))
    if permissions_boundary: kw['PermissionsBoundary'] = permissions_boundary
    try: return c.create_role(**kw)
    except c.exceptions.EntityAlreadyExistsException:
        c.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust_policy))
        return {'Role': c.get_role(RoleName=name)['Role']}

def put_role_policy(auth, role_name, policy_name, document):
    'Attach an inline least-privilege policy to a role. Replaces any policy of the same name.'
    auth.client('iam').put_role_policy(RoleName=role_name, PolicyName=policy_name,
                                       PolicyDocument=json.dumps(document))

def attach_policy(auth, role_name, policy_arn):
    'Attach a managed policy to a role.'
    auth.client('iam').attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

def role_arn(auth, role_name) -> str:
    'ARN of an IAM role.'
    return auth.client('iam').get_role(RoleName=role_name)['Role']['Arn']

def create_instance_profile(auth, name, role_name=None) -> dict:
    'Create an instance profile and add a role to it, for use as create_instance(iam_instance_profile=...).'
    c = auth.client('iam')
    try: c.create_instance_profile(InstanceProfileName=name)
    except c.exceptions.EntityAlreadyExistsException: pass
    prof = c.get_instance_profile(InstanceProfileName=name)['InstanceProfile']
    if role_name and not any(r['RoleName'] == role_name for r in prof.get('Roles', [])):
        c.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role_name)
    return c.get_instance_profile(InstanceProfileName=name)['InstanceProfile']

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    r = create_role(auth, 'bedrock-role', service='bedrock.amazonaws.com',
                    source_account='123456789012', tags={'env': 'prod'})
    doc = r['Role']['AssumeRolePolicyDocument']
    stmt = (json.loads(doc) if isinstance(doc, str) else doc)['Statement'][0]
    assert stmt['Principal']['Service'] == 'bedrock.amazonaws.com'
    # the confused-deputy guard: another AWS account cannot make Bedrock assume this role
    assert stmt['Condition']['StringEquals']['aws:SourceAccount'] == '123456789012'

    assert create_role(auth, 'bedrock-role', service='bedrock.amazonaws.com')['Role']['Arn'] == r['Role']['Arn']
    try: create_role(auth, 'nope'); raise AssertionError('should raise')
    except ValueError as e: assert 'trust_policy' in str(e)

    put_role_policy(auth, 'bedrock-role', 'least-priv', {
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::b/*'}]})
    assert auth.client('iam').list_role_policies(RoleName='bedrock-role')['PolicyNames'] == ['least-priv']
    assert role_arn(auth, 'bedrock-role').endswith(':role/bedrock-role')

    prof = create_instance_profile(auth, 'bedrock-profile', 'bedrock-role')
    assert prof['Roles'][0]['RoleName'] == 'bedrock-role'
    assert create_instance_profile(auth, 'bedrock-profile', 'bedrock-role')['InstanceProfileName'] == 'bedrock-profile'
    print('IAM roles OK')

# %% md
# ## Secrets Manager
#
# Create-or-update: `create_secret` on a name that already exists stores a new version
# rather than raising, which is what makes re-running `GenAIStack.provision()` safe.

# %% export
def create_secret(auth, name, value, kms_key_id=None, description='', tags=None, **_) -> dict:
    'Create a secret, or store a new version if it already exists. KMS-encrypted when kms_key_id is given.'
    c = auth.client('secretsmanager')
    if not isinstance(value, str): value = json.dumps(value)
    kw = {'Name': name, 'SecretString': value, 'Tags': tag_list(tags), 'Description': description}
    if kms_key_id: kw['KmsKeyId'] = kms_key_id
    try: return c.create_secret(**kw)
    except c.exceptions.ResourceExistsException:
        c.put_secret_value(SecretId=name, SecretString=value)
        return c.describe_secret(SecretId=name)

def get_secret(auth, name):
    'Secret value as a str, or a dict when the stored value is JSON.'
    v = auth.client('secretsmanager').get_secret_value(SecretId=name)['SecretString']
    try: return json.loads(v)
    except (json.JSONDecodeError, TypeError): return v

def update_secret(auth, name, value):
    'Store a new version of an existing secret.'
    if not isinstance(value, str): value = json.dumps(value)
    auth.client('secretsmanager').put_secret_value(SecretId=name, SecretString=value)

def secret_arn(auth, name) -> str:
    'ARN of a secret.'
    return auth.client('secretsmanager').describe_secret(SecretId=name)['ARN']

def delete_secret(auth, name, force=False):
    'Schedule a secret for deletion. force=True deletes immediately with no recovery window.'
    kw = {'ForceDeleteWithoutRecovery': True} if force else {'RecoveryWindowInDays': 30}
    auth.client('secretsmanager').delete_secret(SecretId=name, **kw)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    create_secret(auth, 'myapp/api-key', 'sk-123', tags={'env': 'prod'})
    assert get_secret(auth, 'myapp/api-key') == 'sk-123'

    # create-or-update rather than raise, so provisioning can be re-run
    create_secret(auth, 'myapp/api-key', 'sk-456')
    assert get_secret(auth, 'myapp/api-key') == 'sk-456'
    update_secret(auth, 'myapp/api-key', 'sk-789')
    assert get_secret(auth, 'myapp/api-key') == 'sk-789'
    assert secret_arn(auth, 'myapp/api-key').startswith('arn:aws:secretsmanager:')

    # dicts round-trip as JSON — connection details are usually structured
    create_secret(auth, 'myapp/db', {'user': 'pgadmin', 'port': 5432})
    assert get_secret(auth, 'myapp/db')['port'] == 5432

    delete_secret(auth, 'myapp/api-key', force=True)
    print('secrets OK')

# %% md
# ## VPCs, subnets, and security groups
#
# These are keyed on the `Name` tag (or CIDR, or group name), so calling them twice returns
# the existing resource instead of quietly building a second parallel network — the failure
# mode that makes hand-rolled boto3 scripts dangerous to re-run.

# %% export
def create_vpc(auth, name, cidr='10.0.0.0/16', audit=False, tags=None, **compliance_opts) -> dict:
    'Create a VPC with DNS resolution and hostnames on. Idempotent by Name tag; audit=True adds flow logs.'
    ec2 = auth.client('ec2')
    vpc = first(ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [name]}])['Vpcs'])
    if vpc is None:
        vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
            {'ResourceType': 'vpc', 'Tags': tag_list(named(name, tags))}])['Vpc']
    # Private DNS on a VPC endpoint silently does nothing without both of these.
    ec2.modify_vpc_attribute(VpcId=vpc['VpcId'], EnableDnsSupport={'Value': True})
    ec2.modify_vpc_attribute(VpcId=vpc['VpcId'], EnableDnsHostnames={'Value': True})
    if audit: vpc_flow_logs(auth, vpc['VpcId'], name)
    return vpc

def add_subnet(auth, vpc_id, cidr, az, public=False, name=None, tags=None) -> dict:
    'Add a subnet to a VPC. Idempotent by CIDR. public=True auto-assigns public IPs on launch.'
    ec2 = auth.client('ec2')
    subnet = first(ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},
                                                 {'Name': 'cidr-block', 'Values': [cidr]}])['Subnets'])
    if subnet is None:
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az,
                                   TagSpecifications=[{'ResourceType': 'subnet',
                                                       'Tags': tag_list(named(name or cidr, tags))}])['Subnet']
    ec2.modify_subnet_attribute(SubnetId=subnet['SubnetId'], MapPublicIpOnLaunch={'Value': public})
    return subnet

def create_security_group(auth, name, vpc_id, description=None, tags=None) -> dict:
    'Create a security group. Idempotent by group name within the VPC.'
    ec2 = auth.client('ec2')
    sg = first(ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},
                                                     {'Name': 'group-name', 'Values': [name]}])['SecurityGroups'])
    if sg is not None: return sg
    gid = ec2.create_security_group(GroupName=name, Description=description or name, VpcId=vpc_id,
                                    TagSpecifications=[{'ResourceType': 'security-group',
                                                        'Tags': tag_list(named(name, tags))}])['GroupId']
    return ec2.describe_security_groups(GroupIds=[gid])['SecurityGroups'][0]

def sg_rule(auth, sg_id, direction, protocol, port, cidr=None, source_sg=None, description=''):
    '''Authorize one security group rule. Idempotent.

    Exactly one of `cidr` or `source_sg` must be given — there is deliberately no
    `0.0.0.0/0` default, because a wrong default here is a publicly reachable database.
    `port` is an int or an inclusive `(from, to)` tuple.'''
    if bool(cidr) == bool(source_sg): raise ValueError('pass exactly one of cidr= or source_sg=')
    lo, hi = port if isinstance(port, (tuple, list)) else (port, port)
    perm = {'IpProtocol': protocol, 'FromPort': lo, 'ToPort': hi}
    if cidr: perm['IpRanges'] = [{'CidrIp': cidr, 'Description': description}]
    else:    perm['UserIdGroupPairs'] = [{'GroupId': source_sg, 'Description': description}]
    ec2 = auth.client('ec2')
    fn = f"authorize_security_group_{'ingress' if direction == 'ingress' else 'egress'}"
    try: getattr(ec2, fn)(GroupId=sg_id, IpPermissions=[perm])
    except ClientError as e:
        if e.response['Error']['Code'] != 'InvalidPermission.Duplicate': raise

def vpc_flow_logs(auth, vpc_id, name, retention=90) -> dict:
    'Publish VPC Flow Logs to CloudWatch Logs — the network audit trail ISO 27001 and SOC 2 expect.'
    logs, group = auth.client('logs'), f'/aws/vpc/{name}'
    try: logs.create_log_group(logGroupName=group)
    except logs.exceptions.ResourceAlreadyExistsException: pass
    logs.put_retention_policy(logGroupName=group, retentionInDays=retention)
    role = create_role(auth, f'{name}-flowlogs-role', service='vpc-flow-logs.amazonaws.com')
    put_role_policy(auth, f'{name}-flowlogs-role', 'flowlogs-write', {
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow',
                       'Action': ['logs:CreateLogStream', 'logs:PutLogEvents', 'logs:DescribeLogStreams'],
                       'Resource': auth.arn_for('logs', f'log-group:{group}:*')}]})
    ec2 = auth.client('ec2')
    existing = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])['FlowLogs']
    if existing: return existing[0]
    return ec2.create_flow_logs(ResourceIds=[vpc_id], ResourceType='VPC', TrafficType='ALL',
                                LogDestinationType='cloud-watch-logs', LogGroupName=group,
                                DeliverLogsPermissionArn=role['Role']['Arn'])

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'app-vpc', '10.20.0.0/16')
    assert vpc['CidrBlock'] == '10.20.0.0/16'
    ec2 = auth.client('ec2')
    for a in ('enableDnsSupport', 'enableDnsHostnames'):
        assert ec2.describe_vpc_attribute(VpcId=vpc['VpcId'], Attribute=a)[a[0].upper() + a[1:]]['Value']

    # idempotent by Name tag — the classic "ran the script twice" failure
    assert create_vpc(auth, 'app-vpc')['VpcId'] == vpc['VpcId']
    assert len(ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['app-vpc']}])['Vpcs']) == 1

    sn = add_subnet(auth, vpc['VpcId'], '10.20.1.0/24', 'us-east-1a', public=True, name='public-a')
    public_ip = lambda: ec2.describe_subnets(SubnetIds=[sn['SubnetId']])['Subnets'][0]['MapPublicIpOnLaunch']
    assert public_ip() and tag_dict(sn['Tags'])['Name'] == 'public-a'
    assert add_subnet(auth, vpc['VpcId'], '10.20.1.0/24', 'us-east-1a', public=True)['SubnetId'] == sn['SubnetId']

    # `public` is declarative, not sticky: re-declaring the subnet private makes it private
    add_subnet(auth, vpc['VpcId'], '10.20.1.0/24', 'us-east-1a')
    assert not public_ip()
    print(vpc['VpcId'], sn['SubnetId'])

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'sg-vpc')
    sg = create_security_group(auth, 'web', vpc['VpcId'], 'web tier')
    assert create_security_group(auth, 'web', vpc['VpcId'])['GroupId'] == sg['GroupId']

    app = create_security_group(auth, 'app', vpc['VpcId'])
    sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 443, cidr='10.20.0.0/16')
    sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 443, cidr='10.20.0.0/16')   # duplicate is a no-op
    sg_rule(auth, app['GroupId'], 'ingress', 'tcp', (5432, 5432), source_sg=sg['GroupId'])

    ec2 = auth.client('ec2')
    perms = ec2.describe_security_groups(GroupIds=[sg['GroupId']])['SecurityGroups'][0]['IpPermissions']
    assert len(perms) == 1 and perms[0]['FromPort'] == 443
    app_perms = ec2.describe_security_groups(GroupIds=[app['GroupId']])['SecurityGroups'][0]['IpPermissions']
    assert app_perms[0]['UserIdGroupPairs'][0]['GroupId'] == sg['GroupId'], 'SG-to-SG reference, no CIDR'

    # A rule must name its source explicitly, so there is no way to open one to the world by accident.
    for bad in (dict(), dict(cidr='0.0.0.0/0', source_sg=sg['GroupId'])):
        try: sg_rule(auth, sg['GroupId'], 'ingress', 'tcp', 22, **bad); raise AssertionError('should raise')
        except ValueError as e: assert 'exactly one' in str(e)
    print('security group rules OK')

# %% code
with mock_aws():
    # audit=True wires flow logs, a retention policy, and the delivery role in one step
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'audited-vpc', **ISO27001)
    flows = lambda: auth.client('ec2').describe_flow_logs(
        Filters=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}])['FlowLogs']
    assert len(flows()) == 1 and flows()[0]['TrafficType'] == 'ALL'
    grp = auth.client('logs').describe_log_groups(logGroupNamePrefix='/aws/vpc/audited-vpc')['logGroups'][0]
    assert grp['retentionInDays'] == 90

    create_vpc(auth, 'audited-vpc', **ISO27001)   # re-run must not stack up duplicate flow logs
    assert len(flows()) == 1
    print('VPC flow logs OK')

# %% md
# ## VPC endpoints
#
# Interface and Gateway endpoints keep traffic to Bedrock, S3, and Secrets Manager on the
# AWS backbone instead of the public internet — usually a hard requirement once regulated
# data is in play.

# %% export
INTERFACE_SERVICES = ['bedrock-runtime', 'bedrock-agent-runtime', 'secretsmanager', 'kms',
                      'ecr.api', 'ecr.dkr', 'logs', 'sts']

def create_vpc_endpoint(auth, vpc_id, service, endpoint_type='Interface', subnet_ids=None,
                        sg_ids=None, policy=None, route_table_ids=None) -> dict:
    'Create a VPC endpoint. `service` may be a short name ("bedrock-runtime") or a full service name.'
    if not service.startswith('com.amazonaws.'): service = f'com.amazonaws.{auth.region}.{service}'
    kw = dict(VpcId=vpc_id, ServiceName=service, VpcEndpointType=endpoint_type)
    if endpoint_type == 'Interface':
        kw['PrivateDnsEnabled'] = True
        if subnet_ids: kw['SubnetIds'] = subnet_ids
        if sg_ids:     kw['SecurityGroupIds'] = sg_ids
    elif route_table_ids: kw['RouteTableIds'] = route_table_ids
    if policy: kw['PolicyDocument'] = json.dumps(policy)
    return auth.client('ec2').create_vpc_endpoint(**kw)['VpcEndpoint']

def private_endpoints(auth, vpc_id, subnet_ids, sg_ids, services=None) -> list:
    'Create the interface endpoints a fully private GenAI stack needs.'
    return [create_vpc_endpoint(auth, vpc_id, s, subnet_ids=subnet_ids, sg_ids=sg_ids)
            for s in (services or INTERFACE_SERVICES)]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'ep-vpc')
    sn = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', 'us-east-1a')
    sg = create_security_group(auth, 'endpoints', vpc['VpcId'])

    ep = create_vpc_endpoint(auth, vpc['VpcId'], 'bedrock-runtime',
                             subnet_ids=[sn['SubnetId']], sg_ids=[sg['GroupId']])
    assert ep['ServiceName'] == 'com.amazonaws.us-east-1.bedrock-runtime'
    assert ep['PrivateDnsEnabled'], 'without private DNS the SDK still resolves the public endpoint'

    # a full service name is passed straight through
    gw = create_vpc_endpoint(auth, vpc['VpcId'], 'com.amazonaws.us-east-1.s3', endpoint_type='Gateway')
    assert gw['ServiceName'] == 'com.amazonaws.us-east-1.s3'

    eps = private_endpoints(auth, vpc['VpcId'], [sn['SubnetId']], [sg['GroupId']],
                            services=['secretsmanager', 'kms'])
    assert len(eps) == 2
    print('VPC endpoints OK')

# %% md
# ## Application Load Balancer
#
# `create_alb` applies the attributes that get flagged in every AWS security review: invalid
# header dropping, strictest desync mitigation, access logs, and (for regulated stacks)
# deletion protection. `https_listener` refuses to bind without an ACM certificate, and
# `redirect_http` sends port 80 straight to 443.
#
# To put enterprise SSO in front of the whole thing without touching application code, pass
# the listener to `alb_cognito_rule` or `alb_oidc_rule` from [`awseasy.auth`](auth.html).

# %% export
TLS_POLICY = 'ELBSecurityPolicy-TLS13-1-2-2021-06'

def create_alb(auth, name, subnet_ids, sg_ids=None, scheme='internet-facing', log_bucket=None,
               deletion_protection=False, waf_acl_arn=None, tags=None, **compliance_opts) -> dict:
    'Create a hardened internet-facing or internal ALB, optionally behind an AWS WAF web ACL.'
    c = auth.client('elbv2')
    try:
        alb = c.describe_load_balancers(Names=[name])['LoadBalancers'][0]
    except c.exceptions.LoadBalancerNotFoundException:
        alb = c.create_load_balancer(Name=name, Subnets=subnet_ids, SecurityGroups=sg_ids or [],
                                     Scheme=scheme, Type='application', IpAddressType='ipv4',
                                     Tags=tag_list(named(name, tags)))['LoadBalancers'][0]
    attrs = {'routing.http.drop_invalid_header_fields.enabled': 'true',
             'routing.http.desync_mitigation_mode': 'strictest',
             'routing.http2.enabled': 'true',
             'deletion_protection.enabled': str(bool(deletion_protection)).lower()}
    if log_bucket: attrs.update({'access_logs.s3.enabled': 'true', 'access_logs.s3.bucket': log_bucket,
                                 'access_logs.s3.prefix': name})
    c.modify_load_balancer_attributes(LoadBalancerArn=alb['LoadBalancerArn'],
                                      Attributes=[{'Key': k, 'Value': v} for k, v in attrs.items()])
    if waf_acl_arn:
        auth.client('wafv2').associate_web_acl(WebACLArn=waf_acl_arn, ResourceArn=alb['LoadBalancerArn'])
    return alb

def target_group(auth, name, vpc_id, port=8000, protocol='HTTP', target_type='ip',
                 health_path='/health') -> dict:
    'Create a target group for an ALB. Idempotent by name.'
    c = auth.client('elbv2')
    try: return c.describe_target_groups(Names=[name])['TargetGroups'][0]
    except c.exceptions.TargetGroupNotFoundException:
        return c.create_target_group(Name=name, Protocol=protocol, Port=port, VpcId=vpc_id,
                                     TargetType=target_type, HealthCheckPath=health_path,
                                     HealthCheckProtocol=protocol)['TargetGroups'][0]

def https_listener(auth, alb_arn, target_group_arn, cert_arn, port=443, ssl_policy=TLS_POLICY) -> dict:
    'Add an HTTPS listener. An ACM certificate is required — there is no plaintext fallback.'
    if not cert_arn: raise ValueError('cert_arn is required; use request_cert() from awseasy.cdn')
    return auth.client('elbv2').create_listener(
        LoadBalancerArn=alb_arn, Protocol='HTTPS', Port=port, SslPolicy=ssl_policy,
        Certificates=[{'CertificateArn': cert_arn}],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}])['Listeners'][0]

def redirect_http(auth, alb_arn, port=80) -> dict:
    'Add a listener that permanently redirects plaintext HTTP to HTTPS.'
    return auth.client('elbv2').create_listener(
        LoadBalancerArn=alb_arn, Protocol='HTTP', Port=port,
        DefaultActions=[{'Type': 'redirect', 'RedirectConfig': {
            'Protocol': 'HTTPS', 'Port': '443', 'StatusCode': 'HTTP_301'}}])['Listeners'][0]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'alb-vpc')
    sns = [add_subnet(auth, vpc['VpcId'], f'10.0.{i}.0/24', f'us-east-1{az}')['SubnetId']
           for i, az in enumerate('ab')]
    sg = create_security_group(auth, 'alb-sg', vpc['VpcId'])

    alb = create_alb(auth, 'app-alb', sns, [sg['GroupId']], log_bucket='my-log-bucket', **HIPAA)
    attrs = lambda: {a['Key']: a['Value'] for a in auth.client('elbv2').describe_load_balancer_attributes(
        LoadBalancerArn=alb['LoadBalancerArn'])['Attributes']}
    a = attrs()
    assert a['routing.http.drop_invalid_header_fields.enabled'] == 'true'
    assert a['routing.http.desync_mitigation_mode'] == 'strictest'
    assert a['access_logs.s3.enabled'] == 'true' and a['access_logs.s3.bucket'] == 'my-log-bucket'
    assert a['deletion_protection.enabled'] == 'true', 'HIPAA sets deletion_protection=True'

    # idempotent by name, and declarative: dropping the profile relaxes the attributes it set
    assert create_alb(auth, 'app-alb', sns)['LoadBalancerArn'] == alb['LoadBalancerArn']
    assert attrs()['deletion_protection.enabled'] == 'false'

    tg = target_group(auth, 'app-tg', vpc['VpcId'])
    assert target_group(auth, 'app-tg', vpc['VpcId'])['TargetGroupArn'] == tg['TargetGroupArn']
    cert = auth.client('acm').request_certificate(DomainName='app.example.com',
                                                  ValidationMethod='DNS')['CertificateArn']
    lst = https_listener(auth, alb['LoadBalancerArn'], tg['TargetGroupArn'], cert)
    assert lst['Protocol'] == 'HTTPS' and lst['SslPolicy'] == TLS_POLICY

    # no certificate, no listener — an "HTTPS" listener that quietly served plaintext is worse
    try: https_listener(auth, alb['LoadBalancerArn'], tg['TargetGroupArn'], None); raise AssertionError()
    except ValueError as e: assert 'cert_arn' in str(e)

    rd = redirect_http(auth, alb['LoadBalancerArn'])
    assert rd['DefaultActions'][0]['RedirectConfig']['StatusCode'] == 'HTTP_301'
    print('ALB OK')

# %% hide
import nbdev; nbdev.nbdev_export()
