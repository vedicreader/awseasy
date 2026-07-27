# %% md
# # compute
# > EC2 instances, EKS clusters, and ECR registries for serving GenAI workloads.

# %% code
#| default_exp compute

# %% hide
from nbdev.showdoc import *

# %% export
import json, subprocess
from fastcore.all import L, first
from awseasy.core import aws_policy, named, tag_list
from awseasy.network import attach_policy, create_role

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2, create_kms_key
from awseasy.network import add_subnet, create_security_group, create_vpc

# %% md
# ## EC2
#
# Two settings account for most EC2 findings in a cloud security review, and both are applied
# here unconditionally:
#
# - **IMDSv2 required.** With IMDSv1 still enabled, any SSRF bug in the app running on the box
#   can read the instance role's credentials with a single unauthenticated GET. `HttpTokens:
#   required` forces a session token; `HttpPutResponseHopLimit: 1` stops a container from
#   reaching the metadata endpoint at all.
# - **Encrypted root volume.** EBS encryption cannot be turned on after launch — the volume
#   has to be snapshotted and replaced — so getting it right at launch is the only cheap moment.

# %% export
UBUNTU_OWNER = '099720109477'   # Canonical
UBUNTU_SSM = '/aws/service/canonical/ubuntu/server/{ver}/stable/current/amd64/hvm/ebs-gp3/ami-id'

def latest_ubuntu_ami(auth, ver='22.04') -> str:
    'Latest Canonical Ubuntu LTS AMI id, via the SSM public parameter with a describe_images fallback.'
    try: return auth.client('ssm').get_parameter(Name=UBUNTU_SSM.format(ver=ver))['Parameter']['Value']
    except Exception: pass
    imgs = auth.client('ec2').describe_images(Owners=[UBUNTU_OWNER], Filters=[
        {'Name': 'name', 'Values': [f'ubuntu/images/hvm-ssd*/ubuntu-*-{ver}-amd64-server-*']},
        {'Name': 'architecture', 'Values': ['x86_64']},
        {'Name': 'state', 'Values': ['available']}])['Images']
    if not imgs: raise ValueError(f'no Ubuntu {ver} AMI found in {auth.region}; pass ami= explicitly')
    return sorted(imgs, key=lambda i: i['CreationDate'])[-1]['ImageId']

def create_instance(auth, name, instance_type='t3.medium', ami=None, key_name=None, subnet_id=None,
                    sg_ids=None, iam_instance_profile=None, user_data=None, volume_size=30,
                    kms_key_id=None, tags=None, **compliance_opts) -> dict:
    'Launch an EC2 instance with IMDSv2 required and an encrypted root volume.'
    ec2 = auth.client('ec2')
    ebs = {'VolumeSize': volume_size, 'VolumeType': 'gp3', 'Encrypted': True,
           'DeleteOnTermination': True}
    if kms_key_id: ebs['KmsKeyId'] = kms_key_id
    kw = dict(ImageId=ami or latest_ubuntu_ami(auth), InstanceType=instance_type, MinCount=1, MaxCount=1,
              # IMDSv2 only: an SSRF bug can no longer read the instance role's credentials
              MetadataOptions={'HttpTokens': 'required', 'HttpEndpoint': 'enabled',
                               'HttpPutResponseHopLimit': 1, 'InstanceMetadataTags': 'enabled'},
              BlockDeviceMappings=[{'DeviceName': '/dev/sda1', 'Ebs': ebs}],
              Monitoring={'Enabled': bool(compliance_opts.get('audit'))},
              TagSpecifications=[{'ResourceType': t, 'Tags': tag_list(named(name, tags))}
                                 for t in ('instance', 'volume')])
    if key_name: kw['KeyName'] = key_name
    if subnet_id: kw['SubnetId'] = subnet_id
    if sg_ids: kw['SecurityGroupIds'] = sg_ids
    if user_data: kw['UserData'] = user_data
    if iam_instance_profile: kw['IamInstanceProfile'] = {'Name': iam_instance_profile}
    return ec2.run_instances(**kw)['Instances'][0]

def instance_ip(auth, instance_id) -> str:
    'Public IP if the instance has one, otherwise the private IP.'
    i = auth.client('ec2').describe_instances(
        InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    return i.get('PublicIpAddress') or i.get('PrivateIpAddress', '')

def start_instance(auth, instance_id): auth.client('ec2').start_instances(InstanceIds=[instance_id])
def stop_instance(auth, instance_id):  auth.client('ec2').stop_instances(InstanceIds=[instance_id])
def terminate_instance(auth, instance_id): auth.client('ec2').terminate_instances(InstanceIds=[instance_id])

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'ec2-vpc')
    sn = add_subnet(auth, vpc['VpcId'], '10.0.1.0/24', 'us-east-1a')
    sg = create_security_group(auth, 'ec2-sg', vpc['VpcId'])
    key = create_kms_key(auth, 'ebs-key')
    ami = auth.client('ec2').describe_images()['Images'][0]['ImageId']

    i = create_instance(auth, 'inference-1', ami=ami, subnet_id=sn['SubnetId'],
                        sg_ids=[sg['GroupId']], kms_key_id=key['Arn'], **ISO27001)
    ec2 = auth.client('ec2')
    got = ec2.describe_instances(InstanceIds=[i['InstanceId']])['Reservations'][0]['Instances'][0]

    # IMDSv1 disabled: credential theft via SSRF needs a PUT-obtained token it cannot get
    assert got['MetadataOptions']['HttpTokens'] == 'required'
    assert got['MetadataOptions']['HttpPutResponseHopLimit'] == 1

    vol = ec2.describe_volumes(VolumeIds=[got['BlockDeviceMappings'][0]['Ebs']['VolumeId']])['Volumes'][0]
    assert vol['Encrypted'] is True and vol['KmsKeyId'] == key['Arn']
    assert vol['VolumeType'] == 'gp3' and vol['Size'] == 30

    assert instance_ip(auth, i['InstanceId'])
    stop_instance(auth, i['InstanceId'])
    assert ec2.describe_instances(InstanceIds=[i['InstanceId']]
                                  )['Reservations'][0]['Instances'][0]['State']['Name'] == 'stopped'
    start_instance(auth, i['InstanceId'])
    terminate_instance(auth, i['InstanceId'])
    print('EC2 OK')

# %% code
with mock_aws():
    # No AMI and no match: fail loudly with a fixable message rather than launching something arbitrary.
    auth = AWSAuth(region='us-east-1')
    try: latest_ubuntu_ami(auth); raise AssertionError('should raise')
    except ValueError as e: assert 'pass ami= explicitly' in str(e)
    print('AMI resolution failure is explicit OK')

# %% md
# ## EKS
#
# `create_eks` builds the cluster and node roles, then turns on the two things that are
# painful to add later: **envelope encryption of Kubernetes secrets** with a KMS key (which
# can only be set at creation time, never retrofitted), and **control-plane audit logging**.
#
# `public_access=False` keeps the API server endpoint reachable only from inside the VPC. Every
# built-in compliance profile sets it, so `create_eks(auth, name, subnets, **ISO27001)` gets a
# private endpoint without naming the setting.

# %% export
EKS_LOG_TYPES = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']

def create_eks(auth, name, subnet_ids, node_type='m5.large', node_count=2, version='1.31',
               sg_ids=None, kms_key_id=None, public_access=True, public_cidrs=None,
               audit=False, tags=None, **compliance_opts) -> dict:
    'Create an EKS cluster and managed node group, with secrets encryption and audit logging.'
    c = auth.client('eks')
    cluster_role = create_role(auth, f'{name}-eks-cluster-role', service='eks.amazonaws.com')
    attach_policy(auth, f'{name}-eks-cluster-role', aws_policy(auth, 'AmazonEKSClusterPolicy'))
    node_role = create_role(auth, f'{name}-eks-node-role', service='ec2.amazonaws.com')
    for p in ('AmazonEKSWorkerNodePolicy', 'AmazonEKS_CNI_Policy', 'AmazonEC2ContainerRegistryReadOnly'):
        attach_policy(auth, f'{name}-eks-node-role', aws_policy(auth, p))

    vpc_cfg = {'subnetIds': subnet_ids, 'endpointPrivateAccess': True,
               'endpointPublicAccess': public_access}
    if sg_ids: vpc_cfg['securityGroupIds'] = sg_ids
    if public_access and public_cidrs: vpc_cfg['publicAccessCidrs'] = public_cidrs
    kw = dict(name=name, version=version, roleArn=cluster_role['Role']['Arn'],
              resourcesVpcConfig=vpc_cfg, tags=tags or {})
    if kms_key_id:
        # Only settable at creation: without it, Kubernetes Secrets sit in etcd under an AWS-owned key.
        kw['encryptionConfig'] = [{'resources': ['secrets'], 'provider': {'keyArn': kms_key_id}}]
    if audit: kw['logging'] = {'clusterLogging': [{'types': EKS_LOG_TYPES, 'enabled': True}]}
    try: cluster = c.create_cluster(**kw)['cluster']
    except c.exceptions.ResourceInUseException:
        cluster = c.describe_cluster(name=name)['cluster']
    try:
        c.create_nodegroup(clusterName=name, nodegroupName=f'{name}-ng', subnets=subnet_ids,
                           instanceTypes=[node_type], nodeRole=node_role['Role']['Arn'],
                           scalingConfig={'minSize': 1, 'maxSize': max(node_count * 2, 2),
                                          'desiredSize': node_count})
    except c.exceptions.ResourceInUseException: pass
    return cluster

def scale_eks(auth, name, node_count, nodegroup=None):
    'Set the desired node count on a managed node group.'
    auth.client('eks').update_nodegroup_config(
        clusterName=name, nodegroupName=nodegroup or f'{name}-ng',
        scalingConfig={'desiredSize': node_count})

def eks_kubeconfig(auth, name, dry_run=True) -> str:
    'Run `aws eks update-kubeconfig`. Requires the AWS CLI; dry_run prints the config instead of writing it.'
    cmd = ['aws', 'eks', 'update-kubeconfig', '--name', name, '--region', auth.region]
    r = subprocess.run(cmd + (['--dry-run'] if dry_run else []), capture_output=True, text=True)
    if r.returncode: raise RuntimeError(f'aws eks update-kubeconfig failed: {r.stderr.strip()}')
    return r.stdout

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'eks-vpc')
    sns = [add_subnet(auth, vpc['VpcId'], f'10.0.{i}.0/24', f'us-east-1{a}')['SubnetId']
           for i, a in enumerate('ab')]
    key = create_kms_key(auth, 'eks-key')

    # ISO27001 carries public_access=False, so the profile alone makes the endpoint private
    cl = create_eks(auth, 'genai', sns, kms_key_id=key['Arn'], **ISO27001)
    # Kubernetes Secrets are envelope-encrypted with our key, not just etcd-at-rest defaults
    assert cl['encryptionConfig'][0]['provider']['keyArn'] == key['Arn']
    assert cl['encryptionConfig'][0]['resources'] == ['secrets']
    # control-plane audit log, and an API endpoint that is not on the internet
    assert cl['logging']['clusterLogging'][0]['enabled'] and 'audit' in cl['logging']['clusterLogging'][0]['types']
    assert cl['resourcesVpcConfig']['endpointPublicAccess'] is False
    assert cl['resourcesVpcConfig']['endpointPrivateAccess'] is True

    iam = auth.client('iam')
    node_pols = {p['PolicyName'] for p in iam.list_attached_role_policies(
        RoleName='genai-eks-node-role')['AttachedPolicies']}
    assert {'AmazonEKSWorkerNodePolicy', 'AmazonEKS_CNI_Policy',
            'AmazonEC2ContainerRegistryReadOnly'} <= node_pols

    ng = auth.client('eks').describe_nodegroup(clusterName='genai', nodegroupName='genai-ng')['nodegroup']
    assert ng['scalingConfig']['desiredSize'] == 2
    scale_eks(auth, 'genai', 5)
    assert auth.client('eks').describe_nodegroup(
        clusterName='genai', nodegroupName='genai-ng')['nodegroup']['scalingConfig']['desiredSize'] == 5

    assert create_eks(auth, 'genai', sns)['name'] == 'genai'   # idempotent

    # Without a profile the endpoint stays publicly reachable, matching the AWS default —
    # a private-by-default cluster is unreachable until a bastion or VPN exists.
    plain = create_eks(auth, 'plain', sns)
    assert plain['resourcesVpcConfig']['endpointPublicAccess'] is True
    assert 'encryptionConfig' not in plain or not plain['encryptionConfig']
    print('EKS OK')

# %% md
# ## ECR
#
# Repositories are created with **immutable tags**, which is the control that makes a
# deployed digest mean something: without it, anyone with push rights can move `:v1.2.3` to
# different content after it has been reviewed and approved.
#
# `ecr_lifecycle` caps how many untagged images accumulate, since every one of them is a
# stored, billed, and scannable artifact.

# %% export
def create_ecr(auth, name, scan_on_push=True, immutable=True, kms_key_id=None,
               max_untagged=10, tags=None, **compliance_opts) -> dict:
    'Create an ECR repository with scan-on-push, immutable tags, and an untagged-image lifecycle rule.'
    c = auth.client('ecr')
    enc = ({'encryptionType': 'KMS', 'kmsKey': kms_key_id} if kms_key_id
           else {'encryptionType': 'AES256'})
    try:
        repo = c.create_repository(
            repositoryName=name, imageScanningConfiguration={'scanOnPush': scan_on_push},
            imageTagMutability='IMMUTABLE' if immutable else 'MUTABLE',
            encryptionConfiguration=enc, tags=tag_list(tags))['repository']
    except c.exceptions.RepositoryAlreadyExistsException:
        repo = c.describe_repositories(repositoryNames=[name])['repositories'][0]
    if max_untagged: ecr_lifecycle(auth, name, max_untagged)
    return repo

def ecr_lifecycle(auth, name, max_untagged=10, keep_tagged=50) -> dict:
    'Expire untagged images beyond `max_untagged` and cap retained tagged images.'
    policy = {'rules': [
        {'rulePriority': 1, 'description': 'expire untagged images',
         'selection': {'tagStatus': 'untagged', 'countType': 'imageCountMoreThan',
                       'countNumber': max_untagged},
         'action': {'type': 'expire'}},
        {'rulePriority': 2, 'description': 'cap retained tagged images',
         'selection': {'tagStatus': 'any', 'countType': 'imageCountMoreThan',
                       'countNumber': keep_tagged},
         'action': {'type': 'expire'}}]}
    return auth.client('ecr').put_lifecycle_policy(repositoryName=name,
                                                   lifecyclePolicyText=json.dumps(policy))

def ecr_uri(auth, name, tag=None) -> str:
    'Registry URI for docker push/pull, optionally with a tag.'
    uri = f'{auth.account_id}.dkr.ecr.{auth.region}.amazonaws.com/{name}'
    return f'{uri}:{tag}' if tag else uri

def image_tags(auth, name) -> list:
    'Tags currently present in a repository.'
    imgs = auth.client('ecr').list_images(repositoryName=name)['imageIds']
    return [i['imageTag'] for i in imgs if 'imageTag' in i]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    key = create_kms_key(auth, 'ecr-key')
    repo = create_ecr(auth, 'genai-api', kms_key_id=key['Arn'], **HIPAA)

    # immutable tags: a reviewed :v1.0.0 digest cannot be swapped out from under a deployment
    assert repo['imageTagMutability'] == 'IMMUTABLE'
    assert repo['imageScanningConfiguration']['scanOnPush'] is True
    assert repo['encryptionConfiguration']['encryptionType'] == 'KMS'

    pol = json.loads(auth.client('ecr').get_lifecycle_policy(
        repositoryName='genai-api')['lifecyclePolicyText'])
    assert pol['rules'][0]['selection']['tagStatus'] == 'untagged'

    assert create_ecr(auth, 'genai-api')['repositoryName'] == 'genai-api'   # idempotent
    assert ecr_uri(auth, 'genai-api', 'v1') == '123456789012.dkr.ecr.us-east-1.amazonaws.com/genai-api:v1'
    assert ecr_uri(auth, 'genai-api').endswith('/genai-api')
    assert image_tags(auth, 'genai-api') == []
    print(ecr_uri(auth, 'genai-api', 'v1'))

# %% hide
import nbdev; nbdev.nbdev_export()
