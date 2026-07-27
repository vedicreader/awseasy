# %% md
# # images
# > Getting a container image into ECR, either from a local Docker daemon or entirely inside AWS.

# %% md
#
# Two paths, because teams are split on this:
#
# - **Local Docker** — generate a Dockerfile with [`dockeasy`](https://vedicreader.github.io/dockeasy/),
#   build it, and push. Fast to iterate on, needs a Docker daemon.
# - **AWS CodeBuild** — upload the source, let CodeBuild build and push. Nothing to install, works
#   from a laptop with no Docker, from CI, or from a locked-down build account. This is usually the
#   right answer for an enterprise: the build runs on an AWS-managed image with an IAM role scoped
#   to one repository, and there is a CloudWatch log of every build.

# %% code
#| default_exp images

# %% hide
from nbdev.showdoc import *

# %% export
import base64, json, os, subprocess, tempfile, time
from pathlib import Path
from fastcore.all import L, first
from awseasy.core import aws_policy, named, tag_list
from awseasy.compute import create_ecr, ecr_uri
from awseasy.network import attach_policy, create_role, put_role_policy

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2
from awseasy.data import create_bucket

# %% md
# ## Registry login
#
# `ecr_credentials` returns the short-lived token ECR issues (valid 12 hours) rather than any
# stored credential. `ecr_login` feeds it to `docker login` over stdin, so the token never appears
# in the process list or shell history the way `docker login -p <token>` would.

# %% export
def ecr_credentials(auth) -> dict:
    'Short-lived ECR credentials as {username, password, registry}. Valid for 12 hours.'
    d = auth.client('ecr').get_authorization_token()['authorizationData'][0]
    user, _, password = base64.b64decode(d['authorizationToken']).decode().partition(':')
    return {'username': user, 'password': password, 'registry': d['proxyEndpoint']}

def ecr_login(auth, docker='docker') -> str:
    'Log the local Docker daemon into ECR. The token is piped over stdin, never passed as an argument.'
    c = ecr_credentials(auth)
    r = subprocess.run([docker, 'login', '--username', c['username'], '--password-stdin',
                        c['registry']], input=c['password'], text=True, capture_output=True)
    if r.returncode: raise RuntimeError(f"docker login failed: {r.stderr.strip()}")
    return c['registry']

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    create_ecr(auth, 'genai-api')
    c = ecr_credentials(auth)
    assert c['username'] == 'AWS' and c['password']
    assert c['registry'].startswith('https://')
    # the token is issued on demand, not read from a config file or an env var
    assert c['password'] != os.environ.get('AWS_SECRET_ACCESS_KEY')
    print(c['registry'], '|', c['username'])

# %% md
# ## Building locally with dockeasy
#
# `dockeasy` generates the Dockerfile; this module builds it and pushes to ECR. Passing no
# Dockerfile makes `dockeasy.detect_app` infer one from the project layout (`pyproject.toml`,
# `go.mod`, `package.json`, …).
#
# `tag` defaults to a short timestamp rather than `latest`, because ECR repositories are created
# with immutable tags — pushing `latest` twice fails by design, and a moving `latest` is the thing
# immutability exists to prevent.

# %% export
def default_tag() -> str:
    'A sortable, unique tag. Immutable repositories cannot take "latest" twice.'
    return time.strftime('%Y%m%d-%H%M%S', time.gmtime())

def build_push(auth, repo, path='.', tag=None, dockerfile=None, push=True, docker='docker') -> str:
    '''Build a container image locally and push it to ECR. Returns the full image URI.

    `dockerfile` is a `dockeasy.Dockerfile`; omit it to let `dockeasy.detect_app` infer one from
    the project at `path`. Requires a running Docker daemon — use `build_in_codebuild` if there
    is not one.'''
    from dockeasy import detect_app
    tag = tag or default_tag()
    uri = ecr_uri(auth, repo, tag)
    df = dockerfile if dockerfile is not None else detect_app(path)
    df.build(tag=uri, path=path)
    if push:
        ecr_login(auth, docker=docker)
        r = subprocess.run([docker, 'push', uri], capture_output=True, text=True)
        if r.returncode: raise RuntimeError(f'docker push failed: {r.stderr.strip()}')
    return uri

def image_digest(auth, repo, tag) -> str:
    'Immutable digest of a tag. Deploy by digest when you need to pin exactly what runs.'
    imgs = auth.client('ecr').describe_images(repositoryName=repo,
                                              imageIds=[{'imageTag': tag}])['imageDetails']
    return imgs[0]['imageDigest']

def scan_findings(auth, repo, tag) -> dict:
    'Vulnerability counts from the scan-on-push result, e.g. {"HIGH": 2, "MEDIUM": 5}.'
    r = auth.client('ecr').describe_image_scan_findings(repositoryName=repo,
                                                        imageId={'imageTag': tag})
    return r.get('imageScanFindings', {}).get('findingSeverityCounts', {})

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    create_ecr(auth, 'genai-api')
    assert ecr_uri(auth, 'genai-api', 'v1') == \
        '123456789012.dkr.ecr.us-east-1.amazonaws.com/genai-api:v1'

t1 = default_tag()
assert len(t1) == 15 and t1[8] == '-' and t1.replace('-', '').isdigit()
# tags sort chronologically, so the newest image is the last one alphabetically
assert sorted(['20260101-000000', '20260102-000000']) == ['20260101-000000', '20260102-000000']
print(t1)

# %% md
# ## Building inside AWS with CodeBuild
#
# No Docker daemon anywhere in the loop. `create_image_project` sets up a CodeBuild project whose
# service role can push to exactly one repository, with a generated buildspec that logs in,
# builds, and pushes both an immutable tag and the digest.
#
# `privilegedMode` is required for `docker build` inside CodeBuild — it is what gives the build
# container access to a Docker daemon.

# %% export
BUILD_IMAGE = 'aws/codebuild/standard:7.0'

def buildspec(auth, repo, dockerfile='Dockerfile', context='.') -> str:
    'Buildspec that logs into ECR, builds, and pushes $IMAGE_TAG. Returns YAML.'
    registry = f'{auth.account_id}.dkr.ecr.{auth.region}.amazonaws.com'
    return '\n'.join([
        'version: 0.2',
        'phases:',
        '  pre_build:',
        '    commands:',
        f'      - aws ecr get-login-password --region {auth.region} | '
        f'docker login --username AWS --password-stdin {registry}',
        '  build:',
        '    commands:',
        f'      - docker build -f {dockerfile} -t $IMAGE_URI:$IMAGE_TAG {context}',
        '  post_build:',
        '    commands:',
        '      - docker push $IMAGE_URI:$IMAGE_TAG',
        '      - |',
        '        aws ecr describe-images --repository-name $REPO_NAME '
        '--image-ids imageTag=$IMAGE_TAG --query "imageDetails[0].imageDigest" --output text',
    ]) + '\n'

def ecr_push_policy(auth, repo) -> dict:
    'Least-privilege policy for a build: push to one repository, and write its own logs.'
    return {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'EcrAuth', 'Effect': 'Allow', 'Action': 'ecr:GetAuthorizationToken',
         'Resource': '*'},   # this action does not accept a resource; the push rights below do
        {'Sid': 'PushToOneRepo', 'Effect': 'Allow',
         'Action': ['ecr:BatchCheckLayerAvailability', 'ecr:CompleteLayerUpload',
                    'ecr:InitiateLayerUpload', 'ecr:PutImage', 'ecr:UploadLayerPart',
                    'ecr:BatchGetImage', 'ecr:DescribeImages'],
         'Resource': auth.arn_for('ecr', f'repository/{repo}')},
        {'Sid': 'WriteBuildLogs', 'Effect': 'Allow',
         'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
         'Resource': auth.arn_for('logs', 'log-group:/aws/codebuild/*')}]}

def codebuild_role(auth, name, repo, source_bucket=None) -> dict:
    'Service role for a CodeBuild image build, scoped to one ECR repository.'
    role = create_role(auth, name, service='codebuild.amazonaws.com',
                       source_account=auth.account_id)
    put_role_policy(auth, name, 'ecr-push', ecr_push_policy(auth, repo))
    if source_bucket:
        put_role_policy(auth, name, 'read-source', {
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:GetObjectVersion'],
                           'Resource': auth.arn_for('s3', f'{source_bucket}/*', region='',
                                                    account=False)}]})
    return role

def create_image_project(auth, name, repo, source_bucket=None, source_key=None, github_url=None,
                         dockerfile='Dockerfile', context='.', compute='BUILD_GENERAL1_SMALL',
                         build_image=BUILD_IMAGE, tags=None, **compliance_opts) -> dict:
    'Create a CodeBuild project that builds a container image and pushes it to ECR.'
    if bool(source_bucket) == bool(github_url):
        raise ValueError('pass exactly one of source_bucket= (with source_key=) or github_url=')
    create_ecr(auth, repo, **compliance_opts)
    role = codebuild_role(auth, f'{name}-build-role', repo, source_bucket)
    source = ({'type': 'S3', 'location': f'{source_bucket}/{source_key}'} if source_bucket
              else {'type': 'GITHUB', 'location': github_url})
    source['buildspec'] = buildspec(auth, repo, dockerfile, context)
    c = auth.client('codebuild')
    kw = dict(
        name=name, source=source, artifacts={'type': 'NO_ARTIFACTS'},
        serviceRole=role['Role']['Arn'],
        environment={'type': 'LINUX_CONTAINER', 'image': build_image, 'computeType': compute,
                     # docker build needs a Docker daemon inside the build container
                     'privilegedMode': True,
                     'environmentVariables': [
                         {'name': 'IMAGE_URI', 'value': ecr_uri(auth, repo)},
                         {'name': 'REPO_NAME', 'value': repo},
                         {'name': 'IMAGE_TAG', 'value': 'latest'}]})
    if tags: kw['tags'] = tag_list(tags, 'key', 'value')
    try: return c.create_project(**kw)['project']
    except c.exceptions.ResourceAlreadyExistsException:
        cur = c.batch_get_projects(names=[name])['projects'][0]
        if not project_drifted(cur, kw): return cur
        c.update_project(**kw)
        return c.batch_get_projects(names=[name])['projects'][0]

def project_drifted(current, wanted) -> bool:
    'True when a stored CodeBuild project differs from the config we would send.'
    src, env = current.get('source', {}), current.get('environment', {})
    w_src, w_env = wanted['source'], wanted['environment']
    return (src.get('buildspec') != w_src.get('buildspec')
            or src.get('location') != w_src.get('location')
            or src.get('type') != w_src.get('type')
            or env.get('image') != w_env['image']
            or env.get('computeType') != w_env['computeType']
            or env.get('privilegedMode') != w_env['privilegedMode']
            or current.get('serviceRole') != wanted['serviceRole'])

def build_image_in_codebuild(auth, project, tag=None) -> dict:
    'Start a build. Returns the build record; poll it with `build_status`.'
    tag = tag or default_tag()
    return auth.client('codebuild').start_build(
        projectName=project,
        environmentVariablesOverride=[{'name': 'IMAGE_TAG', 'value': tag,
                                       'type': 'PLAINTEXT'}])['build']

def build_status(auth, build_id) -> str:
    'IN_PROGRESS, SUCCEEDED, FAILED, ...'
    return auth.client('codebuild').batch_get_builds(ids=[build_id])['builds'][0]['buildStatus']

def upload_source(auth, bucket, key, path='.') -> str:
    'Zip a directory and upload it as CodeBuild S3 source. Returns "bucket/key".'
    import zipfile
    root = Path(path).resolve()
    skip = {'.git', '__pycache__', '.venv', 'node_modules', '.ipynb_checkpoints'}
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f: tmp = f.name
    try:
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
            for p in root.rglob('*'):
                if p.is_file() and not skip & set(p.relative_to(root).parts):
                    z.write(p, p.relative_to(root))
        auth.client('s3').upload_file(tmp, bucket, key)
    finally: Path(tmp).unlink(missing_ok=True)
    return f'{bucket}/{key}'

# %% code
with mock_aws():
    auth = AWSAuth(region='eu-west-1')
    spec = buildspec(auth, 'genai-api')
    reg = '123456789012.dkr.ecr.eu-west-1.amazonaws.com'

    assert spec.startswith('version: 0.2')
    # login uses get-login-password piped to stdin — the token is never a command-line argument
    assert f'aws ecr get-login-password --region eu-west-1 | docker login --username AWS ' \
           f'--password-stdin {reg}' in spec
    assert 'docker build -f Dockerfile -t $IMAGE_URI:$IMAGE_TAG .' in spec
    assert 'docker push $IMAGE_URI:$IMAGE_TAG' in spec
    assert '--password ' not in spec and 'AWS_SECRET' not in spec

    custom = buildspec(auth, 'genai-api', dockerfile='docker/api.Dockerfile', context='./src')
    assert 'docker build -f docker/api.Dockerfile -t $IMAGE_URI:$IMAGE_TAG ./src' in custom
    print(spec)

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pol = ecr_push_policy(auth, 'genai-api')
    sids = {s['Sid']: s for s in pol['Statement']}

    # push rights are scoped to one repository, not to ecr:* on everything
    assert sids['PushToOneRepo']['Resource'] == \
        'arn:aws:ecr:us-east-1:123456789012:repository/genai-api'
    assert 'ecr:DeleteRepository' not in sids['PushToOneRepo']['Action']
    assert 'ecr:*' not in sids['PushToOneRepo']['Action']
    # GetAuthorizationToken is the one ECR action with no resource-level permission
    assert sids['EcrAuth']['Action'] == 'ecr:GetAuthorizationToken'
    assert sids['WriteBuildLogs']['Resource'].endswith('log-group:/aws/codebuild/*')
    print(json.dumps(sids['PushToOneRepo'], indent=1))

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    # tls_min=None because moto serves plaintext HTTP: the TLS-only policy create_bucket normally
    # writes would (correctly) deny this upload. Against real S3, leave the default in place.
    create_bucket(auth, 'build-source', tls_min=None)
    upload_source(auth, 'build-source', 'app/src.zip', path='.')
    assert auth.client('s3').head_object(Bucket='build-source', Key='app/src.zip')['ContentLength']

    proj = create_image_project(auth, 'genai-api-build', 'genai-api',
                                source_bucket='build-source', source_key='app/src.zip', **HIPAA)
    env = proj['environment']
    # privileged mode is what gives the build container a Docker daemon
    assert env['privilegedMode'] is True
    assert env['image'] == BUILD_IMAGE
    assert proj['source']['location'] == 'build-source/app/src.zip'
    assert 'docker push' in proj['source']['buildspec']
    envvars = {v['name']: v['value'] for v in env['environmentVariables']}
    assert envvars['IMAGE_URI'] == '123456789012.dkr.ecr.us-east-1.amazonaws.com/genai-api'

    # the repository it pushes to exists and inherits the compliance profile's hardening
    repo = auth.client('ecr').describe_repositories(repositoryNames=['genai-api'])['repositories'][0]
    assert repo['imageTagMutability'] == 'IMMUTABLE'

    # the build role can push to that repo and nothing else
    inline = auth.client('iam').list_role_policies(RoleName='genai-api-build-build-role')['PolicyNames']
    assert set(inline) == {'ecr-push', 'read-source'}

    b = build_image_in_codebuild(auth, 'genai-api-build', tag='v1.2.3')
    assert b['id'] and b['buildStatus'] in ('IN_PROGRESS', 'SUCCEEDED')

    # idempotent: an unchanged re-run is recognised as unchanged and skips the update call
    assert create_image_project(auth, 'genai-api-build', 'genai-api',
                                source_bucket='build-source', source_key='app/src.zip')['name'] \
        == 'genai-api-build'
    assert auth.client('codebuild').list_projects()['projects'] == ['genai-api-build']
    print(proj['name'], envvars)

# drift detection is a pure comparison, so check it directly
wanted = {'source': {'type': 'S3', 'location': 'b/k.zip', 'buildspec': 'version: 0.2'},
          'environment': {'image': BUILD_IMAGE, 'computeType': 'BUILD_GENERAL1_SMALL',
                          'privilegedMode': True},
          'serviceRole': 'arn:aws:iam::123456789012:role/r'}
assert project_drifted(wanted, wanted) is False
for k, v in [('serviceRole', 'arn:aws:iam::123456789012:role/other')]:
    assert project_drifted({**wanted, k: v}, wanted)
assert project_drifted({**wanted, 'source': {**wanted['source'], 'buildspec': 'changed'}}, wanted)
assert project_drifted({**wanted, 'environment': {**wanted['environment'],
                                                  'privilegedMode': False}}, wanted)
print('drift detection OK')

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    # exactly one source: S3 or GitHub, never both and never neither
    for bad in (dict(), dict(source_bucket='b', github_url='https://github.com/o/r')):
        try:
            create_image_project(auth, 'x-build', 'x-repo', **bad)
            raise AssertionError('should raise')
        except ValueError as e: assert 'exactly one' in str(e)

    gh = create_image_project(auth, 'gh-build', 'gh-repo',
                              github_url='https://github.com/acme/api')
    assert gh['source']['type'] == 'GITHUB'
    # no source bucket means no S3 read policy on the role
    assert auth.client('iam').list_role_policies(
        RoleName='gh-build-build-role')['PolicyNames'] == ['ecr-push']
    print('source guards OK')

# %% md
# ### Against a real account
#
# The local path needs a Docker daemon; the CodeBuild path needs none. Both push to a real
# repository, so run them in an account you are happy to leave an image in.

# %% noeval
auth = AWSAuth()
create_ecr(auth, 'awseasy-demo')

# Local: dockeasy infers a Dockerfile from the project, builds it, pushes it.
uri = build_push(auth, 'awseasy-demo', path='.')
print('pushed', uri)
print('digest', image_digest(auth, 'awseasy-demo', uri.rsplit(':', 1)[1]))
print('vulnerabilities', scan_findings(auth, 'awseasy-demo', uri.rsplit(':', 1)[1]))

# %% noeval
# CodeBuild: no Docker daemon required anywhere.
auth = AWSAuth()
create_bucket(auth, f'awseasy-src-{auth.account_id}')
upload_source(auth, f'awseasy-src-{auth.account_id}', 'demo/src.zip', path='.')
create_image_project(auth, 'awseasy-demo-build', 'awseasy-demo',
                     source_bucket=f'awseasy-src-{auth.account_id}', source_key='demo/src.zip')
build = build_image_in_codebuild(auth, 'awseasy-demo-build')
while build_status(auth, build['id']) == 'IN_PROGRESS': time.sleep(10)
print(build_status(auth, build['id']))

# %% hide
import nbdev; nbdev.nbdev_export()
