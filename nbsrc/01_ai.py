# %% md
# # ai
# > Amazon Bedrock inference, Guardrails, and the vector stores behind a Knowledge Base.

# %% code
#| default_exp ai

# %% hide
from nbdev.showdoc import *

# %% export
import json, secrets, string
from awseasy.core import named, poll_until, tag_list
from awseasy.network import create_secret, get_secret

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from botocore.stub import ANY, Stubber
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2, create_kms_key

def stub_auth(region='us-east-1'):
    '''AWSAuth with its identity pre-seeded, for use with botocore Stubber.

    moto does not mock Bedrock inference, Guardrails, or OpenSearch Serverless collections, so
    those are tested with botocore's Stubber instead — which asserts the exact request parameters
    we send. For a library whose whole job is sending hardened parameters, that is the assertion
    that matters.'''
    a = AWSAuth(region=region)
    a._ident = {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:user/test'}
    return a

# %% md
# ## Bedrock inference
#
# `converse()` uses Bedrock's [Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html),
# which takes the same request shape for every foundation model — so switching from Claude to
# Llama to Mistral is a change of `model_id` and nothing else. The older `InvokeModel` path
# required hand-building a different JSON body per model family.
#
# It also takes `guardrail=`, which is how a guardrail actually gets enforced: a guardrail that
# exists but is not attached to the call does nothing.
#
# `DEFAULT_MODEL` is a starting point, not a recommendation — run `list_bedrock_models()` to see
# what your account and region have access to, since Bedrock model availability is per-region and
# newer models are usually reached through a cross-region inference profile.

# %% export
DEFAULT_MODEL = 'anthropic.claude-3-5-sonnet-20241022-v2:0'
EMBED_MODEL = 'amazon.titan-embed-text-v2:0'

def inference_profile(model_id, prefix='us') -> str:
    'Cross-region inference profile id, e.g. "us.anthropic.claude-...". Newer models require one.'
    return model_id if model_id.startswith(f'{prefix}.') else f'{prefix}.{model_id}'

def list_bedrock_models(auth, provider=None) -> list:
    'Foundation models available on demand in this region, optionally filtered by provider.'
    kw = {'byInferenceType': 'ON_DEMAND'}
    if provider: kw['byProvider'] = provider
    return auth.client('bedrock').list_foundation_models(**kw)['modelSummaries']

def converse(auth, prompt, model_id=DEFAULT_MODEL, system=None, max_tokens=1024,
             temperature=None, guardrail=None, region=None, **_) -> str:
    'Call any Bedrock foundation model and return its text. guardrail=(id, version) enforces a guardrail.'
    kw = dict(modelId=model_id,
              messages=[{'role': 'user', 'content': [{'text': prompt}]}],
              inferenceConfig={'maxTokens': max_tokens})
    if temperature is not None: kw['inferenceConfig']['temperature'] = temperature
    if system: kw['system'] = [{'text': system}]
    if guardrail:
        gid, gver = guardrail if isinstance(guardrail, (tuple, list)) else (guardrail, 'DRAFT')
        kw['guardrailConfig'] = {'guardrailIdentifier': gid, 'guardrailVersion': str(gver)}
    r = auth.client('bedrock-runtime', region=region).converse(**kw)
    return ''.join(b.get('text', '') for b in r['output']['message']['content'])

# %% code
CONVERSE_REPLY = {'output': {'message': {'role': 'assistant', 'content': [{'text': 'Hello there.'}]}},
                  'stopReason': 'end_turn',
                  'usage': {'inputTokens': 8, 'outputTokens': 3, 'totalTokens': 11},
                  'metrics': {'latencyMs': 210}}

auth = stub_auth()
with Stubber(auth.client('bedrock-runtime')) as stub:
    stub.add_response('converse', CONVERSE_REPLY, {
        'modelId': DEFAULT_MODEL,
        'messages': [{'role': 'user', 'content': [{'text': 'Hi'}]}],
        'inferenceConfig': {'maxTokens': 1024}})
    assert converse(auth, 'Hi') == 'Hello there.'

    # a system prompt, a guardrail and an inference profile all ride on the same request
    stub.add_response('converse', CONVERSE_REPLY, {
        'modelId': 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',
        'messages': [{'role': 'user', 'content': [{'text': 'Hi'}]}],
        'system': [{'text': 'Be terse.'}],
        'inferenceConfig': {'maxTokens': 256, 'temperature': 0.0},
        'guardrailConfig': {'guardrailIdentifier': 'gr-123', 'guardrailVersion': '1'}})
    assert converse(auth, 'Hi', model_id=inference_profile(DEFAULT_MODEL), system='Be terse.',
                    max_tokens=256, temperature=0.0, guardrail=('gr-123', 1)) == 'Hello there.'
    stub.assert_no_pending_responses()

assert inference_profile(DEFAULT_MODEL) == f'us.{DEFAULT_MODEL}'
assert inference_profile('us.foo') == 'us.foo'      # already profiled, left alone
assert inference_profile('foo', 'eu') == 'eu.foo'
print('converse OK')

# %% code
# A guardrail with no version defaults to DRAFT — the working version you get before publishing.
auth = stub_auth()
with Stubber(auth.client('bedrock-runtime')) as stub:
    stub.add_response('converse', CONVERSE_REPLY, {
        'modelId': DEFAULT_MODEL,
        'messages': [{'role': 'user', 'content': [{'text': 'Hi'}]}],
        'inferenceConfig': {'maxTokens': 1024},
        'guardrailConfig': {'guardrailIdentifier': 'gr-123', 'guardrailVersion': 'DRAFT'}})
    converse(auth, 'Hi', guardrail='gr-123')
    stub.assert_no_pending_responses()
print('guardrail defaults to DRAFT OK')

# %% md
# ## Guardrails
#
# A model that will answer anything is the largest single risk in an enterprise GenAI
# deployment. A Bedrock guardrail sits between the app and the model and enforces four things
# server-side, where a user cannot prompt their way around them:
#
# - **Content filters** — hate, insults, sexual content, violence, misconduct, and prompt-injection
#   attacks, at configurable strength.
# - **PII redaction** — email, phone, name, address, SSN, and card numbers are masked before they
#   reach the model and before a response reaches the user.
# - **Denied topics** — subjects the app must never discuss, described in natural language.
# - **Word filters** — exact terms to block.
#
# The defaults here are deliberately strict. `create_guardrail` returns the guardrail id and
# version to hand to `converse(guardrail=...)`.

# %% export
CONTENT_FILTERS = ['HATE', 'INSULTS', 'SEXUAL', 'VIOLENCE', 'MISCONDUCT']
PII_ENTITIES = ['EMAIL', 'PHONE', 'NAME', 'ADDRESS', 'US_SOCIAL_SECURITY_NUMBER',
                'CREDIT_DEBIT_CARD_NUMBER', 'PASSWORD', 'AWS_ACCESS_KEY', 'AWS_SECRET_KEY']

def _content_policy(strength):
    # PROMPT_ATTACK is input-only: an output strength other than NONE is rejected by the API.
    f = [{'type': t, 'inputStrength': strength, 'outputStrength': strength} for t in CONTENT_FILTERS]
    return {'filtersConfig': f + [{'type': 'PROMPT_ATTACK', 'inputStrength': strength,
                                   'outputStrength': 'NONE'}]}

def create_guardrail(auth, name, strength='HIGH', pii=None, pii_action='ANONYMIZE',
                     denied_topics=None, blocked_words=None, kms_key_arn=None,
                     blocked_message='This request cannot be answered.', tags=None,
                     **compliance_opts) -> dict:
    'Create a Bedrock guardrail with strict content filters and PII redaction. Idempotent by name.'
    c = auth.client('bedrock')
    kw = dict(name=name,
              description=f'awseasy guardrail for {name}',
              contentPolicyConfig=_content_policy(strength),
              sensitiveInformationPolicyConfig={'piiEntitiesConfig': [
                  {'type': t, 'action': pii_action} for t in (pii if pii is not None else PII_ENTITIES)]},
              blockedInputMessaging=blocked_message,
              blockedOutputsMessaging=blocked_message,
              tags=tag_list(tags, 'key', 'value'))
    if denied_topics:
        kw['topicPolicyConfig'] = {'topicsConfig': [
            {'name': t['name'], 'definition': t['definition'], 'type': 'DENY',
             'examples': t.get('examples', [])} for t in denied_topics]}
    if blocked_words:
        kw['wordPolicyConfig'] = {'wordsConfig': [{'text': w} for w in blocked_words]}
    if kms_key_arn: kw['kmsKeyId'] = kms_key_arn
    try: return c.create_guardrail(**kw)
    except c.exceptions.ConflictException:
        return next(g for g in c.list_guardrails()['guardrails'] if g['name'] == name)

def guardrail_ref(guardrail) -> tuple:
    'Turn a create_guardrail response into the (id, version) pair converse() expects.'
    return guardrail['guardrailId'], guardrail.get('version', 'DRAFT')

# %% code
GUARDRAIL_REPLY = {'guardrailId': 'abc123', 'guardrailArn': 'arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123',
                   'version': 'DRAFT', 'createdAt': '2026-01-01T00:00:00Z'}

auth = stub_auth()
with Stubber(auth.client('bedrock')) as stub:
    stub.add_response('create_guardrail', GUARDRAIL_REPLY, {
        'name': 'app-guardrail',
        'description': ANY,
        'contentPolicyConfig': _content_policy('HIGH'),
        'sensitiveInformationPolicyConfig': {'piiEntitiesConfig': [
            {'type': t, 'action': 'ANONYMIZE'} for t in PII_ENTITIES]},
        'blockedInputMessaging': ANY, 'blockedOutputsMessaging': ANY, 'tags': []})
    g = create_guardrail(auth, 'app-guardrail')
    assert guardrail_ref(g) == ('abc123', 'DRAFT')
    stub.assert_no_pending_responses()

# every content category is filtered, and prompt-injection defence is on
pol = _content_policy('HIGH')['filtersConfig']
kinds = {f['type'] for f in pol}
assert kinds == set(CONTENT_FILTERS) | {'PROMPT_ATTACK'}
assert all(f['inputStrength'] == 'HIGH' for f in pol)
# PROMPT_ATTACK is an input-only filter; sending an output strength for it is rejected by Bedrock
assert next(f for f in pol if f['type'] == 'PROMPT_ATTACK')['outputStrength'] == 'NONE'
# credentials and identifiers are masked before they ever reach the model
assert {'AWS_SECRET_KEY', 'US_SOCIAL_SECURITY_NUMBER', 'CREDIT_DEBIT_CARD_NUMBER'} <= set(PII_ENTITIES)
print('guardrail defaults OK')

# %% code
auth = stub_auth()
with Stubber(auth.client('bedrock')) as stub:
    stub.add_response('create_guardrail', GUARDRAIL_REPLY, {
        'name': 'legal-guardrail', 'description': ANY,
        'contentPolicyConfig': _content_policy('MEDIUM'),
        'sensitiveInformationPolicyConfig': {'piiEntitiesConfig': [{'type': 'EMAIL', 'action': 'BLOCK'}]},
        'topicPolicyConfig': {'topicsConfig': [
            {'name': 'LegalAdvice', 'definition': 'Advice a licensed attorney should give.',
             'type': 'DENY', 'examples': ['Should I sue?']}]},
        'wordPolicyConfig': {'wordsConfig': [{'text': 'competitor-x'}]},
        'kmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/k1',
        'blockedInputMessaging': 'Not supported.', 'blockedOutputsMessaging': 'Not supported.',
        'tags': [{'key': 'env', 'value': 'prod'}]})
    create_guardrail(auth, 'legal-guardrail', strength='MEDIUM', pii=['EMAIL'], pii_action='BLOCK',
                     denied_topics=[{'name': 'LegalAdvice',
                                     'definition': 'Advice a licensed attorney should give.',
                                     'examples': ['Should I sue?']}],
                     blocked_words=['competitor-x'], blocked_message='Not supported.',
                     kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/k1', tags={'env': 'prod'})
    stub.assert_no_pending_responses()
print('guardrail customisation OK')

# %% md
# ## Least-privilege Bedrock policy
#
# `AmazonBedrockFullAccess` grants every Bedrock action on every resource in the account. For a
# stack that invokes two models and reads one bucket, that is several orders of magnitude more
# access than the job needs. `bedrock_policy` builds the policy the job actually requires.

# %% export
def bedrock_policy(auth, models=None, bucket=None, kms_key_arn=None, collection_arn=None) -> dict:
    'Least-privilege policy: invoke only the named models, read only the named bucket and key.'
    p = auth.partition
    model_arns = [f'arn:{p}:bedrock:{auth.region}::foundation-model/{m}'
                  for m in (models or [DEFAULT_MODEL, EMBED_MODEL])]
    stmts = [{'Sid': 'InvokeNamedModels', 'Effect': 'Allow',
              'Action': ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream',
                         'bedrock:Converse', 'bedrock:ConverseStream',
                         'bedrock:ApplyGuardrail'],
              'Resource': model_arns}]
    if bucket:
        b = auth.arn_for('s3', bucket, region='', account=False)
        stmts.append({'Sid': 'ReadStackBucket', 'Effect': 'Allow',
                      'Action': ['s3:GetObject', 's3:ListBucket'], 'Resource': [b, f'{b}/*']})
    if kms_key_arn:
        stmts.append({'Sid': 'UseStackKey', 'Effect': 'Allow',
                      'Action': ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey'],
                      'Resource': kms_key_arn})
    if collection_arn:
        stmts.append({'Sid': 'QueryVectorStore', 'Effect': 'Allow',
                      'Action': 'aoss:APIAccessAll', 'Resource': collection_arn})
    return {'Version': '2012-10-17', 'Statement': stmts}

# %% code
auth = stub_auth()
pol = bedrock_policy(auth, bucket='docs', kms_key_arn='arn:aws:kms:us-east-1:123456789012:key/k1')
sids = {s['Sid']: s for s in pol['Statement']}

# no wildcards anywhere: every statement names the exact resources it may touch
assert all('*' not in r or r.endswith('/*') for s in pol['Statement']
           for r in ([s['Resource']] if isinstance(s['Resource'], str) else s['Resource']))
assert sids['InvokeNamedModels']['Resource'] == [
    f'arn:aws:bedrock:us-east-1::foundation-model/{DEFAULT_MODEL}',
    f'arn:aws:bedrock:us-east-1::foundation-model/{EMBED_MODEL}']
assert sids['ReadStackBucket']['Resource'] == ['arn:aws:s3:::docs', 'arn:aws:s3:::docs/*']
assert 's3:DeleteObject' not in sids['ReadStackBucket']['Action'], 'read-only means read-only'
assert sids['UseStackKey']['Action'] == ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey']
assert 'QueryVectorStore' not in sids   # only added when a collection is passed

only_models = bedrock_policy(auth, models=['anthropic.claude-3-haiku-20240307-v1:0'])
assert len(only_models['Statement']) == 1
print(json.dumps(pol, indent=1)[:400])

# %% md
# ## Vector store: OpenSearch Serverless
#
# A Bedrock Knowledge Base stores its embeddings in an **OpenSearch Serverless collection** —
# not in an OpenSearch managed domain, which is a different service with a different ARN shape.
# `create_aoss_collection` creates the three policies a collection needs before it will accept
# any traffic (encryption, network, data access) and then the collection itself.
#
# The network policy defaults to `AllowFromPublic: False`, so the collection is reachable only
# through a VPC endpoint.

# %% export
def _aoss_policies(auth, name, role_arns, kms_key_arn, public):
    'The three policies an AOSS collection needs before it will accept traffic.'
    res = [f'collection/{name}']
    enc = {'Rules': [{'ResourceType': 'collection', 'Resource': res}]}
    if kms_key_arn: enc['KmsARN'] = kms_key_arn
    else:           enc['AWSOwnedKey'] = True
    net = [{'Rules': [{'ResourceType': 'collection', 'Resource': res},
                      {'ResourceType': 'dashboard', 'Resource': res}],
            'AllowFromPublic': public}]
    access = [{'Rules': [{'ResourceType': 'collection', 'Resource': res,
                          'Permission': ['aoss:CreateCollectionItems', 'aoss:DescribeCollectionItems',
                                         'aoss:UpdateCollectionItems']},
                         {'ResourceType': 'index', 'Resource': [f'index/{name}/*'],
                          'Permission': ['aoss:CreateIndex', 'aoss:DescribeIndex', 'aoss:ReadDocument',
                                         'aoss:WriteDocument', 'aoss:UpdateIndex']}],
               'Principal': list(role_arns or []) + [auth.arn]}]
    return enc, net, access

def create_aoss_collection(auth, name, role_arns=None, kms_key_arn=None, public=False,
                           tags=None, **compliance_opts) -> dict:
    'Create an OpenSearch Serverless vector collection with its encryption, network, and access policies.'
    c = auth.client('opensearchserverless')
    enc, net, access = _aoss_policies(auth, name, role_arns, kms_key_arn, public)
    for kind, pol in (('encryption', enc), ('network', net)):
        try: c.create_security_policy(name=f'{name}-{kind}', type=kind, policy=json.dumps(pol))
        except c.exceptions.ConflictException: pass
    try: c.create_access_policy(name=f'{name}-access', type='data', policy=json.dumps(access))
    except c.exceptions.ConflictException: pass
    try:
        return c.create_collection(name=name, type='VECTORSEARCH',
                                   tags=tag_list(tags, 'key', 'value'))['createCollectionDetail']
    except c.exceptions.ConflictException:
        return c.batch_get_collection(names=[name])['collectionDetails'][0]

def aoss_endpoint(auth, name) -> str:
    'HTTPS endpoint of an AOSS collection.'
    d = auth.client('opensearchserverless').batch_get_collection(names=[name])['collectionDetails'][0]
    return d['collectionEndpoint']

# %% code
# The policy documents are pure functions, so assert on them directly.
auth = stub_auth()
enc, net, access = _aoss_policies(auth, 'demo', ['arn:aws:iam::123456789012:role/kb'], None, False)
assert enc['AWSOwnedKey'] is True and enc['Rules'][0]['Resource'] == ['collection/demo']
assert net[0]['AllowFromPublic'] is False, 'a vector store must not be open to the internet'
# the KB role and the caller can both reach the collection; nobody else can
assert access[0]['Principal'] == ['arn:aws:iam::123456789012:role/kb', auth.arn]
assert 'aoss:DeleteIndex' not in access[0]['Rules'][1]['Permission']

enc_cmk, _, _ = _aoss_policies(auth, 'demo', None, 'arn:aws:kms:us-east-1:123456789012:key/k1', False)
assert 'AWSOwnedKey' not in enc_cmk and enc_cmk['KmsARN'].endswith('key/k1')
print(json.dumps(net, indent=1))

# %% code
COLLECTION = {'id': 'abc', 'name': 'demo', 'type': 'VECTORSEARCH', 'status': 'CREATING',
              'arn': 'arn:aws:aoss:us-east-1:123456789012:collection/abc'}

auth = stub_auth()
c = auth.client('opensearchserverless')
with Stubber(c) as stub:
    for kind in ('encryption', 'network'):
        stub.add_response('create_security_policy', {'securityPolicyDetail': {'name': f'demo-{kind}'}},
                          {'name': f'demo-{kind}', 'type': kind, 'policy': ANY})
    stub.add_response('create_access_policy', {'accessPolicyDetail': {'name': 'demo-access'}},
                      {'name': 'demo-access', 'type': 'data', 'policy': ANY})
    stub.add_response('create_collection', {'createCollectionDetail': COLLECTION},
                      {'name': 'demo', 'type': 'VECTORSEARCH', 'tags': []})
    col = create_aoss_collection(auth, 'demo')
    assert col['arn'].startswith('arn:aws:aoss:')
    stub.assert_no_pending_responses()
print('AOSS collection OK')

# %% md
# ## Bedrock Knowledge Base
#
# `create_kb` wires an S3 bucket of documents to the vector collection above. The collection ARN
# is a required argument rather than a string built from the name — building it by convention is
# how a knowledge base ends up silently pointing at a collection that does not exist.
#
# Ingestion is not automatic: call `sync_kb()` after documents land in the bucket, and again
# whenever they change.

# %% export
def create_kb(auth, name, bucket, role_arn, collection_arn, index=None, prefix='',
              embed_model=EMBED_MODEL, description=None, tags=None, **compliance_opts) -> dict:
    'Create a Bedrock Knowledge Base over an AOSS collection, with an S3 data source attached.'
    c = auth.client('bedrock-agent')
    index = index or f'{name}-index'
    kw = dict(name=name, roleArn=role_arn,
              description=description or f'awseasy knowledge base {name}',
              knowledgeBaseConfiguration={
                  'type': 'VECTOR',
                  'vectorKnowledgeBaseConfiguration': {
                      'embeddingModelArn':
                          f'arn:{auth.partition}:bedrock:{auth.region}::foundation-model/{embed_model}'}},
              storageConfiguration={
                  'type': 'OPENSEARCH_SERVERLESS',
                  'opensearchServerlessConfiguration': {
                      'collectionArn': collection_arn,
                      'vectorIndexName': index,
                      'fieldMapping': {'vectorField': 'embedding', 'textField': 'content',
                                       'metadataField': 'metadata'}}},
              tags=tags or {})
    kb = c.create_knowledge_base(**kw)['knowledgeBase']
    kb['dataSource'] = kb_data_source(auth, kb['knowledgeBaseId'], bucket, prefix)
    return kb

def kb_data_source(auth, kb_id, bucket, prefix='') -> dict:
    'Attach an S3 bucket (optionally one prefix of it) to a knowledge base as a data source.'
    s3 = {'bucketArn': auth.arn_for('s3', bucket, region='', account=False)}
    if prefix: s3['inclusionPrefixes'] = [prefix]
    return auth.client('bedrock-agent').create_data_source(
        knowledgeBaseId=kb_id, name=f'{kb_id}-s3',
        dataSourceConfiguration={'type': 'S3', 's3Configuration': s3})['dataSource']

def sync_kb(auth, kb_id, data_source_id) -> dict:
    'Start an ingestion job. Documents are not indexed until this runs.'
    return auth.client('bedrock-agent').start_ingestion_job(
        knowledgeBaseId=kb_id, dataSourceId=data_source_id)['ingestionJob']

# %% code
from datetime import datetime

COL_ARN = 'arn:aws:aoss:us-east-1:123456789012:collection/abc'
NOW = datetime(2026, 1, 1)
KB_REPLY = {'knowledgeBase': {
    'knowledgeBaseId': 'KB123', 'name': 'docs-kb',
    'knowledgeBaseArn': 'arn:aws:bedrock:us-east-1:123456789012:knowledge-base/KB123',
    'roleArn': 'arn:aws:iam::123456789012:role/kb-role', 'status': 'CREATING',
    'createdAt': NOW, 'updatedAt': NOW,
    'knowledgeBaseConfiguration': {'type': 'VECTOR'}}}
DS_REPLY = {'dataSource': {
    'knowledgeBaseId': 'KB123', 'dataSourceId': 'DS123', 'name': 'KB123-s3', 'status': 'AVAILABLE',
    'createdAt': NOW, 'updatedAt': NOW,
    'dataSourceConfiguration': {'type': 'S3', 's3Configuration': {'bucketArn': 'arn:aws:s3:::docs-bucket'}}}}

auth = stub_auth()
with Stubber(auth.client('bedrock-agent')) as stub:
    stub.add_response('create_knowledge_base', KB_REPLY, {
        'name': 'docs-kb', 'roleArn': 'arn:aws:iam::123456789012:role/kb-role', 'description': ANY,
        'knowledgeBaseConfiguration': {
            'type': 'VECTOR',
            'vectorKnowledgeBaseConfiguration': {
                'embeddingModelArn': f'arn:aws:bedrock:us-east-1::foundation-model/{EMBED_MODEL}'}},
        # the collection ARN is the one we were given, not one reconstructed from the name
        'storageConfiguration': {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': COL_ARN, 'vectorIndexName': 'docs-kb-index',
                'fieldMapping': {'vectorField': 'embedding', 'textField': 'content',
                                 'metadataField': 'metadata'}}},
        'tags': {}})
    stub.add_response('create_data_source', DS_REPLY, {
        'knowledgeBaseId': 'KB123', 'name': 'KB123-s3',
        'dataSourceConfiguration': {'type': 'S3',
                                    's3Configuration': {'bucketArn': 'arn:aws:s3:::docs-bucket'}}})
    kb = create_kb(auth, 'docs-kb', bucket='docs-bucket',
                   role_arn='arn:aws:iam::123456789012:role/kb-role', collection_arn=COL_ARN)
    assert kb['knowledgeBaseId'] == 'KB123' and kb['dataSource']['dataSourceId'] == 'DS123'
    stub.assert_no_pending_responses()

# a prefix scopes ingestion to one folder instead of the whole bucket
auth = stub_auth()
with Stubber(auth.client('bedrock-agent')) as stub:
    stub.add_response('create_data_source', DS_REPLY, {
        'knowledgeBaseId': 'KB123', 'name': 'KB123-s3',
        'dataSourceConfiguration': {'type': 'S3', 's3Configuration': {
            'bucketArn': 'arn:aws:s3:::docs-bucket', 'inclusionPrefixes': ['policies/']}}})
    kb_data_source(auth, 'KB123', 'docs-bucket', prefix='policies/')
    stub.assert_no_pending_responses()
print('knowledge base OK')

# %% md
# ## OpenSearch managed domains
#
# Distinct from the serverless collection above: a managed domain is for keyword and hybrid
# search over your own indices, not for Knowledge Base embeddings.
#
# Fine-grained access control is enabled by default, which requires a master user. The password is
# generated here and written straight to Secrets Manager at `opensearch/<name>/admin` — it is never
# returned, printed, or placed in the domain description.

# %% export
def _password(n=24) -> str:
    'Password meeting the OpenSearch master-user rules: upper, lower, digit, and symbol.'
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, '!@#$%^&*()-_=+']
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(''.join(pools)) for _ in range(n - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)

def create_opensearch(auth, name, engine_version='OpenSearch_2.13', instance_type='r6g.large.search',
                      instance_count=1, volume_size=20, master_user='os-admin', kms_key_id=None,
                      subnet_ids=None, sg_ids=None, audit=False, wait=False, tags=None,
                      **compliance_opts) -> dict:
    'Create an OpenSearch domain with TLS 1.2, encryption everywhere, and fine-grained access control.'
    c = auth.client('opensearch')
    password = _password()
    kw = dict(
        DomainName=name, EngineVersion=engine_version,
        ClusterConfig={'InstanceType': instance_type, 'InstanceCount': instance_count,
                       'ZoneAwarenessEnabled': instance_count > 1},
        EBSOptions={'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': volume_size},
        EncryptionAtRestOptions={'Enabled': True, **({'KmsKeyId': kms_key_id} if kms_key_id else {})},
        NodeToNodeEncryptionOptions={'Enabled': True},
        DomainEndpointOptions={'EnforceHTTPS': True,
                               'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-2019-07'},
        AdvancedSecurityOptions={'Enabled': True, 'InternalUserDatabaseEnabled': True,
                                 'MasterUserOptions': {'MasterUserName': master_user,
                                                       'MasterUserPassword': password}},
        TagList=tag_list(named(name, tags)))
    if subnet_ids: kw['VPCOptions'] = {'SubnetIds': subnet_ids, 'SecurityGroupIds': sg_ids or []}
    if audit:
        kw['LogPublishingOptions'] = {'AUDIT_LOGS': {
            'CloudWatchLogsLogGroupArn': auth.arn_for('logs', f'log-group:/aws/opensearch/{name}'),
            'Enabled': True}}
    try:
        domain = c.create_domain(**kw)['DomainStatus']
        # The only copy of the password leaves this process straight into Secrets Manager.
        create_secret(auth, f'opensearch/{name}/admin',
                      {'username': master_user, 'password': password},
                      kms_key_id=kms_key_id, description=f'OpenSearch master user for {name}')
    except c.exceptions.ResourceAlreadyExistsException:
        domain = c.describe_domain(DomainName=name)['DomainStatus']
    if wait:
        # OpenSearch has no boto3 waiter; Processing stays true until the domain settles.
        domain = poll_until(lambda: c.describe_domain(DomainName=name)['DomainStatus'],
                            lambda d: not d.get('Processing') and d.get('Endpoint'),
                            desc=f'OpenSearch domain {name}')
    return domain

def opensearch_endpoint(auth, name) -> str:
    'HTTPS endpoint of an OpenSearch domain.'
    d = auth.client('opensearch').describe_domain(DomainName=name)['DomainStatus']
    return f"https://{d['Endpoint']}"

def opensearch_admin_creds(auth, name) -> dict:
    'Master user credentials stored by create_opensearch, as {username, password}.'
    return get_secret(auth, f'opensearch/{name}/admin')

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    key = create_kms_key(auth, 'search-key')
    d = create_opensearch(auth, 'app-search', kms_key_id=key['Arn'], **ISO27001)

    assert d['EncryptionAtRestOptions']['Enabled'] and d['NodeToNodeEncryptionOptions']['Enabled']
    assert d['DomainEndpointOptions']['EnforceHTTPS']
    assert d['DomainEndpointOptions']['TLSSecurityPolicy'] == 'Policy-Min-TLS-1-2-2019-07'
    assert d['AdvancedSecurityOptions']['Enabled'], 'without FGAC the domain has no authorization at all'

    # the password never appears in the create_domain response we hand back
    assert 'MasterUserPassword' not in json.dumps(d)

    creds = opensearch_admin_creds(auth, 'app-search')
    assert creds['username'] == 'os-admin' and len(creds['password']) == 24
    assert create_opensearch(auth, 'app-search')['DomainName'] == 'app-search'   # idempotent
    print('OpenSearch domain OK')

# %% code
# Generated passwords satisfy the OpenSearch master-user complexity rules every time.
for _ in range(50):
    p = _password()
    assert len(p) == 24
    assert any(c.isupper() for c in p) and any(c.islower() for c in p)
    assert any(c.isdigit() for c in p) and any(c in '!@#$%^&*()-_=+' for c in p)
assert len({_password() for _ in range(50)}) == 50, 'passwords must not repeat'
print('password generation OK')

# %% hide
import nbdev; nbdev.nbdev_export()
