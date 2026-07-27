# %% md
# # auth
# > Enterprise OAuth 2.0 / OIDC sign-in with Amazon Cognito: SSO federation, app clients, JWT verification, and ALB-enforced login.

# %% md
#
# Enterprises do not want another username and password. They want their staff to sign in with
# the identity provider they already run — Microsoft Entra ID, Okta, Google Workspace, or any
# SAML 2.0 IdP — and they want the app to see a verified identity with group claims attached.
#
# A Cognito user pool is the OAuth 2.0 authorization server that makes that happen. This module
# covers the whole path:
#
# 1. `create_user_pool` — the authorization server, with enterprise defaults (no self-signup, MFA on).
# 2. `add_saml_idp` / `add_entra_idp` / `add_okta_idp` / `add_google_idp` — federate the corporate IdP.
# 3. `create_app_client` — an OAuth client restricted to the authorization-code flow.
# 4. `verify_jwt` — validate the token your API receives.
# 5. `protect_listener` — put every request behind SSO at the load balancer, with no app code at all.

# %% code
#| default_exp auth

# %% hide
from nbdev.showdoc import *

# %% export
import json, time
from urllib.parse import urlencode, urlparse
from fastcore.all import L, first
from awseasy.core import tag_list

# %% hide
import os
os.environ.update(AWS_ACCESS_KEY_ID='testing', AWS_SECRET_ACCESS_KEY='testing',
                  AWS_SECURITY_TOKEN='testing', AWS_SESSION_TOKEN='testing',
                  AWS_DEFAULT_REGION='us-east-1',
                  MOTO_IAM_LOAD_MANAGED_POLICIES='true')
from moto import mock_aws
from awseasy.core import AWSAuth, HIPAA, ISO27001, SOC2
from awseasy.network import add_subnet, create_alb, create_security_group, create_vpc, target_group

# %% md
# ## User pools
#
# The defaults are the ones an enterprise deployment wants and that Cognito does *not* give you
# out of the box:
#
# - **No self-signup** (`AllowAdminCreateUserOnly`) — accounts come from the corporate IdP or an
#   administrator. A pool that anyone on the internet can register with is not an enterprise login.
# - **MFA required**, with TOTP enabled, for any native (non-federated) user.
# - **Threat protection enforced** — Cognito blocks credential-stuffing and known-compromised
#   passwords rather than only reporting them.
# - **12-character passwords** with all four character classes.
# - **Deletion protection**, so the pool holding every user identity cannot be deleted by accident.

# %% export
PASSWORD_POLICY = {'MinimumLength': 12, 'RequireUppercase': True, 'RequireLowercase': True,
                   'RequireNumbers': True, 'RequireSymbols': True,
                   'TemporaryPasswordValidityDays': 3}

def create_user_pool(auth, name, mfa_required=True, self_signup=False, threat_protection=True,
                     password_policy=None, deletion_protection=True, tags=None,
                     **compliance_opts) -> dict:
    'Create a Cognito user pool with enterprise defaults. Idempotent by pool name.'
    c = auth.client('cognito-idp')
    found = first(p for p in c.list_user_pools(MaxResults=60)['UserPools'] if p['Name'] == name)
    if found: return c.describe_user_pool(UserPoolId=found['Id'])['UserPool']
    pool = c.create_user_pool(
        PoolName=name,
        Policies={'PasswordPolicy': password_policy or PASSWORD_POLICY},
        # Federated or admin-created accounts only — the internet cannot sign itself up.
        AdminCreateUserConfig={'AllowAdminCreateUserOnly': not self_signup},
        UserPoolAddOns={'AdvancedSecurityMode': 'ENFORCED' if threat_protection else 'OFF'},
        DeletionProtection='ACTIVE' if deletion_protection else 'INACTIVE',
        AutoVerifiedAttributes=['email'],
        UsernameConfiguration={'CaseSensitive': False},
        AccountRecoverySetting={'RecoveryMechanisms': [{'Priority': 1, 'Name': 'verified_email'}]},
        UserPoolTags=tags or {})['UserPool']
    if mfa_required:
        # MFA cannot be set to ON at create time until a factor exists, so enable TOTP first.
        c.set_user_pool_mfa_config(UserPoolId=pool['Id'], MfaConfiguration='ON',
                                   SoftwareTokenMfaConfiguration={'Enabled': True})
    return c.describe_user_pool(UserPoolId=pool['Id'])['UserPool']

def user_pool_id(auth, name) -> str:
    'Look up a user pool id by name.'
    p = first(p for p in auth.client('cognito-idp').list_user_pools(MaxResults=60)['UserPools']
              if p['Name'] == name)
    if not p: raise ValueError(f'user pool {name!r} not found in {auth.region}')
    return p['Id']

def user_pool_arn(auth, pool_id) -> str:
    'ARN of a user pool, as required by ALB authenticate-cognito actions.'
    return auth.arn_for('cognito-idp', f'userpool/{pool_id}')

def issuer_url(auth, pool_id) -> str:
    'OIDC issuer for the pool — the `iss` claim on every token it mints.'
    return f'https://cognito-idp.{auth.region}.amazonaws.com/{pool_id}'

def jwks_url(auth, pool_id) -> str:
    'Public key set used to verify the pool\'s tokens.'
    return f'{issuer_url(auth, pool_id)}/.well-known/jwks.json'

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    # SOC2 carries mfa_required=True and tags={'compliance': 'soc2'}, so both bind straight through
    pool = create_user_pool(auth, 'myapp-users', **SOC2)
    pid = pool['Id']
    c = auth.client('cognito-idp')
    assert pool['UserPoolTags'] == {'compliance': 'soc2'}

    # nobody can sign themselves up; accounts arrive from the IdP or an admin
    assert pool['AdminCreateUserConfig']['AllowAdminCreateUserOnly'] is True
    assert pool['UserPoolAddOns']['AdvancedSecurityMode'] == 'ENFORCED'
    assert pool['DeletionProtection'] == 'ACTIVE'
    assert c.get_user_pool_mfa_config(UserPoolId=pid)['MfaConfiguration'] == 'ON'

    pol = pool['Policies']['PasswordPolicy']
    assert pol['MinimumLength'] >= 12
    assert all(pol[k] for k in ('RequireUppercase', 'RequireLowercase',
                                'RequireNumbers', 'RequireSymbols'))

    assert create_user_pool(auth, 'myapp-users')['Id'] == pid     # idempotent by name
    assert len(c.list_user_pools(MaxResults=60)['UserPools']) == 1
    assert user_pool_id(auth, 'myapp-users') == pid
    try: user_pool_id(auth, 'nope'); raise AssertionError('should raise')
    except ValueError as e: assert 'not found' in str(e)

    assert user_pool_arn(auth, pid) == f'arn:aws:cognito-idp:us-east-1:123456789012:userpool/{pid}'
    assert issuer_url(auth, pid) == f'https://cognito-idp.us-east-1.amazonaws.com/{pid}'
    assert jwks_url(auth, pid).endswith('/.well-known/jwks.json')
    print(pid, user_pool_arn(auth, pid))

# %% code
with mock_aws():
    # A consumer-style pool is possible, but you have to ask for it explicitly.
    auth = AWSAuth(region='us-east-1')
    pool = create_user_pool(auth, 'open-pool', mfa_required=False, self_signup=True,
                            threat_protection=False, deletion_protection=False)
    assert pool['AdminCreateUserConfig']['AllowAdminCreateUserOnly'] is False
    assert pool['UserPoolAddOns']['AdvancedSecurityMode'] == 'OFF'
    assert pool['DeletionProtection'] == 'INACTIVE'
    assert auth.client('cognito-idp').get_user_pool_mfa_config(
        UserPoolId=pool['Id'])['MfaConfiguration'] == 'OFF'
    print('opt-out defaults OK')

# %% md
# ## Hosted UI domain
#
# The domain hosts the OAuth endpoints (`/oauth2/authorize`, `/oauth2/token`, `/logout`) and the
# sign-in page that redirects staff to the corporate IdP. A prefix domain gives you
# `https://<prefix>.auth.<region>.amazoncognito.com`; passing `cert_arn` uses your own domain
# instead, which is what most enterprises want on the address bar.

# %% export
def create_pool_domain(auth, pool_id, domain, cert_arn=None) -> dict:
    'Create the hosted-UI domain for a pool. Pass cert_arn for a custom domain (cert must be in us-east-1).'
    c = auth.client('cognito-idp')
    kw = {'Domain': domain, 'UserPoolId': pool_id}
    if cert_arn: kw['CustomDomainConfig'] = {'CertificateArn': cert_arn}
    try: c.create_user_pool_domain(**kw)
    except c.exceptions.InvalidParameterException as e:
        if 'already' not in str(e).lower(): raise
    return c.describe_user_pool_domain(Domain=domain)['DomainDescription']

def domain_url(auth, domain) -> str:
    'Base URL of a hosted-UI domain. A custom domain (one containing a dot) is used as given.'
    return domain if '.' in domain else f'https://{domain}.auth.{auth.region}.amazoncognito.com'

def login_url(auth, domain, client_id, redirect_uri, scopes=('openid', 'email', 'profile'),
              idp=None) -> str:
    'Authorization-code login URL. idp= sends the user straight to that IdP, skipping the chooser.'
    q = {'client_id': client_id, 'response_type': 'code', 'scope': ' '.join(scopes),
         'redirect_uri': redirect_uri}
    if idp: q['identity_provider'] = idp
    return f'{domain_url(auth, domain)}/oauth2/authorize?{urlencode(q)}'

def logout_url(auth, domain, client_id, redirect_uri) -> str:
    'Sign the user out of the Cognito session and return them to redirect_uri.'
    return f'{domain_url(auth, domain)}/logout?' + urlencode(
        {'client_id': client_id, 'logout_uri': redirect_uri})

def token_url(auth, domain) -> str:
    'Token endpoint, where the app exchanges an authorization code for tokens.'
    return f'{domain_url(auth, domain)}/oauth2/token'

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pool = create_user_pool(auth, 'dom-users')
    d = create_pool_domain(auth, pool['Id'], 'myapp-123456789012')
    assert d['Domain'] == 'myapp-123456789012'
    assert create_pool_domain(auth, pool['Id'], 'myapp-123456789012')['Domain'] == d['Domain']

base = 'https://myapp-123456789012.auth.us-east-1.amazoncognito.com'
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    assert domain_url(auth, 'myapp-123456789012') == base
    assert domain_url(auth, 'https://login.example.com') == 'https://login.example.com'
    assert token_url(auth, 'myapp-123456789012') == f'{base}/oauth2/token'

    u = login_url(auth, 'myapp-123456789012', 'cid', 'https://app.example.com/cb', idp='EntraID')
    assert u.startswith(f'{base}/oauth2/authorize?')
    # authorization code only — response_type=token would put an access token in the URL fragment
    assert 'response_type=code' in u and 'response_type=token' not in u
    assert 'identity_provider=EntraID' in u
    assert logout_url(auth, 'myapp-123456789012', 'cid', 'https://app.example.com/').startswith(
        f'{base}/logout?')
    print(u)

# %% md
# ## Enterprise identity providers
#
# `add_saml_idp` and `add_oidc_idp` cover any compliant IdP; the three named wrappers just fill in
# the endpoints so you do not have to look them up.
#
# `attr_map` is the part that matters for authorization. Map the IdP's group claim into the token
# and the application can authorize on real corporate group membership instead of a local role
# table that drifts. `GROUP_ATTR` maps the common ones onto Cognito's `custom:groups`.

# %% export
GROUP_ATTR = {'entra': 'groups', 'okta': 'groups', 'google': 'groups', 'saml': 'groups'}
SAML_ATTRS = {
    'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'given_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'family_name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'}
OIDC_ATTRS = {'email': 'email', 'given_name': 'given_name', 'family_name': 'family_name'}

def _put_idp(auth, pool_id, name, kind, details, attr_map) -> dict:
    'Create or update an identity provider. Idempotent by provider name.'
    c = auth.client('cognito-idp')
    existing = {p['ProviderName'] for p in
                c.list_identity_providers(UserPoolId=pool_id, MaxResults=60)['Providers']}
    if name in existing:
        return c.update_identity_provider(UserPoolId=pool_id, ProviderName=name,
                                          ProviderDetails=details,
                                          AttributeMapping=attr_map)['IdentityProvider']
    return c.create_identity_provider(UserPoolId=pool_id, ProviderName=name, ProviderType=kind,
                                      ProviderDetails=details,
                                      AttributeMapping=attr_map)['IdentityProvider']

def add_saml_idp(auth, pool_id, name, metadata_url=None, metadata_file=None, attr_map=None,
                 idp_signout=True) -> dict:
    'Federate a SAML 2.0 IdP (ADFS, Entra ID SAML, Okta SAML, Ping, Shibboleth).'
    if not (metadata_url or metadata_file):
        raise ValueError('pass metadata_url= or metadata_file=')
    details = {'IDPSignout': 'true' if idp_signout else 'false'}
    if metadata_url: details['MetadataURL'] = metadata_url
    else:            details['MetadataFile'] = metadata_file
    return _put_idp(auth, pool_id, name, 'SAML', details, attr_map or SAML_ATTRS)

def add_oidc_idp(auth, pool_id, name, client_id, client_secret, issuer,
                 scopes='openid email profile', attr_map=None, method='GET') -> dict:
    'Federate any OIDC provider by issuer URL; endpoints are discovered from the issuer.'
    return _put_idp(auth, pool_id, name, 'OIDC', {
        'client_id': client_id, 'client_secret': client_secret, 'oidc_issuer': issuer,
        'authorize_scopes': scopes, 'attributes_request_method': method}, attr_map or OIDC_ATTRS)

def add_entra_idp(auth, pool_id, tenant_id, client_id, client_secret, name='EntraID',
                  attr_map=None) -> dict:
    'Federate Microsoft Entra ID (Azure AD) over OIDC for one tenant.'
    return add_oidc_idp(auth, pool_id, name, client_id, client_secret,
                        issuer=f'https://login.microsoftonline.com/{tenant_id}/v2.0',
                        attr_map=attr_map)

def add_okta_idp(auth, pool_id, okta_domain, client_id, client_secret, name='Okta',
                 attr_map=None) -> dict:
    'Federate Okta over OIDC. okta_domain is e.g. "acme.okta.com".'
    issuer = okta_domain if okta_domain.startswith('https://') else f'https://{okta_domain}'
    return add_oidc_idp(auth, pool_id, name, client_id, client_secret,
                        issuer=f'{issuer}/oauth2/default', attr_map=attr_map)

def add_google_idp(auth, pool_id, client_id, client_secret, name='Google',
                   scopes='openid email profile', attr_map=None) -> dict:
    'Federate Google Workspace.'
    return _put_idp(auth, pool_id, name, 'Google',
                    {'client_id': client_id, 'client_secret': client_secret,
                     'authorize_scopes': scopes},
                    attr_map or {'email': 'email', 'given_name': 'given_name',
                                 'family_name': 'family_name'})

def list_idps(auth, pool_id) -> list:
    'Identity provider names configured on a pool.'
    return [p['ProviderName'] for p in
            auth.client('cognito-idp').list_identity_providers(UserPoolId=pool_id,
                                                               MaxResults=60)['Providers']]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pid = create_user_pool(auth, 'idp-users')['Id']

    saml = add_saml_idp(auth, pid, 'CorpADFS', metadata_url='https://adfs.corp/FederationMetadata.xml',
                        attr_map={**SAML_ATTRS, 'custom:groups': 'http://schemas.corp/groups'})
    assert saml['ProviderType'] == 'SAML'
    assert saml['ProviderDetails']['IDPSignout'] == 'true', 'logout must propagate to the IdP'
    # group membership rides in on the token, so the app authorizes on real corporate groups
    assert saml['AttributeMapping']['custom:groups'] == 'http://schemas.corp/groups'

    entra = add_entra_idp(auth, pid, 'tenant-abc', 'app-id', 'app-secret')
    assert entra['ProviderDetails']['oidc_issuer'] == 'https://login.microsoftonline.com/tenant-abc/v2.0'
    okta = add_okta_idp(auth, pid, 'acme.okta.com', 'okta-id', 'okta-secret')
    assert okta['ProviderDetails']['oidc_issuer'] == 'https://acme.okta.com/oauth2/default'
    assert add_okta_idp(auth, pid, 'https://acme.okta.com', 'i', 's',
                        name='Okta2')['ProviderDetails']['oidc_issuer'].count('https://') == 1
    add_google_idp(auth, pid, 'g-id', 'g-secret')

    assert set(list_idps(auth, pid)) == {'CorpADFS', 'EntraID', 'Okta', 'Okta2', 'Google'}

    # re-adding updates in place rather than creating a duplicate provider
    add_entra_idp(auth, pid, 'tenant-xyz', 'app-id', 'new-secret')
    assert len(list_idps(auth, pid)) == 5
    assert auth.client('cognito-idp').describe_identity_provider(
        UserPoolId=pid, ProviderName='EntraID'
    )['IdentityProvider']['ProviderDetails']['oidc_issuer'].endswith('tenant-xyz/v2.0')

    try: add_saml_idp(auth, pid, 'Bad'); raise AssertionError('should raise')
    except ValueError as e: assert 'metadata_url' in str(e)
    print(list_idps(auth, pid))

# %% md
# ## App clients
#
# The app client is where most OAuth misconfigurations live, so several things are enforced
# rather than defaulted:
#
# - **Authorization-code flow only.** `implicit` returns the access token in the URL fragment,
#   where it lands in browser history, referrer headers, and proxy logs. Asking for it raises.
# - **HTTPS callbacks only** (`http://localhost` excepted for development). A plaintext callback
#   hands the authorization code to anyone on the network path.
# - **No password auth flows.** `USER_PASSWORD_AUTH` sends the user's password to your app; with
#   federation the app should never see a password at all.
# - **`PreventUserExistenceErrors`** so failed logins cannot be used to enumerate staff accounts.
# - **Token revocation on**, and one-hour access tokens.

# %% export
def _check_callbacks(urls):
    'Reject plaintext callbacks; localhost is allowed so local development still works.'
    for u in urls:
        p = urlparse(u)
        if p.scheme == 'https': continue
        if p.scheme == 'http' and p.hostname in ('localhost', '127.0.0.1'): continue
        raise ValueError(f'callback {u!r} must use https (http is allowed only on localhost)')

def create_app_client(auth, pool_id, name, callback_urls=None, logout_urls=None, idps=None,
                      scopes=('openid', 'email', 'profile'), generate_secret=True,
                      access_minutes=60, id_minutes=60, refresh_days=1, flows=('code',)) -> dict:
    'Create an OAuth app client restricted to the authorization-code flow. Idempotent by client name.'
    if 'implicit' in flows:
        raise ValueError('the implicit flow exposes tokens in the URL fragment; use flows=("code",)')
    callback_urls = list(callback_urls or [])
    _check_callbacks(callback_urls + list(logout_urls or []))
    c = auth.client('cognito-idp')
    found = first(cl for cl in c.list_user_pool_clients(UserPoolId=pool_id,
                                                        MaxResults=60)['UserPoolClients']
                  if cl['ClientName'] == name)
    if found:
        return c.describe_user_pool_client(UserPoolId=pool_id,
                                           ClientId=found['ClientId'])['UserPoolClient']
    return c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=name, GenerateSecret=generate_secret,
        AllowedOAuthFlows=list(flows), AllowedOAuthScopes=list(scopes),
        AllowedOAuthFlowsUserPoolClient=True,
        CallbackURLs=callback_urls, LogoutURLs=list(logout_urls or []),
        SupportedIdentityProviders=list(idps or list_idps(auth, pool_id) or ['COGNITO']),
        # No USER_PASSWORD_AUTH: the application must never handle a user's password.
        ExplicitAuthFlows=['ALLOW_REFRESH_TOKEN_AUTH'],
        PreventUserExistenceErrors='ENABLED', EnableTokenRevocation=True,
        AccessTokenValidity=access_minutes, IdTokenValidity=id_minutes,
        RefreshTokenValidity=refresh_days,
        TokenValidityUnits={'AccessToken': 'minutes', 'IdToken': 'minutes',
                            'RefreshToken': 'days'})['UserPoolClient']

def app_client_secret(auth, pool_id, client_id) -> str:
    'Client secret for a confidential app client.'
    return auth.client('cognito-idp').describe_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id)['UserPoolClient'].get('ClientSecret', '')

def create_resource_server(auth, pool_id, identifier, scopes, name=None) -> dict:
    'Declare API scopes for machine-to-machine access. scopes is {scope_name: description}.'
    return auth.client('cognito-idp').create_resource_server(
        UserPoolId=pool_id, Identifier=identifier, Name=name or identifier,
        Scopes=[{'ScopeName': k, 'ScopeDescription': v} for k, v in scopes.items()])['ResourceServer']

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pid = create_user_pool(auth, 'client-users')['Id']
    add_entra_idp(auth, pid, 'tenant-abc', 'app-id', 'app-secret')

    cl = create_app_client(auth, pid, 'web', callback_urls=['https://app.example.com/oauth2/callback'],
                           logout_urls=['https://app.example.com/'])
    assert cl['AllowedOAuthFlows'] == ['code']
    assert cl['PreventUserExistenceErrors'] == 'ENABLED'
    assert cl['EnableTokenRevocation'] is True
    # the app never sees a password, so no password-based auth flow is enabled
    assert cl['ExplicitAuthFlows'] == ['ALLOW_REFRESH_TOKEN_AUTH']
    assert 'ALLOW_USER_PASSWORD_AUTH' not in cl['ExplicitAuthFlows']
    assert cl['SupportedIdentityProviders'] == ['EntraID'], 'defaults to the pool\'s configured IdPs'
    assert cl['AccessTokenValidity'] == 60 and cl['TokenValidityUnits']['AccessToken'] == 'minutes'
    assert app_client_secret(auth, pid, cl['ClientId'])

    assert create_app_client(auth, pid, 'web')['ClientId'] == cl['ClientId']   # idempotent

    rs = create_resource_server(auth, pid, 'https://api.example.com',
                                {'read': 'Read data', 'write': 'Write data'})
    assert {s['ScopeName'] for s in rs['Scopes']} == {'read', 'write'}
    print(cl['ClientId'], cl['SupportedIdentityProviders'])

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pid = create_user_pool(auth, 'guard-users')['Id']

    # the implicit flow is refused outright, not merely discouraged
    try:
        create_app_client(auth, pid, 'bad', callback_urls=['https://a/cb'], flows=('code', 'implicit'))
        raise AssertionError('should raise')
    except ValueError as e: assert 'implicit' in str(e)

    # a plaintext callback would leak the authorization code to the network
    try:
        create_app_client(auth, pid, 'bad', callback_urls=['http://app.example.com/cb'])
        raise AssertionError('should raise')
    except ValueError as e: assert 'https' in str(e)

    # localhost over http is still allowed, so local development works
    ok = create_app_client(auth, pid, 'dev', callback_urls=['http://localhost:8000/cb'])
    assert ok['CallbackURLs'] == ['http://localhost:8000/cb']
    print('app client guards OK')

# %% md
# ## Verifying tokens
#
# An API that trusts a JWT without checking its signature trusts anyone who can type one. Cognito
# publishes its public keys at the pool's JWKS URL; `verify_jwt` checks the signature against
# them and then the claims that actually matter:
#
# - `iss` matches this pool — a valid token from a *different* pool is not valid here.
# - `token_use` is the kind you expected. An **access token is not an identity**: it has no `aud`
#   and no verified email, so accepting one where an ID token was meant is an authorization bug.
# - `aud` (ID tokens) or `client_id` (access tokens) matches your app client.
# - `exp` has not passed.
#
# Pass `jwks=` with a cached key set to avoid an HTTPS fetch on every request.

# %% export
def verify_jwt(auth, pool_id, token, client_id=None, use='id', jwks=None, leeway=10) -> dict:
    'Verify a Cognito JWT and return its claims. Raises jwt.InvalidTokenError if anything fails.'
    import jwt
    kid = jwt.get_unverified_header(token).get('kid')
    if jwks is not None:
        key = first(k for k in jwt.PyJWKSet.from_dict(jwks).keys if k.key_id == kid)
        if key is None: raise jwt.InvalidTokenError(f'no key {kid!r} in the supplied JWKS')
        key = key.key
    else:
        key = jwt.PyJWKClient(jwks_url(auth, pool_id)).get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=['RS256'], issuer=issuer_url(auth, pool_id),
                        leeway=leeway, options={'verify_aud': False,
                                                'require': ['exp', 'iss', 'token_use']})
    return check_claims(claims, client_id, use)

def check_claims(claims, client_id=None, use='id') -> dict:
    'Check token_use and audience on already-signature-verified claims. Returns the claims.'
    import jwt
    if use and claims.get('token_use') != use:
        raise jwt.InvalidTokenError(
            f"expected a {use!r} token, got {claims.get('token_use')!r}")
    if client_id:
        # ID tokens carry the app client in `aud`; access tokens carry it in `client_id`.
        got = claims.get('aud') if claims.get('token_use') == 'id' else claims.get('client_id')
        if got != client_id:
            raise jwt.InvalidTokenError(f'token was issued for {got!r}, not {client_id!r}')
    return claims

def token_groups(claims) -> list:
    'Group memberships from a token: the federated IdP groups, else the Cognito groups.'
    g = claims.get('custom:groups') or claims.get('cognito:groups') or []
    return json.loads(g) if isinstance(g, str) and g.startswith('[') else L(g).map(str) if g else []

# %% code
#| hide
# Sign real tokens with a throwaway RSA key so the full verification path runs offline.
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = jwt.algorithms.RSAAlgorithm.to_jwk(_key.public_key(), as_dict=True)
_pub.update(kid='test-key', use='sig', alg='RS256')
JWKS = {'keys': [_pub]}

def make_token(claims, kid='test-key'):
    return jwt.encode(claims, _key, algorithm='RS256', headers={'kid': kid})

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    pool_id, cid = 'us-east-1_abc123', 'client-abc'
    iss = issuer_url(auth, pool_id)
    base = dict(iss=iss, exp=int(time.time()) + 600, sub='u1', email='a@corp.com')

    ok = make_token({**base, 'token_use': 'id', 'aud': cid, 'custom:groups': ['engineering']})
    claims = verify_jwt(auth, pool_id, ok, client_id=cid, jwks=JWKS)
    assert claims['email'] == 'a@corp.com' and token_groups(claims) == ['engineering']

    def rejects(tok, msg, **kw):
        try: verify_jwt(auth, pool_id, tok, jwks=JWKS, **kw); raise AssertionError(f'accepted {msg}')
        except jwt.InvalidTokenError: pass

    # a token minted by a different pool must not authenticate against this one
    rejects(make_token({**base, 'iss': issuer_url(auth, 'us-east-1_other'),
                        'token_use': 'id', 'aud': cid}), 'foreign issuer', client_id=cid)
    rejects(make_token({**base, 'exp': int(time.time()) - 60, 'token_use': 'id', 'aud': cid}),
            'expired token', client_id=cid)
    # an access token is not proof of identity: no aud, no verified email
    rejects(make_token({**base, 'token_use': 'access', 'client_id': cid}), 'access token as id',
            client_id=cid)
    rejects(make_token({**base, 'token_use': 'id', 'aud': 'someone-else'}), 'wrong audience',
            client_id=cid)
    rejects(make_token({**base, 'token_use': 'id', 'aud': cid}, kid='unknown-key'), 'unknown key',
            client_id=cid)

    # a token signed by an attacker's own key fails the signature check
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode({**base, 'token_use': 'id', 'aud': cid}, other, algorithm='RS256',
                        headers={'kid': 'test-key'})
    rejects(forged, 'forged signature', client_id=cid)

    # access tokens verify against client_id, and are what an API should require
    acc = make_token({**base, 'token_use': 'access', 'client_id': cid, 'scope': 'openid'})
    assert verify_jwt(auth, pool_id, acc, client_id=cid, use='access',
                      jwks=JWKS)['scope'] == 'openid'
    print('JWT verification OK')

# %% code
# Groups arrive in several shapes depending on the IdP and the attribute mapping.
assert token_groups({'custom:groups': ['a', 'b']}) == ['a', 'b']
assert token_groups({'custom:groups': '["a", "b"]'}) == ['a', 'b']   # SAML sends a JSON string
assert token_groups({'cognito:groups': ['admins']}) == ['admins']
assert token_groups({'custom:groups': ['idp'], 'cognito:groups': ['local']}) == ['idp']
assert token_groups({}) == []
print('token_groups OK')

# %% md
# ## SSO at the load balancer
#
# An ALB can complete the whole OIDC flow itself: unauthenticated requests are redirected to the
# IdP, and only authenticated ones reach the target — which receives the user's claims in the
# `x-amzn-oidc-data` header. The application needs no login code, no session store, and no
# secret handling.
#
# `protect_listener` puts this on the listener's *default* action, so there is no unauthenticated
# path left. `alb_cognito_rule` does the same for one path prefix when only part of the app needs it.

# %% export
def _cognito_action(pool_arn, client_id, domain, scope, session_timeout, order=1) -> dict:
    return {'Type': 'authenticate-cognito', 'Order': order, 'AuthenticateCognitoConfig': {
        'UserPoolArn': pool_arn, 'UserPoolClientId': client_id, 'UserPoolDomain': domain,
        'Scope': scope, 'SessionTimeout': session_timeout,
        'SessionCookieName': 'AWSELBAuthSessionCookie',
        'OnUnauthenticatedRequest': 'authenticate'}}

def _oidc_action(issuer, client_id, client_secret, endpoints, scope, session_timeout,
                 order=1) -> dict:
    cfg = {'Issuer': issuer, 'ClientId': client_id, 'ClientSecret': client_secret,
           'Scope': scope, 'SessionTimeout': session_timeout,
           'SessionCookieName': 'AWSELBAuthSessionCookie',
           'OnUnauthenticatedRequest': 'authenticate'}
    cfg.update({'AuthorizationEndpoint': endpoints['authorization'],
                'TokenEndpoint': endpoints['token'],
                'UserInfoEndpoint': endpoints['userinfo']})
    return {'Type': 'authenticate-oidc', 'Order': order, 'AuthenticateOidcConfig': cfg}

def protect_listener(auth, listener_arn, target_group_arn, pool_arn, client_id, domain,
                     scope='openid', session_timeout=3600) -> dict:
    'Require Cognito sign-in for every request on a listener. Leaves no unauthenticated path.'
    return auth.client('elbv2').modify_listener(
        ListenerArn=listener_arn,
        DefaultActions=[_cognito_action(pool_arn, client_id, domain, scope, session_timeout),
                        {'Type': 'forward', 'Order': 2,
                         'TargetGroupArn': target_group_arn}])['Listeners'][0]

def alb_cognito_rule(auth, listener_arn, target_group_arn, pool_arn, client_id, domain,
                     paths=('/*',), priority=1, scope='openid', session_timeout=3600) -> dict:
    'Require Cognito sign-in for requests matching `paths` on a listener.'
    return auth.client('elbv2').create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{'Field': 'path-pattern', 'Values': list(paths)}],
        Actions=[_cognito_action(pool_arn, client_id, domain, scope, session_timeout),
                 {'Type': 'forward', 'Order': 2, 'TargetGroupArn': target_group_arn}])['Rules'][0]

def alb_oidc_rule(auth, listener_arn, target_group_arn, issuer, client_id, client_secret,
                  endpoints, paths=('/*',), priority=1, scope='openid email',
                  session_timeout=3600) -> dict:
    '''Authenticate at the ALB against any OIDC provider directly, bypassing Cognito.

    `endpoints` is {authorization, token, userinfo} — take them from the IdP's
    /.well-known/openid-configuration document.'''
    missing = {'authorization', 'token', 'userinfo'} - set(endpoints)
    if missing: raise ValueError(f'endpoints is missing {sorted(missing)}')
    return auth.client('elbv2').create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{'Field': 'path-pattern', 'Values': list(paths)}],
        Actions=[_oidc_action(issuer, client_id, client_secret, endpoints, scope, session_timeout),
                 {'Type': 'forward', 'Order': 2, 'TargetGroupArn': target_group_arn}])['Rules'][0]

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'sso-vpc')
    sns = [add_subnet(auth, vpc['VpcId'], f'10.0.{i}.0/24', f'us-east-1{a}')['SubnetId']
           for i, a in enumerate('ab')]
    sg = create_security_group(auth, 'sso-sg', vpc['VpcId'])
    alb = create_alb(auth, 'sso-alb', sns, [sg['GroupId']])
    tg = target_group(auth, 'sso-tg', vpc['VpcId'])
    cert = auth.client('acm').request_certificate(DomainName='app.example.com',
                                                  ValidationMethod='DNS')['CertificateArn']
    lst = auth.client('elbv2').create_listener(
        LoadBalancerArn=alb['LoadBalancerArn'], Protocol='HTTPS', Port=443,
        Certificates=[{'CertificateArn': cert}],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': tg['TargetGroupArn']}])['Listeners'][0]

    pid = create_user_pool(auth, 'alb-users')['Id']
    cl = create_app_client(auth, pid, 'alb-web',
                           callback_urls=['https://app.example.com/oauth2/idpresponse'])

    out = protect_listener(auth, lst['ListenerArn'], tg['TargetGroupArn'],
                           user_pool_arn(auth, pid), cl['ClientId'], 'myapp-123456789012')
    actions = auth.client('elbv2').describe_listeners(
        ListenerArns=[lst['ListenerArn']])['Listeners'][0]['DefaultActions']
    auth_action = first(a for a in actions if a['Type'] == 'authenticate-cognito')

    # authentication runs first and unauthenticated requests are redirected, never passed through
    assert auth_action['Order'] == 1
    assert auth_action['AuthenticateCognitoConfig']['OnUnauthenticatedRequest'] == 'authenticate'
    assert auth_action['AuthenticateCognitoConfig']['UserPoolArn'].endswith(f'userpool/{pid}')
    assert first(a for a in actions if a['Type'] == 'forward')['Order'] == 2
    print('ALB Cognito SSO OK')

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')
    vpc = create_vpc(auth, 'oidc-vpc')
    sns = [add_subnet(auth, vpc['VpcId'], f'10.0.{i}.0/24', f'us-east-1{a}')['SubnetId']
           for i, a in enumerate('ab')]
    alb = create_alb(auth, 'oidc-alb', sns)
    tg = target_group(auth, 'oidc-tg', vpc['VpcId'])
    lst = auth.client('elbv2').create_listener(
        LoadBalancerArn=alb['LoadBalancerArn'], Protocol='HTTP', Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': tg['TargetGroupArn']}])['Listeners'][0]

    eps = {'authorization': 'https://login.microsoftonline.com/t/oauth2/v2.0/authorize',
           'token': 'https://login.microsoftonline.com/t/oauth2/v2.0/token',
           'userinfo': 'https://graph.microsoft.com/oidc/userinfo'}
    rule = alb_oidc_rule(auth, lst['ListenerArn'], tg['TargetGroupArn'],
                         issuer='https://login.microsoftonline.com/t/v2.0',
                         client_id='cid', client_secret='secret', endpoints=eps, paths=['/app/*'])
    cfg = first(a for a in rule['Actions'] if a['Type'] == 'authenticate-oidc')['AuthenticateOidcConfig']
    assert cfg['Issuer'] == 'https://login.microsoftonline.com/t/v2.0'
    assert cfg['OnUnauthenticatedRequest'] == 'authenticate'
    assert rule['Conditions'][0]['Values'] == ['/app/*']

    # an incomplete endpoint set fails here rather than as a redirect loop in production
    try:
        alb_oidc_rule(auth, lst['ListenerArn'], tg['TargetGroupArn'], issuer='x', client_id='c',
                      client_secret='s', endpoints={'authorization': 'a'}, priority=2)
        raise AssertionError('should raise')
    except ValueError as e: assert 'token' in str(e) and 'userinfo' in str(e)
    print('ALB OIDC SSO OK')

# %% md
# ## End to end
#
# Everything above, in the order you would actually run it.

# %% code
with mock_aws():
    auth = AWSAuth(region='us-east-1')

    pool = create_user_pool(auth, 'acme-users', **ISO27001)
    pid = pool['Id']
    create_pool_domain(auth, pid, f'acme-{auth.account_id}')
    add_entra_idp(auth, pid, tenant_id='11111111-2222-3333-4444-555555555555',
                  client_id='entra-app-id', client_secret='entra-secret',
                  attr_map={**OIDC_ATTRS, 'custom:groups': 'groups'})
    client = create_app_client(auth, pid, 'acme-web',
                               callback_urls=['https://acme.example.com/oauth2/idpresponse'],
                               logout_urls=['https://acme.example.com/'])
    create_resource_server(auth, pid, 'https://api.acme.com', {'documents.read': 'Read documents'})

    url = login_url(auth, f'acme-{auth.account_id}', client['ClientId'],
                    'https://acme.example.com/oauth2/idpresponse', idp='EntraID')
    assert 'identity_provider=EntraID' in url and 'response_type=code' in url
    assert list_idps(auth, pid) == ['EntraID']
    print(url)
    print(f"pool={pid} client={client['ClientId']}")

# %% md
# ### Against a real account
#
# Requires credentials with Cognito permissions. Creates a pool, then deletes it.

# %% noeval
auth = AWSAuth()
pool = create_user_pool(auth, 'awseasy-smoke-test')
print(pool['Id'], issuer_url(auth, pool['Id']))
auth.client('cognito-idp').update_user_pool(UserPoolId=pool['Id'], DeletionProtection='INACTIVE')
auth.client('cognito-idp').delete_user_pool(UserPoolId=pool['Id'])
print('cleaned up')

# %% hide
import nbdev; nbdev.nbdev_export()
