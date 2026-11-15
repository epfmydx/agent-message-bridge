"""Explicit sign-in intent keeps legacy routing IDs distinct from owner email."""
import base64
import hashlib
from urllib.parse import urlencode, urlsplit

from sqlalchemy import select, text
from werkzeug.security import generate_password_hash
import pytest

from bridge.app import create_app
from bridge.invitations import create_invitation
from bridge.models import Participant
from bridge.models_auth import BrowserOwner, LoginRate, User
from test_migration import legacy, migrate
from test_profiles import BASE, HEADERS, get, hidden, post


def add_legacy_bot(f, ident, password):
    with f.engine.begin() as c:
        c.execute(text("INSERT INTO participants(id,name,managed_source,active,sequence) VALUES (:id,'Legacy Bot','config',true,0)"),{'id':ident})
        c.execute(text("INSERT INTO oauth_users(id,email,managed_source,password_hash,api_key_hash,active) VALUES (:id,'private-contact@example.com','config',:password,NULL,true)"),dict(id=ident,password=generate_password_hash(password)))
    f.mapping['participants'].append(dict(id=ident,owner_id='owner-a',stable_id='private-collision-label'))


def login(client, mode, identifier, password):
    page=get(client,'/login?mode='+mode)
    assert page.status_code==200 and hidden(page,'mode')==mode
    return post(client,'/login',data=dict(mode=mode,csrf=hidden(page,'csrf'),email=identifier,password=password))


def account(client):
    with client.session_transaction(base_url=BASE) as cookie:
        return cookie.get('account_kind'),cookie.get('owner')


@pytest.mark.parametrize('same_password',[False,True])
def test_migrated_email_shaped_bot_and_owner_both_sign_in_by_explicit_intent(legacy,same_password):
    f=legacy;ident='owner-a@example.com';bot_password='synthetic-password' if same_password else 'synthetic-bot-password'
    add_legacy_bot(f,ident,bot_password);migrate(f,apply=True)
    app=create_app(f.settings);app.config['TESTING']=True
    try:
        owner=app.test_client();bot=app.test_client()
        assert login(owner,'owner',ident,'synthetic-password').status_code==302
        assert account(owner)==('owner','owner-a')
        assert get(owner,'/profiles').status_code==200
        assert login(bot,'bot',ident,'wrong-password').status_code==200
        failed=post(bot,'/login',data=dict(mode='bot',csrf=hidden(get(bot,'/login?mode=bot'),'csrf'),email=ident,password='wrong-password'))
        assert b'Sign-in details are incorrect.' in failed.data and hidden(failed,'mode')=='bot'
        assert account(bot)==(None,None)
        assert post(bot,'/login',data=dict(mode=hidden(failed,'mode'),csrf=hidden(failed,'csrf'),email=ident,password=bot_password)).status_code==302
        assert account(bot)==('participant',ident)
        assert get(bot,'/profiles').status_code==403
        assert get(bot,'/oauth/connections').status_code==200
        if not same_password:
            assert login(app.test_client(),'owner',ident,bot_password).status_code==200
            assert login(app.test_client(),'bot',ident,'synthetic-password').status_code==200
        with app.extensions['sessions']() as db:
            assert db.get(User,ident).email=='private-contact@example.com'
    finally:app.extensions['engine'].dispose()


def test_later_owner_registration_cannot_shadow_legacy_bot_sign_in(legacy):
    f=legacy;ident='later-owner@example.com';add_legacy_bot(f,ident,'synthetic-bot-password');migrate(f,apply=True)
    app=create_app(f.settings);app.config['TESTING']=True
    try:
        with app.extensions['sessions'].begin() as db:
            _,raw=create_invitation(db,db.get(BrowserOwner,'owner-a'))
        client=app.test_client();page=get(client,'/register')
        result=post(client,'/register',data=dict(csrf=hidden(page,'csrf'),name='Later Owner',email=ident,password='synthetic-new-owner-password',code=raw))
        assert result.status_code==303
        assert login(client,'owner',ident,'synthetic-new-owner-password').status_code==302
        kind,new_owner=account(client)
        assert kind=='owner' and new_owner!=ident
        bot=app.test_client();assert login(bot,'bot',ident,'synthetic-bot-password').status_code==302
        assert account(bot)==('participant',ident)
    finally:app.extensions['engine'].dispose()


def test_oauth_return_and_failed_retry_keep_bot_mode_across_switching(legacy):
    f=legacy;ident='owner-a@example.com';add_legacy_bot(f,ident,'synthetic-bot-password');migrate(f,apply=True)
    app=create_app(f.settings);app.config['TESTING']=True
    try:
        client=app.test_client();callback='https://client.example.com/cb'
        registered=client.post('/oauth/register',base_url=BASE,json=dict(redirect_uris=[callback],token_endpoint_auth_method='none'))
        assert registered.status_code==201
        params=dict(client_id=registered.json['client_id'],redirect_uri=callback,response_type='code',scope='bridge:messages',resource=BASE+'/mcp',code_challenge='A'*43,code_challenge_method='S256')
        target='/oauth/authorize?'+urlencode(params)
        redirect=get(client,target)
        assert redirect.status_code==302 and redirect.location=='/login?mode=bot'
        get(client,'/login?mode=owner')
        page=get(client,redirect.location)
        failed=post(client,'/login',data=dict(csrf=hidden(page,'csrf'),mode='bot',email=ident,password='wrong'))
        assert hidden(failed,'mode')=='bot'
        success=post(client,'/login',data=dict(csrf=hidden(failed,'csrf'),mode=hidden(failed,'mode'),email=ident,password='synthetic-bot-password'))
        assert success.status_code==302 and success.location==target
        consent=get(client,success.location)
        assert consent.status_code==200 and b'Connect' in consent.data
        approved=post(client,'/oauth/authorize',data={**params,'csrf':hidden(consent,'csrf'),'approve':'yes'})
        assert approved.status_code==302 and approved.location.startswith(callback+'?code=')
        assert account(client)==('participant',ident)
    finally:app.extensions['engine'].dispose()


def test_modes_have_uniform_failed_hash_work_and_keep_guard_csrf_and_rate_budget(legacy,monkeypatch):
    f=legacy;ident='owner-a@example.com';add_legacy_bot(f,ident,'synthetic-bot-password');migrate(f,apply=True)
    with f.sessions.begin() as db:db.get(User,'agent-b').password_hash=generate_password_hash('synthetic-other',method='pbkdf2:sha256:1000')
    app=create_app(f.settings);app.config['TESTING']=True
    try:
        import bridge.auth as auth
        original=auth.check_password_hash;methods=[]
        def checked(value,password):
            methods.append(value.split('$',1)[0]);return original(value,password)
        monkeypatch.setattr(auth,'check_password_hash',checked)
        client=app.test_client();page=get(client,'/login?mode=bot');csrf=hidden(page,'csrf')
        for mode,name in [('bot',ident),('owner',ident),('invalid',ident),('bot','missing'),('owner','missing')]:
            methods.clear()
            result=post(client,'/login',data=dict(mode=mode,csrf=csrf,email=name,password='synthetic-password' if mode=='invalid' else 'wrong'))
            assert result.status_code==200 and b'Sign-in details are incorrect.' in result.data
            assert sorted(methods)==['pbkdf2:sha256:1000','scrypt:32768:8:1']
            assert account(client)==(None,None)
        assert get(client,'/login?mode=invalid').status_code==400
        assert post(client,'/login',data=dict(mode='bot',csrf='bad',email=ident,password='synthetic-bot-password')).status_code==400
        assert client.get('/login?mode=bot',base_url=BASE).status_code==403
        with app.extensions['sessions']() as db:
            counters=list(db.scalars(select(LoginRate)))
            assert len(counters)==1 and len(counters[0].attempts)==6
    finally:app.extensions['engine'].dispose()
