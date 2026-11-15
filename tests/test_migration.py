"""Full published-schema ownership upgrades; fixtures run without Git history."""
import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import make_url
from werkzeug.security import generate_password_hash

from bridge.app import bootstrap, create_app
from bridge.auth import digest, service_family
from bridge.events import identity, cursor
from bridge.messages import canonical
from bridge.migration import migrate_v01
from bridge.models import database, Delivery, Message, Participant, Subscription, now
from bridge.models_auth import BrowserOwner, Token, User
from test_profiles import BASE, HEADERS, hidden


@pytest.fixture(params=['v0.1.0', 'v0.1.1'])
def legacy(request, tmp_path):
    root = os.environ.get('TEST_DATABASE_URL')
    admin = schema = None
    url = 'sqlite:///' + str(tmp_path / 'legacy.sqlite')
    if root:
        admin = create_engine(root, hide_parameters=True)
        schema = 'amb_migration_' + uuid.uuid4().hex
        with admin.begin() as c:
            c.execute(text('CREATE SCHEMA "' + schema + '"'))
        url = make_url(root).update_query_dict({'options':'-csearch_path=' + schema}).render_as_string(hide_password=False)
    engine, sessions = database(url)
    ddl = json.loads((Path(__file__).parent/'fixtures/public-v01-schema.json').read_text())[request.param][engine.dialect.name]
    encryption = Fernet.generate_key().decode()
    timestamp = now()
    password = generate_password_hash('synthetic-password')
    settings = dict(DATABASE_URL=url, BASE_URL=BASE, SECRET_KEY='synthetic-session-secret', ENCRYPTION_KEY=encryption,
                    BROWSER_ADMIN=dict(id='owner-a',name='Owner A',email='owner-a@example.com',password_hash=password),
                    CLOUDFLARE_ORIGIN_SECRET='synthetic-origin-secret-for-agent-message-bridge-1234567890',TRUSTED_PROXY_CIDRS=['127.0.0.1/32'])
    mapping = dict(version=1, admin_owner_id='owner-a', participants=[
        dict(id='agent-a',owner_id='owner-a',stable_id='private-a'),
        dict(id='agent-b',owner_id='owner-b',stable_id='private-b'),
        dict(id='inactive',owner_id='owner-a',stable_id='reserved')])
    legacy_config = tmp_path/'old-config.json'
    legacy_config.write_text(json.dumps(dict(participants=[],owners=[],webhook_participant_id='agent-a')))
    env = dict(ENCRYPTION_KEY=encryption,WEBHOOK_URL='https://receiver.example.com/hook',WEBHOOK_TOKEN='synthetic-legacy-token')
    def insert(c, table, **values):
        cols=','.join(values);binds=','.join(':'+v for v in values)
        c.execute(text('INSERT INTO '+table+' ('+cols+') VALUES ('+binds+')'),values)
    with engine.begin() as c:
        for sql in ddl:c.exec_driver_sql(sql)
        for ident in ['owner-a','owner-b']:
            insert(c,'browser_owners',id=ident,name=ident,email=ident+'@example.com',password_hash=password,active=True)
        for ident in ['agent-a','agent-b','inactive']:
            insert(c,'participants',id=ident,name=ident,managed_source='config' if ident!='agent-b' else 'database',active=ident!='inactive',sequence=1 if ident=='agent-a' else 0)
            insert(c,'oauth_users',id=ident,email=ident+'@example.com',managed_source='config' if ident!='agent-b' else 'database',creation_token_hash=None,password_hash=password,api_key_hash=digest('synthetic-key-'+ident),active=ident!='inactive')
        insert(c,'threads',id='thread-legacy',sequence=2,created_at=timestamp)
        for ident in ['agent-a','agent-b']:insert(c,'thread_members',thread_id='thread-legacy',participant_id=ident)
        fingerprint=digest(canonical(['agent-a',None,None,'synthetic request','completed',True,[]]))
        insert(c,'messages',id='message-legacy',thread_id='thread-legacy',sender_id='agent-b',recipient_id='agent-a',reply_to=None,text='synthetic request',status='completed',needs_reply=True,sequence=1,recipient_sequence=1,fingerprint=fingerprint,created_at=timestamp)
        insert(c,'messages',id='silent-legacy',thread_id='thread-legacy',sender_id='agent-a',recipient_id='agent-b',reply_to=None,text='synthetic attachment',status='completed',needs_reply=False,sequence=2,recipient_sequence=None,fingerprint='synthetic-silent-fingerprint',created_at=timestamp+1)
        insert(c,'artifacts',id='artifact-legacy',owner_id='agent-a',idempotency_key='upload-legacy',input_fingerprint='synthetic-upload-fingerprint',object_key='synthetic/original-object-key',filename='synthetic.txt',content_type='text/plain',size_bytes=3,sha256='a'*64,state='ready',lease=None,lease_until=None,created_at=timestamp)
        insert(c,'message_artifacts',message_id='silent-legacy',artifact_id='artifact-legacy')
        insert(c,'work_claims',message_id='message-legacy',claim_id='claim-legacy',claimed_at=timestamp)
        # OAuth JSON fields require native typed bind handling on PostgreSQL.
        from bridge.models_auth import Client
        c.execute(Client.__table__.insert().values(client_id='client-legacy',name='Synthetic OAuth',secret_hash=None,redirect_uris=['https://client.example.com/cb'],auth_method='none',grant_types=['authorization_code','refresh_token'],active=True,created_at=timestamp))
        insert(c,'oauth_families',id='family-legacy',owner_id='agent-a',client_id='client-legacy',active=True)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(('V'*43).encode()).digest()).decode().rstrip('=')
        insert(c,'oauth_codes',code_hash=digest('synthetic-authorization-code'),owner_id='agent-a',client_id='client-legacy',family='family-legacy',redirect_uri='https://client.example.com/cb',resource=BASE+'/mcp',scope='bridge:messages',challenge=challenge,method='S256',expires_at=timestamp+300,used=False)
        insert(c,'oauth_tokens',id='token-legacy',owner_id='agent-a',client_id='client-legacy',family='family-legacy',access_hash=digest('synthetic-access'),refresh_hash=digest('synthetic-refresh'),resource=BASE+'/mcp',scope='bridge:messages',expires_at=timestamp+900,refresh_expires_at=timestamp+3600,revoked=False)
        token=SimpleNamespace(owner_id='agent-a',client_id='service:agent-a')
        subid=identity(token,'https://subscriber.example.com/hook')
        secret=Fernet(encryption.encode()).encrypt(('whsec_'+base64.b64encode(b's'*32).decode()).encode()).decode()
        insert(c,'subscriptions',id=subid,owner_id='agent-a',client_id='service:agent-a',family=service_family(digest('synthetic-key-agent-a')),callback='https://subscriber.example.com/hook',secret=secret,previous_secret=None,rotation_until=0,expires_at=timestamp+3600,active=True,start_sequence=0,generation=2,acknowledged_sequence=0,acknowledged_generation=2)
        insert(c,'deliveries',id='delivery-legacy',message_id='message-legacy',kind='webhook',destination='webhook:agent-a',subscription_id=None,state='retry',attempts=3,available_at=timestamp,lease=None,lease_until=None,status=503,reason='transient_http')
        insert(c,'deliveries',id='delivery-mcp',message_id='message-legacy',kind='mcp',destination='mcp:'+subid,subscription_id=subid,state='accepted',attempts=1,available_at=timestamp,lease=None,lease_until=None,status=200,reason=None)
        if request.param=='v0.1.1':
            insert(c,'participant_api_keys',id='additional-key',owner_id='agent-a',key_hash=digest('synthetic-additional-key'),source='database',active=True,created_at=timestamp)
            insert(c,'credential_operations',token_hash='a'*64,owner_id='agent-a',purpose='issue_key',key_id='additional-key',created_at=timestamp)
    fixture=SimpleNamespace(engine=engine,sessions=sessions,settings=settings,mapping=mapping,legacy_config=legacy_config,env=env,version=request.param,subid=subid)
    try:yield fixture
    finally:
        engine.dispose()
        if admin:
            with admin.begin() as c:c.execute(text('DROP SCHEMA "'+schema+'" CASCADE'))
            admin.dispose()


def snapshot(engine):
    with engine.connect() as c:
        return {t: list(c.execute(text('SELECT * FROM '+t)).mappings()) for t in inspect(c).get_table_names()}


def migrate(f, **kwargs):
    return migrate_v01(f.engine,f.mapping,legacy_config=f.legacy_config,environ=f.env,**kwargs)


def test_complete_upgrade_preserves_data_auth_refresh_subscriptions_and_exact_retry(legacy):
    f=legacy;before=snapshot(f.engine)
    assert migrate(f)=='ready' and snapshot(f.engine)==before
    assert migrate(f,apply=True)=='applied'
    after=snapshot(f.engine)
    for table in ['messages','threads','thread_members','artifacts','message_artifacts','work_claims','subscriptions','deliveries','oauth_clients','oauth_families','oauth_codes','oauth_tokens']:
        assert [{k: row[k] for k in old} for row, old in zip(after[table], before[table])] == before[table], table
        assert len(after[table]) == len(before[table])
    if f.version=='v0.1.1':
        assert after['participant_api_keys']==before['participant_api_keys']
        assert after['credential_operations']==before['credential_operations']
    for row in after['oauth_users']:
        old=next(u for u in before['oauth_users'] if u['id']==row['id'])
        assert all(row[k]==old[k] for k in ['id','password_hash','api_key_hash','active','email'])
        assert row['managed_source']=='database'
    for row in after['participants']:
        old=next(p for p in before['participants'] if p['id']==row['id'])
        assert all(row[k]==old[k] for k in ['id','name','active','sequence'])
        assert row['reachability_policy']=='own_owner'
    assert migrate_v01(f.engine,f.mapping,apply=True,environ={})=='already_applied'
    app=create_app(f.settings);app.config['TESTING']=True;app.extensions['verify_callback']=lambda *a:None
    with app.extensions['sessions'].begin() as db:
        bootstrap(db,app.config)
        assert db.get(Participant,'agent-b').active and not db.get(Participant,'inactive').active
        assert db.get(BrowserOwner,'owner-b').active
    client=app.test_client()
    profile=client.get('/api/profile',headers={'Authorization':'Bearer synthetic-access'})
    assert profile.status_code==200 and profile.json['participant_id']=='agent-a'
    assert client.get('/api/profile',headers={'Authorization':'Bearer synthetic-key-agent-a'}).status_code==200
    if f.version=='v0.1.1':assert client.get('/api/profile',headers={'Authorization':'Bearer synthetic-additional-key'}).status_code==200
    refreshed=client.post('/oauth/token',data=dict(grant_type='refresh_token',refresh_token='synthetic-refresh',client_id='client-legacy',resource=BASE+'/mcp'))
    assert refreshed.status_code==200
    assert client.get('/api/profile',headers={'Authorization':'Bearer '+refreshed.json['access_token']}).status_code==200
    exchanged=client.post('/oauth/token',data=dict(grant_type='authorization_code',code='synthetic-authorization-code',client_id='client-legacy',redirect_uri='https://client.example.com/cb',resource=BASE+'/mcp',code_verifier='V'*43))
    assert exchanged.status_code==200
    assert client.get('/api/profile',headers={'Authorization':'Bearer '+exchanged.json['access_token']}).status_code==200
    duplicate=client.post('/api/messages',headers={'Authorization':'Bearer synthetic-key-agent-b'},json=dict(message_id='message-legacy',recipient='agent-a',text='synthetic request',status='completed',needs_reply=True))
    assert duplicate.status_code==200 and duplicate.json['duplicate']
    from bridge.events import parse_cursor
    with app.extensions['sessions']() as db:
        sub=db.get(Subscription,f.subid)
        assert identity(SimpleNamespace(owner_id='agent-a',client_id='service:agent-a'),sub.callback)==sub.id
        assert parse_cursor(app.config,cursor(app.config,sub,0),sub.id)==0
    # Refresh the original key-owned subscription through the real MCP handler.
    secret='whsec_'+base64.b64encode(b't'*32).decode()
    response=client.post('/mcp',headers={'Authorization':'Bearer synthetic-key-agent-a'},json=dict(jsonrpc='2.0',id=1,method='events/subscribe',params=dict(name='bridge.message.received',arguments={},delivery=dict(mode='webhook',url='https://subscriber.example.com/hook',secret=secret))))
    assert response.status_code==200 and response.json['result']['id']==f.subid
    # Next manual login uses the retained routing ID and unchanged password.
    page=client.get('/login',base_url=BASE,headers=HEADERS)
    login=client.post('/login',base_url=BASE,headers=HEADERS,data=dict(csrf=hidden(page,'csrf'),email='agent-a',password='synthetic-password'))
    assert login.status_code==302
    app.extensions['engine'].dispose()


@pytest.mark.parametrize('fault',['missing','unknown','duplicate_label','bad_admin','custom_check','partial','index_collision'])
def test_bad_mapping_or_unsupported_schema_is_read_only(legacy,fault):
    f=legacy
    if fault=='missing':f.mapping['participants'].pop()
    elif fault=='unknown':f.mapping['participants'][0]['owner_id']='unknown-owner'
    elif fault=='duplicate_label':f.mapping['participants'][2]['stable_id']='private-a'
    elif fault=='bad_admin':f.mapping['admin_owner_id']='inactive-or-missing'
    elif fault=='index_collision':
        with f.engine.begin() as c:c.exec_driver_sql('CREATE INDEX ix_participants_owner_id ON participants(name)')
    elif fault=='partial':
        with f.engine.begin() as c:c.exec_driver_sql('ALTER TABLE participants ADD COLUMN owner_account_id VARCHAR')
    else:
        if f.engine.dialect.name=='postgresql':
            with f.engine.begin() as c:c.exec_driver_sql("ALTER TABLE participants ADD CHECK (length(name)>0)")
        else:
            # SQLite can add a CHECK on a known column only through a faithful
            # table definition change; writable_schema is test-fixture-only.
            with f.engine.begin() as c:
                c.exec_driver_sql('PRAGMA writable_schema=ON')
                c.exec_driver_sql("UPDATE sqlite_master SET sql=replace(sql,'name VARCHAR NOT NULL','name VARCHAR NOT NULL CHECK (length(name)>0)') WHERE name='participants'")
                c.exec_driver_sql('PRAGMA writable_schema=OFF')
                c.exec_driver_sql('PRAGMA schema_version=20')
    before=snapshot(f.engine)
    with pytest.raises(ValueError):migrate(f,apply=True)
    assert snapshot(f.engine)==before


def test_interrupted_migration_rolls_back_all_schema_data_and_can_retry(legacy):
    f=legacy;before=snapshot(f.engine)
    def fail(connection,cursor,statement,*args):
        if statement.startswith('INSERT INTO bridge_migrations'):raise RuntimeError('synthetic migration interruption')
    event.listen(f.engine,'before_cursor_execute',fail)
    try:
        with pytest.raises(RuntimeError,match='synthetic migration interruption'):migrate(f,apply=True)
    finally:event.remove(f.engine,'before_cursor_execute',fail)
    assert snapshot(f.engine)==before
    assert migrate(f,apply=True)=='applied'
    altered=json.loads(json.dumps(f.mapping));altered['participants'][0]['stable_id']='remap'
    with pytest.raises(ValueError):migrate_v01(f.engine,altered,apply=True,environ={})


@pytest.mark.parametrize('state',['inherited','unconfigured','disabled','profile'])
def test_webhook_transfer_preserves_effective_generation_and_retry_state(legacy,state):
    f=legacy
    if state=='unconfigured':f.env.pop('WEBHOOK_URL');f.env.pop('WEBHOOK_TOKEN')
    if state in ('disabled','profile'):
        if f.version=='v0.1.0':pytest.skip('Profile settings were added in 0.1.1')
        with f.engine.begin() as c:
            c.execute(text('UPDATE participants SET webhook_enabled=:enabled,webhook_generation=4,webhook_url=:url,webhook_token=:token WHERE id=:id'),dict(enabled=state=='profile',url='https://profile.example.com/hook',token=Fernet(f.settings['ENCRYPTION_KEY'].encode()).encrypt(b'synthetic-profile-token').decode(),id='agent-a'))
    before=snapshot(f.engine)
    migrate(f,apply=True)
    from bridge.profile_webhooks import callback,current_delivery
    with f.sessions() as db:
        p=db.get(Participant,'agent-a');d=db.get(Delivery,'delivery-legacy')
        assert d.webhook_generation is None and d.destination=='webhook:agent-a' and d.state=='retry'
        assert p.webhook_generation==(1 if state in ('inherited','unconfigured') else 4)
        assert current_delivery(f.settings,p,d)==(state in ('inherited','unconfigured'))
        got=callback(f.settings,p)
        if state=='inherited':assert got==('https://receiver.example.com/hook','synthetic-legacy-token')
        elif state in ('unconfigured','disabled'):assert got==(None,None)
        else:assert got==('https://profile.example.com/hook','synthetic-profile-token')
    from bridge.worker import deliver_one
    calls=[]
    assert deliver_one(f.sessions,f.settings,post=lambda url,body,headers:calls.append((url,headers)) or (200,b''))
    with f.sessions() as db:
        delivery=db.get(Delivery,'delivery-legacy')
        assert delivery.webhook_generation is None and delivery.destination=='webhook:agent-a'
        if state=='inherited':
            assert delivery.state=='accepted' and delivery.attempts==4
            assert calls[0][0]=='https://receiver.example.com/hook'
            assert calls[0][1]['Authorization']=='Bearer synthetic-legacy-token'
        elif state=='unconfigured':
            assert delivery.state=='retry' and delivery.reason=='webhook_not_configured' and calls==[]
        else:
            assert delivery.state=='stopped' and calls==[]


def schema_snapshot(engine):
    with engine.connect() as c:
        if engine.dialect.name=='sqlite':
            return list(c.exec_driver_sql("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))
        i=inspect(c)
        return {t:dict(columns=[(col['name'],str(col['type']),col['nullable'],col['default']) for col in i.get_columns(t)],
                       indexes=i.get_indexes(t),unique=i.get_unique_constraints(t),pk=i.get_pk_constraint(t),fk=i.get_foreign_keys(t),checks=i.get_check_constraints(t))
                for t in i.get_table_names()} | {'views': {v:i.get_view_definition(v) for v in i.get_view_names()}}


def test_no_owner_bootstrap_is_explicit_and_preserves_bots(legacy):
    f=legacy
    with f.engine.begin() as c:c.exec_driver_sql('DELETE FROM browser_owners')
    f.mapping['admin_owner_id']='new-admin'
    for item in f.mapping['participants']:item['owner_id']='new-admin'
    before=snapshot(f.engine)
    with pytest.raises(ValueError):migrate(f,apply=True)
    assert snapshot(f.engine)==before
    f.mapping['bootstrap_admin']=dict(id='new-admin',name='New Admin',email='new-admin@example.com',password_hash_env='BOOTSTRAP_PASSWORD_HASH')
    f.env['BOOTSTRAP_PASSWORD_HASH']=f.settings['BROWSER_ADMIN']['password_hash']
    assert migrate(f,apply=True)=='applied'
    f.settings['BROWSER_ADMIN']=dict(id='new-admin',name='New Admin',email='new-admin@example.com',password_hash=f.env['BOOTSTRAP_PASSWORD_HASH'])
    app=create_app(f.settings)
    client=app.test_client()
    page=client.get('/login',base_url=BASE,headers=HEADERS)
    result=client.post('/login',base_url=BASE,headers=HEADERS,data=dict(csrf=hidden(page,'csrf'),email='new-admin@example.com',password='synthetic-password'))
    assert result.status_code==302
    assert client.get('/profiles',base_url=BASE,headers=HEADERS).status_code==200
    with app.extensions['sessions']() as db:
        assert db.get(User,'new-admin') is None
        assert db.get(Participant,'agent-a').owner_account_id=='new-admin'
    app.extensions['engine'].dispose()


def test_cli_preflight_apply_replay_and_missing_path_never_bootstrap_legacy(legacy,tmp_path):
    f=legacy
    import subprocess,sys
    mapping=tmp_path/'mapping.json';mapping.write_text(json.dumps(f.mapping))
    env={**os.environ,**f.env,'DATABASE_URL':f.settings['DATABASE_URL'],'BRIDGE_CONFIG':str(f.legacy_config),'PYTHONDONTWRITEBYTECODE':'1'}
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    def run(*extra):return subprocess.run([sys.executable,'-m','bridge','migrate-v01','--mapping',str(mapping),*extra],env=env,capture_output=True,text=True)
    check=run('--check')
    assert check.returncode==0,check.stderr
    assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before
    bad=tmp_path/'malformed.json';bad.write_text('{')
    invalid=subprocess.run([sys.executable,'-m','bridge','migrate-v01','--mapping',str(bad),'--check'],env=env,capture_output=True,text=True)
    assert invalid.returncode==2
    assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before
    applied=run('--apply')
    assert applied.returncode==0,applied.stderr
    f.legacy_config.unlink()
    env.pop('ENCRYPTION_KEY')
    assert run('--apply').returncode==0
    for output in [check.stdout+check.stderr,applied.stdout+applied.stderr]:
        assert 'synthetic-legacy-token' not in output and 'receiver.example.com' not in output
    missing=tmp_path/'nonexistent.sqlite'
    env['DATABASE_URL']='sqlite:///'+str(missing)
    assert run('--check').returncode==2 and not missing.exists()


def test_nonunique_index_view_trigger_and_schema_rollback_are_preserved(legacy):
    f=legacy
    with f.engine.begin() as c:
        c.exec_driver_sql('CREATE INDEX synthetic_profile_name_idx ON participants(name)')
        c.exec_driver_sql('CREATE VIEW synthetic_profile_view AS SELECT id,name FROM participants')
        if f.engine.dialect.name=='sqlite':
            c.exec_driver_sql('CREATE TRIGGER synthetic_profile_trigger AFTER UPDATE OF name ON participants BEGIN SELECT 1; END')
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    def fail(connection,cursor,statement,*args):
        if statement.startswith('INSERT INTO bridge_migrations'):raise RuntimeError('synthetic final interruption')
    event.listen(f.engine,'before_cursor_execute',fail)
    try:
        with pytest.raises(RuntimeError):migrate(f,apply=True)
    finally:event.remove(f.engine,'before_cursor_execute',fail)
    assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before
    assert migrate(f,apply=True)=='applied'
    with f.engine.connect() as c:
        i=inspect(c)
        assert 'synthetic_profile_name_idx' in {idx['name'] for idx in i.get_indexes('participants')}
        assert 'synthetic_profile_view' in i.get_view_names()
        assert c.exec_driver_sql('SELECT count(*) FROM synthetic_profile_view').scalar()==3
        assert any(key['constrained_columns']==['owner_account_id'] and key['referred_table']=='browser_owners' for key in i.get_foreign_keys('participants'))
        if f.engine.dialect.name=='sqlite':
            assert c.exec_driver_sql("SELECT count(*) FROM sqlite_master WHERE name='synthetic_profile_trigger'").scalar()==1
            assert not c.exec_driver_sql('PRAGMA foreign_key_check').all()
            assert c.exec_driver_sql('PRAGMA foreign_keys').scalar()==1


@pytest.mark.parametrize('definition',["CREATE UNIQUE INDEX unsupported_email_expression ON oauth_users(lower(email))", "CREATE UNIQUE INDEX unsupported_email_index ON oauth_users(email)"])
def test_unrecognized_email_uniqueness_rejects_initial_and_replay_migrations(legacy,definition):
    f=legacy
    if 'expression' not in definition:
        assert migrate(f,apply=True)=='applied'
    with f.engine.begin() as c:c.exec_driver_sql(definition)
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    with pytest.raises(ValueError):migrate_v01(f.engine,f.mapping,legacy_config=f.legacy_config,environ=f.env,apply=True)
    assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before


@pytest.mark.parametrize('table,column',[('participant_api_keys','key_hash'),('credential_operations','purpose')])
def test_malformed_optional_credentials_fail_check_and_apply_before_mutation(legacy,table,column):
    f=legacy
    if f.version!='v0.1.1':pytest.skip('Credential tables were added in 0.1.1')
    with f.engine.begin() as c:c.exec_driver_sql('ALTER TABLE '+table+' RENAME COLUMN '+column+' TO changed_column')
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    for apply in (False,True):
        with pytest.raises(ValueError):migrate(f,apply=apply)
        assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before


def test_incomplete_historical_release_combination_is_rejected(legacy):
    f=legacy
    if f.version=='v0.1.0':
        from bridge.models_auth import APIKey
        APIKey.__table__.create(f.engine)
    else:
        with f.engine.begin() as c:c.exec_driver_sql('DROP TABLE credential_operations')
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    for apply in (False,True):
        with pytest.raises(ValueError):migrate(f,apply=apply)
        assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before


@pytest.mark.parametrize('policy',['ON DELETE CASCADE','ON UPDATE CASCADE','DEFERRABLE INITIALLY DEFERRED','missing'])
def test_changed_or_missing_user_fk_contract_fails_without_schema_or_data_change(legacy,policy):
    f=legacy
    with f.engine.begin() as c:
        if f.engine.dialect.name=='sqlite':
            definition=c.scalar(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='oauth_users'"))
            edge='REFERENCES participants (id)'
            assert definition.count(edge)==1
            if policy=='missing':
                import re
                definition,count=re.subn(r',?\s*FOREIGN KEY\(id\) REFERENCES participants \(id\)','',definition)
                assert count==1
            else:definition=definition.replace(edge,edge+' '+policy)
            version=c.exec_driver_sql('PRAGMA schema_version').scalar()
            c.exec_driver_sql('PRAGMA writable_schema=ON')
            c.execute(text("UPDATE sqlite_master SET sql=:sql WHERE name='oauth_users' AND type='table'"),{'sql':definition})
            c.exec_driver_sql('PRAGMA writable_schema=OFF')
            c.exec_driver_sql('PRAGMA schema_version='+str(version+1))
        else:
            name=inspect(c).get_foreign_keys('oauth_users')[0]['name']
            c.exec_driver_sql('ALTER TABLE oauth_users DROP CONSTRAINT '+c.dialect.identifier_preparer.quote(name))
            if policy!='missing':c.exec_driver_sql('ALTER TABLE oauth_users ADD FOREIGN KEY (id) REFERENCES participants(id) '+policy)
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    for apply in (False,True):
        with pytest.raises(ValueError):migrate(f,apply=apply)
        assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before


def test_real_migrated_unconfigured_webhook_rendering_distinguishes_enablement(legacy):
    f=legacy;f.env.pop('WEBHOOK_URL');f.env.pop('WEBHOOK_TOKEN');migrate(f,apply=True)
    app=create_app(f.settings);app.config['TESTING']=True
    try:
        client=app.test_client();page=client.get('/login',base_url=BASE,headers=HEADERS)
        signed=client.post('/login',base_url=BASE,headers=HEADERS,data=dict(csrf=hidden(page,'csrf'),email='owner-a@example.com',password='synthetic-password'))
        assert signed.status_code==302
        path='/profiles/notifications?profile_id=agent-a'
        profiles=client.get('/profiles',base_url=BASE,headers=HEADERS)
        settings=client.get(path,base_url=BASE,headers=HEADERS)
        expected='Enabled — not configured'.encode()
        assert expected in profiles.data and expected in settings.data
        assert b'Enter both fields to finish setup.' in settings.data
        assert b'Saving settings stops pending notifications from the previous settings' in settings.data
        for enabled,label in [(False,b'Disabled'),(True,b'Configured')]:
            with app.extensions['sessions'].begin() as db:
                p=db.get(Participant,'agent-a');p.webhook_enabled=enabled
                p.webhook_url='https://configured.example.com/hook'
                p.webhook_token=Fernet(f.settings['ENCRYPTION_KEY'].encode()).encrypt(b'synthetic-private-token').decode()
            rendered=client.get(path,base_url=BASE,headers=HEADERS)
            assert b'Current webhook: <strong>'+label+b'</strong>' in rendered.data
            assert b'synthetic-private-token' not in rendered.data
            assert expected not in rendered.data
    finally:app.extensions['engine'].dispose()


@pytest.mark.parametrize('fault',['type','nullable'])
def test_optional_key_column_type_and_nullability_are_known_before_apply(legacy,fault):
    f=legacy
    if f.version!='v0.1.1':pytest.skip('Credential tables were added in 0.1.1')
    with f.engine.begin() as c:
        if f.engine.dialect.name=='sqlite':
            definition=c.scalar(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='participant_api_keys'"))
            known='key_hash VARCHAR NOT NULL'
            assert definition.count(known)==1
            changed='key_hash INTEGER NOT NULL' if fault=='type' else 'key_hash VARCHAR'
            definition=definition.replace(known,changed)
            version=c.exec_driver_sql('PRAGMA schema_version').scalar()
            c.exec_driver_sql('PRAGMA writable_schema=ON')
            c.execute(text("UPDATE sqlite_master SET sql=:sql WHERE name='participant_api_keys' AND type='table'"),{'sql':definition})
            c.exec_driver_sql('PRAGMA writable_schema=OFF')
            c.exec_driver_sql('PRAGMA schema_version='+str(version+1))
        elif fault=='type':c.exec_driver_sql('ALTER TABLE participant_api_keys ALTER COLUMN key_hash TYPE INTEGER USING 1')
        else:c.exec_driver_sql('ALTER TABLE participant_api_keys ALTER COLUMN key_hash DROP NOT NULL')
    before=snapshot(f.engine);schema_before=schema_snapshot(f.engine)
    for apply in (False,True):
        with pytest.raises(ValueError):migrate(f,apply=apply)
        assert snapshot(f.engine)==before and schema_snapshot(f.engine)==schema_before
