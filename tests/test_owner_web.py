"""Personal owner overview is independent of Agent membership and machine access."""
from contextlib import contextmanager
from urllib.parse import quote

import pytest
from flask import template_rendered
from sqlalchemy import func, select, text
from werkzeug.security import generate_password_hash

from bridge import files
from bridge.app import bootstrap
from bridge.errors import Invalid, Unavailable
from bridge.models import Artifact, Member, Message, MessageArtifact, Participant, Thread
from bridge.models_auth import BrowserOwner, User

BASE = 'https://bridge.example.com'
HEADERS = {'X-Bridge-Origin':'synthetic-origin-secret-for-agent-message-bridge-1234567890',
           'X-Forwarded-Proto':'https','CF-Connecting-IP':'8.8.8.8'}


def get(client, path):
    return client.get(path, base_url=BASE, headers=HEADERS)


def login(client, email='owner@example.com', password='synthetic-owner-password'):
    response = get(client, '/login')
    assert response.status_code == 200
    with client.session_transaction(base_url=BASE) as session:
        csrf = session['csrf']
    response = client.post('/login', data={'csrf':csrf,'email':email,'password':password}, base_url=BASE,headers=HEADERS)
    assert response.status_code == 302
    return response


@contextmanager
def rendered(app):
    contexts=[]
    def capture(sender, template, context, **extra): contexts.append(context)
    template_rendered.connect(capture,app)
    try: yield contexts
    finally: template_rendered.disconnect(capture,app)


def page(app,client,path='/'):
    with rendered(app) as contexts: response=get(client,path)
    assert response.status_code==200, response.text
    return contexts[-1],response


@pytest.fixture
def owner_view(bridge_app):
    bridge_app.config['BROWSER_OWNERS']=[{'id':'bridge-owner','name':'Owner','email':'owner@example.com',
                                       'password_hash':generate_password_hash('synthetic-owner-password')}]
    with bridge_app.extensions['sessions'].begin() as db:
        bootstrap(db,bridge_app.config)
        db.add_all([Thread(id='agent-thread'),Thread(id='other-thread')]);db.flush()
        db.add_all([Member(thread_id='agent-thread',participant_id=p) for p in ('agent-a','agent-b')])
        db.add_all([Member(thread_id='other-thread',participant_id=p) for p in ('agent-a','intruder')]);db.flush()
        for i in range(31):
            db.add(Message(id=f'owner-message-{i:02}',thread_id='agent-thread' if i%2 else 'other-thread',
                sender_id='agent-a',recipient_id='agent-b' if i%2 else 'intruder',text=f'Synthetic overview message {i}',
                status='completed',needs_reply=False,sequence=i+1,fingerprint=f'owner-synthetic-{i}',created_at=1704067200+i//2))
        db.add_all([Artifact(id=ident,owner_id='intruder',idempotency_key=ident,object_key='synthetic/'+ident,
            filename='synthetic.txt',content_type='text/plain',size_bytes=10,sha256='0'*64,state=state)
            for ident,state in (('other-file','ready'),('unshared-ready-file','ready'),('pending-file','pending'))]);db.flush()
        db.add(MessageArtifact(message_id='owner-message-30',artifact_id='other-file'))
    client=bridge_app.test_client();login(client)
    return bridge_app,client


def test_owner_reads_all_threads_and_paginates_without_membership(owner_view):
    app,client=owner_view
    with app.extensions['sessions']() as db:
        assert db.get(Participant,'bridge-owner') is None and db.get(User,'bridge-owner') is None
        assert db.scalar(select(func.count()).select_from(Member).where(Member.participant_id=='bridge-owner'))==0
    first,response=page(app,client,'/?page_size=1')
    assert [t['thread_id'] for t in first['threads']]==['other-thread']
    assert first['threads'][0]['last_message']['message_id']=='owner-message-30'
    assert b'Conversations' in response.data and b'>Connections<' not in response.data
    second,_=page(app,client,first['pagination']['older_url'])
    assert [t['thread_id'] for t in second['threads']]==['agent-thread']
    returned,_=page(app,client,second['pagination']['newer_url'])
    assert [t['thread_id'] for t in returned['threads']]==[t['thread_id'] for t in first['threads']]
    conversation,_=page(app,client,'/conversation?thread_id=other-thread')
    assert len(conversation['messages'])==16
    assert conversation['messages'][-1]['message_id']=='owner-message-30'
    assert page(app,client,'/message?message_id=owner-message-30')[0]['message']['thread_id']=='other-thread'
    agent=app.test_client();login(agent,'agent-b@example.com','synthetic-password-agent-b')
    scoped,_=page(app,agent)
    assert {m['thread_id'] for m in scoped['messages']}=={'agent-thread'}
    assert get(agent,'/message?message_id=owner-message-30').status_code==404
    assert get(agent,first['pagination']['older_url']).status_code==400
    assert get(client,'/message?message_id=missing').status_code==404
    assert client.post('/',base_url=BASE,headers=HEADERS).status_code==405


def test_owner_and_participant_cursors_cannot_be_interchanged(owner_view):
    app,client=owner_view
    agent=app.test_client();login(agent,'agent-b@example.com','synthetic-password-agent-b')
    cursor=page(app,agent,'/?page_size=2')[0]['pagination']['older_url']
    assert get(client,cursor).status_code==400
    first,_=page(app,client,'/?page_size=1')
    assert get(client,first['pagination']['older_url']+'x').status_code==400
    assert get(client,first['pagination']['older_url'].replace('page_size=1','page_size=3')).status_code==400


def test_owner_global_ready_downloads_preserve_participant_rules(owner_view):
    app,client=owner_view
    calls=[]
    class Store:
        def presign_get(self,key,filename,content_type,expires):
            calls.append((key,expires));return 'https://download.example.com/synthetic-temporary'
    app.extensions['object_store']=Store()
    for artifact in ('other-file','unshared-ready-file'):
        assert get(client,'/files/'+artifact+'/download').location=='https://download.example.com/synthetic-temporary'
    assert all(expires==900 for key,expires in calls)
    for artifact,code in (('pending-file',409),('missing',404)):
        assert get(client,'/files/'+artifact+'/download').status_code==code
    assert len(calls)==2
    agent=app.test_client();login(agent,'agent-b@example.com','synthetic-password-agent-b')
    assert get(agent,'/files/other-file/download').status_code==404
    with app.extensions['sessions']() as db:
        with pytest.raises(Unavailable): files.get_overview_artifact(db,app.config,'agent-b','other-file',store=Store())
    with app.extensions['sessions'].begin() as db: db.get(BrowserOwner,'bridge-owner').active=False
    assert get(client,'/files/other-file/download').location=='/login'
    assert len(calls)==2


def test_existing_schema_adds_owner_table_without_changing_memberships(bridge_app):
    app=bridge_app;engine=app.extensions['engine']
    BrowserOwner.__table__.drop(engine)
    from bridge.models import Base
    Base.metadata.create_all(engine)
    settings=dict(app.config,BROWSER_OWNERS=[{'id':'new-owner','name':'Owner','email':'owner@example.com','password_hash':'synthetic-hash'}])
    with app.extensions['sessions'].begin() as db:
        before=db.scalar(select(func.count()).select_from(Participant))
        bootstrap(db,settings)
        assert db.get(BrowserOwner,'new-owner').active
        assert db.scalar(select(func.count()).select_from(Participant))==before
        assert db.scalar(select(func.count()).select_from(Member))==0
