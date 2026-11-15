"""Public bot presentation and rejected-recipient query/locking boundaries."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import event, select, text

from bridge.app import bootstrap
from bridge.errors import Unavailable
from bridge.messages import send_message
from bridge.models import BotAllowlist, Message, Participant
from bridge.models_auth import BrowserOwner, User
from bridge.worker import deliver_one
from conftest import bearer_headers
from test_fix_round2 import bot
from test_multi_owner import policies, send, tenants
from test_profiles import BASE, get, hidden, post, sign_in


@pytest.fixture
def blues(tenants):
    app, first, second = tenants
    with app.extensions['sessions'].begin() as db:
        db.get(BrowserOwner, first).name = 'Alice'
        db.get(BrowserOwner, second).name = 'Bob'
    left, _ = bot(app, first, label='private-alice-label', name='Blue', email='private-alice@example.com')
    right, _ = bot(app, second, label='private-bob-label', name='Blue', email='private-bob@example.com')
    policies(app, left, 'open')
    policies(app, right, 'open')
    return app, first, second, left, right


def assert_private(value):
    import json
    text = json.dumps(value)
    assert 'private-alice-label' not in text and 'private-bob-label' not in text
    assert 'private-alice@example.com' not in text and 'private-bob@example.com' not in text
    assert 'seed-admin@example.com' not in text and 'second@example.com' not in text


def test_blue_discovery_profile_messages_threads_have_separate_public_fields(blues):
    app, _, _, left, right = blues
    client = app.test_client()
    outputs = []
    for sender, recipient, owner_name in ((left, right, 'Bob'), (right, left, 'Alice')):
        headers = bearer_headers(app, sender)
        listing = client.get('/api/participants', headers=headers).json
        identity = next(p for p in listing['participants'] if p['participant_id'] == recipient)
        assert identity == dict(participant_id=recipient, name='Blue', owner_name=owner_name)
        mcp = client.post('/mcp', headers=headers, json=dict(jsonrpc='2.0', id=1, method='tools/call',
            params=dict(name='list_participants', arguments={}))).json
        assert owner_name in str(mcp) and recipient in str(mcp)
        profile = client.get('/api/profile', headers=headers).json
        assert profile == dict(participant_id=sender, name='Blue', owner_name='Alice' if sender == left else 'Bob')
        outputs.extend((listing, mcp, profile))
    result = send(app, sender=left, recipient=right, ident='blue-first').json
    assert result['sender'] == left and result['recipient'] == right
    assert result['sender_name'] == result['recipient_name'] == 'Blue'
    assert result['sender_owner_name'] == 'Alice' and result['recipient_owner_name'] == 'Bob'
    headers = bearer_headers(app, right)
    detail = client.get('/api/messages/blue-first', headers=headers).json
    history = client.get('/api/threads/' + result['thread_id'] + '/messages', headers=headers).json
    threads = client.get('/api/threads', headers=headers).json
    assert {p['owner_name'] for p in threads['threads'][0]['participants']} == {'Alice', 'Bob'}
    assert history['messages'][0] == {k:v for k,v in result.items() if k != 'duplicate'}
    assert detail == history['messages'][0]
    for item in (*outputs, result, detail, history, threads):
        assert_private(item)
    policies(app, right, 'own_owner')
    listing = client.get('/api/participants', headers=bearer_headers(app, left)).json
    assert right not in {p['participant_id'] for p in listing['participants']}


@pytest.mark.parametrize('transport', ['mcp', 'webhook'])
def test_notifications_include_public_names_and_owner_names_without_private_fields(blues, transport):
    import base64
    import json
    from cryptography.fernet import Fernet
    app, _, _, left, right = blues
    if transport == 'mcp':
        result = app.test_client().post('/mcp', headers=bearer_headers(app, right), json=dict(
            jsonrpc='2.0', id=1, method='events/subscribe', params=dict(name='bridge.message.received', arguments={},
            delivery=dict(mode='webhook', url='https://callback.example.com/events',
                          secret='whsec_' + base64.b64encode(b'synthetic-notification-secret-32').decode()))))
        assert 'result' in result.json
    else:
        with app.extensions['sessions'].begin() as db:
            receiver = db.get(Participant, right)
            receiver.webhook_enabled = True
            receiver.webhook_url = 'https://callback.example.com/hook'
            receiver.webhook_token = Fernet(app.config['ENCRYPTION_KEY'].encode()).encrypt(b'synthetic-receiver-token').decode()
    assert send(app, sender=left, recipient=right, ident='blue-notify', needs_reply=True).status_code == 200
    captured = []
    assert deliver_one(app.extensions['sessions'], app.config,
        post=lambda url, body, headers: captured.append(json.loads(body)) or (200, b''))
    data = captured[0]['data']
    assert data['sender'] == left and data['recipient'] == right
    assert data['sender_name'] == data['recipient_name'] == 'Blue'
    assert data['sender_owner_name'] == 'Alice' and data['recipient_owner_name'] == 'Bob'
    assert_private(captured)


def test_owner_and_bot_web_present_full_identity_and_you_without_private_leaks(blues):
    from html import unescape
    import re
    app, first, second, left, right = blues
    thread = send(app, sender=left, recipient=right, ident='blue-ui').json['thread_id']
    assert send(app, sender=right, recipient=left, ident='blue-ui-reply', thread_id=thread).status_code == 200
    for viewer, own, foreign, foreign_owner in ((first, left, right, 'Bob'), (second, right, left, 'Alice')):
        client = sign_in(app, viewer)
        for path in ('/', '/conversation?thread_id='+thread, '/message?message_id=blue-ui'):
            response = get(client, path)
            assert response.status_code == 200
            plain = unescape(re.sub('<[^>]+>', '', response.text))
            assert f'Blue (you) <{own}>' in plain
            assert f'Blue ({foreign_owner}) <{foreign}>' in plain
            if path.startswith('/conversation'):
                article_labels = re.findall(r'<article[^>]+aria-label="([^"]+)"', response.text)
                assert any(f'Blue ({foreign_owner}) <{foreign}>' in unescape(value) for value in article_labels)
            assert 'private-alice-label' not in plain and 'private-bob-label' not in plain
            assert 'private-alice@example.com' not in plain and 'private-bob@example.com' not in plain
        profiles = get(client, '/profiles')
        assert 'Blue (you)' in unescape(re.sub('<[^>]+>', '', profiles.text))
    with app.extensions['sessions'].begin() as db:
        user = db.get(User, left)
        user.email = None
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash('synthetic-password')
    participant = sign_in(app, left, 'participant')
    page = get(participant, '/')
    assert page.status_code == 200
    header = re.search(r'<header.*?</header>', page.text, re.S)[0]
    plain = unescape(re.sub('<[^>]+>', '', header))
    assert f'Blue (you) <{left}>' in plain
    assert 'None' not in header and 'account-email' not in header


@pytest.mark.parametrize('state', ['missing', 'inactive', 'unreachable'])
def test_rejected_recipients_stop_at_the_same_unlocked_eligibility_query(tenants, state):
    app, _, _ = tenants
    with app.extensions['sessions'].begin() as db:
        db.get(Participant, 'intruder').active = state != 'inactive'
    statements = []
    def capture(conn, cursor, statement, params, context, many):
        statements.append(statement)
    engine = app.extensions['engine']
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        with app.extensions['sessions'].begin() as db:
            with pytest.raises(Unavailable, match='Recipient is unavailable'):
                send_message(db, app.config, 'agent-a', dict(message_id='rejected-probe',
                    recipient='missing' if state == 'missing' else 'intruder', text='Synthetic',
                    status='received', needs_reply=False))
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert len(statements) == 2
    assert all('FOR UPDATE' not in sql for sql in statements)
    assert 'SELECT participants.id \n' in statements[-1]
    assert 'reachability_policy' in statements[-1] and 'fingerprint' in statements[-1]


@pytest.mark.parametrize('state', ['missing', 'inactive', 'unreachable'])
def test_postgres_unavailable_recipient_never_waits_on_its_locked_row(tenants, state):
    app, _, _ = tenants
    if app.extensions['engine'].dialect.name != 'postgresql':
        pytest.skip('Native recipient lock-wait regression requires PostgreSQL')
    with app.extensions['sessions'].begin() as db:
        db.get(Participant, 'intruder').active = state != 'inactive'
    with app.extensions['sessions'].begin() as blocker:
        blocker.get(Participant, 'intruder', with_for_update=True)
        def rejected():
            with app.extensions['sessions'].begin() as db:
                db.execute(text("SET LOCAL statement_timeout = '500ms'"))
                with pytest.raises(Unavailable, match='Recipient is unavailable'):
                    send_message(db, app.config, 'agent-a', dict(message_id='locked-probe',
                        recipient='missing' if state == 'missing' else 'intruder', text='Synthetic',
                        status='received', needs_reply=False))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(rejected).result(timeout=3)


def test_postgres_policy_revocation_between_preflight_and_locks_is_rechecked(tenants):
    app, _, _ = tenants
    engine = app.extensions['engine']
    if engine.dialect.name != 'postgresql':
        pytest.skip('Native reachability race requires PostgreSQL')
    policies(app, 'intruder', 'open')
    paused, resume = Event(), Event()
    def pause(conn, cursor, statement, params, context, many):
        if 'SELECT participants.id \n' in statement and 'fingerprint' in statement and not paused.is_set():
            paused.set()
            assert resume.wait(10)
    event.listen(engine, 'after_cursor_execute', pause)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(send, app, ident='revocation-race')
            try:
                assert paused.wait(10)
                policies(app, 'intruder', 'own_owner')
            finally:
                resume.set()
            assert future.result(timeout=10).status_code == 404
    finally:
        event.remove(engine, 'after_cursor_execute', pause)
    with app.extensions['sessions']() as db:
        assert db.get(Message, 'revocation-race') is None


@pytest.mark.parametrize('control', ['\x00', '\x01', '\t', '\r', '\v', '\f', '\x1f', '\x7f'])
def test_allowlist_controls_are_rejected_before_being_bound_to_any_query(tenants, control):
    app, first, _ = tenants
    client = sign_in(app, first)
    path = '/profiles/reachability?profile_id=agent-a'
    page = get(client, path)
    invalid = 'amb_' + 'a' * 16 + control + 'b' * 16
    def reject_bad_bind(conn, cursor, statement, parameters, context, many):
        values = parameters.values() if isinstance(parameters, dict) else parameters
        assert all(not isinstance(v, str) or control not in v for v in values)
    engine = app.extensions['engine']
    event.listen(engine, 'before_cursor_execute', reject_bad_bind)
    try:
        response = post(client, path, data=dict(csrf=hidden(page, 'csrf'), policy='allowlist', sender_ids=invalid))
    finally:
        event.remove(engine, 'before_cursor_execute', reject_bad_bind)
    assert response.status_code == 400 and b'Enter one routing address per line, without control characters.' in response.data
    with app.extensions['sessions']() as db:
        assert not db.scalar(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == 'agent-a'))


def test_bootstrap_admin_email_trims_and_casefolds_like_login(bridge_app):
    app = bridge_app
    settings = dict(app.config, BROWSER_ADMIN=dict(app.config['BROWSER_ADMIN'], email='  SEED-ADMIN@EXAMPLE.COM  '))
    with app.extensions['sessions'].begin() as db:
        bootstrap(db, settings)
        assert db.get(BrowserOwner, 'seed-admin').email == 'seed-admin@example.com'
    client = app.test_client()
    page = get(client, '/login')
    assert post(client, '/login', data=dict(csrf=hidden(page, 'csrf'), email='  SEED-ADMIN@EXAMPLE.COM  ',
        password='synthetic-seed-password')).status_code == 302


@pytest.mark.parametrize('guard', ['email-unique', 'ownership', 'private-label', 'role'])
def test_schema_guard_rejects_unsafe_legacy_tables_on_each_engine(bridge_app, guard):
    from bridge.models import Base
    from bridge.schema import ensure_multi_owner_schema
    engine = bridge_app.extensions['engine']
    Base.metadata.drop_all(engine)
    with engine.begin() as db:
        if guard == 'email-unique':
            db.exec_driver_sql('CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY, email VARCHAR UNIQUE)')
        elif guard == 'ownership':
            db.exec_driver_sql('CREATE TABLE participants (id VARCHAR PRIMARY KEY)')
            db.exec_driver_sql("INSERT INTO participants VALUES ('synthetic-legacy')")
        elif guard == 'private-label':
            db.exec_driver_sql('CREATE TABLE participants (id VARCHAR PRIMARY KEY, owner_account_id VARCHAR NOT NULL)')
            db.exec_driver_sql("INSERT INTO participants VALUES ('synthetic-legacy', 'owner')")
        else:
            db.exec_driver_sql('CREATE TABLE participants (id VARCHAR PRIMARY KEY, owner_account_id VARCHAR NOT NULL, stable_id VARCHAR NOT NULL)')
            db.exec_driver_sql('CREATE TABLE browser_owners (id VARCHAR PRIMARY KEY)')
            db.exec_driver_sql("INSERT INTO browser_owners VALUES ('synthetic-legacy')")
    with pytest.raises(RuntimeError, match='fresh database'):
        ensure_multi_owner_schema(engine)
