"""Final review fixes: published event contracts, registration text and owner copy."""
import json
import re
from html import unescape

import pytest
from sqlalchemy import event

from bridge.identities import label, public_identity
from bridge.invitations import REGISTRATION_ERROR
from bridge.models_auth import OwnerInvitation
from bridge.worker import deliver_one
from conftest import bearer_headers
from test_events import rpc, subscribe
from test_fix_round3 import blues
from test_multi_owner import invite, register_owner, send, tenants
from test_profiles import create, get, hidden, post, profile_app, sign_in
from test_web import rendered


def validate_published_payload(value, spec):
    """Check the complete flat JSON Schema vocabulary published by events/list.

    Unknown schema keywords fail the test rather than being silently ignored.
    No general-purpose schema dependency is needed for this flat contract.
    """
    assert set(spec) <= {'type', 'properties', 'required', 'additionalProperties'}
    assert spec['type'] == 'object' and type(value) is dict
    assert set(spec['required']) <= value.keys()
    if spec.get('additionalProperties') is False:
        assert value.keys() <= spec['properties'].keys()
    for key, item in value.items():
        rule = spec['properties'][key]
        assert set(rule) <= {'type', 'minLength', 'enum'}
        assert type(item) is {'string': str, 'boolean': bool}[rule['type']]
        if rule['type'] == 'string':
            assert len(item) >= rule.get('minLength', 0)
        if 'enum' in rule:
            assert item in rule['enum']


@pytest.mark.parametrize('transport,needs_reply', [('mcp', False), ('mcp', True), ('webhook', True)])
def test_emitted_notifications_validate_against_the_published_event_schema(bridge_app, transport, needs_reply):
    app, client = bridge_app, bridge_app.test_client()
    receiver, sender = ('agent-b', 'agent-a') if transport == 'mcp' else ('agent-a', 'agent-b')
    published = rpc(client, app, receiver, 'events/list')['result']['events'][0]['payloadSchema']
    if transport == 'mcp':
        assert 'result' in subscribe(client, app, participant=receiver)
    response = client.post('/api/messages', headers=bearer_headers(app, sender), json=dict(
        message_id='schema-notification', recipient=receiver, text='Synthetic contract check',
        status='received', needs_reply=needs_reply))
    assert response.status_code == 200
    emitted = []
    assert deliver_one(app.extensions['sessions'], app.config,
        post=lambda url, body, headers: emitted.append(json.loads(body)) or (200, b''))
    assert len(emitted) == 1
    data = emitted[0]['data']
    assert data['needs_reply'] is needs_reply
    validate_published_payload(data, published)
    # Pin rejection of the mismatch that escaped the previous schema-only test.
    with pytest.raises(AssertionError):
        validate_published_payload({**data, 'undeclared': 'value'}, published)
    with pytest.raises(AssertionError):
        validate_published_payload({k:v for k,v in data.items() if k != 'sender_owner_name'}, published)
    with pytest.raises(AssertionError):
        validate_published_payload({**data, 'sender_name': 123}, published)


@pytest.mark.parametrize('field', ['name', 'email'])
@pytest.mark.parametrize('control', ['\x00', '\x1f', '\x7f', '\x85', '\n'])
def test_registration_controls_fail_generically_before_sql_and_preserve_invitation(bridge_app, monkeypatch, field, control):
    app = bridge_app
    ident, code = invite(app)
    client = app.test_client()
    page = get(client, '/register')
    data = dict(csrf=hidden(page, 'csrf'), name='Synthetic Owner', email='new@example.com',
                password='synthetic-password', code=code)
    data[field] = f'New{control}Owner' if field == 'name' else f'new{control}@example.com'
    statements = []
    def capture(conn, cursor, statement, params, context, many):
        statements.append(statement)
    import werkzeug.security as security
    with monkeypatch.context() as guard:
        guard.setattr(security, 'generate_password_hash', lambda *args, **kwargs: pytest.fail('malformed owner text reached hashing'))
        event.listen(app.extensions['engine'], 'before_cursor_execute', capture)
        try:
            response = post(client, '/register', data=data)
        finally:
            event.remove(app.extensions['engine'], 'before_cursor_execute', capture)
    assert response.status_code == 400 and REGISTRATION_ERROR.encode() in response.data
    assert not any("owner_invitations" in statement or "browser_owners" in statement for statement in statements)
    with app.extensions['sessions']() as db:
        assert db.get(OwnerInvitation, ident).redeemer_id is None
    assert register_owner(app, code, 'recovered@example.com').status_code == 303


def test_requested_owner_form_copy_explains_visibility_webhook_gate_and_address_format(profile_app):
    client = sign_in(profile_app)
    registration = get(client, '/register').text
    assert 'Your display name' in registration
    assert 'Other owners and bots can see this name alongside your bots.' in registration
    new = get(client, '/profiles/new').text
    assert 'Other owners and bots see this name with the bot’s address ID and your display name.' in new
    gate = 'The webhook notifies the receiver only when a new message requests a reply.'
    assert gate in new and 'Existing message history is not sent.' in new
    notifications = get(client, '/profiles/notifications?profile_id=agent-b')
    assert gate in notifications.text and 'Existing message history' in notifications.text
    from test_profile_webhook_ui import notification_form
    invalid = post(client, '/profiles/notifications?profile_id=agent-b', data=notification_form(
        client, webhook_enabled='1', webhook_url='https://receiver.example.com/hook', webhook_token=''))
    assert invalid.status_code == 400
    assert 'When changing the destination, enter that receiver’s bearer token.' in invalid.text
    assert 'requires a new token' not in invalid.text
    path = '/profiles/reachability?profile_id=agent-b'
    bad_address = post(client, path, data=dict(csrf=hidden(get(client, path), 'csrf'),
        policy='allowlist', sender_ids='amb_\x00invalid'))
    assert bad_address.status_code == 400
    assert 'Enter one routing address per line, without control characters.' in bad_address.text


def test_profile_pages_keep_one_public_identity_without_redundant_owner_name_headings(profile_app):
    client = sign_in(profile_app)
    pages = [get(client, '/profiles/'+page+'?profile_id=agent-b') for page in ('credentials', 'notifications', 'reachability')]
    from test_credential_ui import PATH, credential_form
    pages.append(post(client, PATH, data=credential_form(client)))
    created = create(client)
    pages.append(created)
    for response in pages:
        assert response.status_code == 200
        assert 'profile-public-identity' in response.text
        assert '<p class="eyebrow">' not in response.text
        assert 'Owner ·' not in response.text
    plain = unescape(re.sub('<[^>]+>', '', created.text))
    assert plain.count('Synthetic Participant') == 1


def test_browser_api_identity_fields_and_picker_accessible_labels_share_the_same_projection(blues):
    app, first, _, left, right = blues
    response = send(app, sender=left, recipient=right, ident='shared-projection')
    assert response.status_code == 200
    machine = response.json
    client = sign_in(app, first)
    with rendered(app) as contexts:
        conversation = get(client, '/conversation?thread_id='+machine['thread_id'])
    context = contexts[-1]
    assert 'participant_names' not in context['thread']
    browser = context['messages'][0]
    fields = ('sender_name', 'sender_owner_name', 'recipient_name', 'recipient_owner_name')
    assert {k:browser[k] for k in fields} == {k:machine[k] for k in fields}
    expected = label(public_identity(left, 'Blue', 'Alice'), own=True)
    assert browser['sender_label'] == expected
    assert expected+', '+browser['created_at'] in unescape(conversation.text)
    with rendered(app) as contexts:
        assert get(client, '/').status_code == 200
    listing = contexts[-1]
    assert all('participant_names' not in thread for thread in listing['threads'])
    assert next(profile['label'] for profile in listing['profiles'] if profile['id'] == left) == expected
