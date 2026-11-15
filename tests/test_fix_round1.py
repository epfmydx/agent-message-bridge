"""Lead acceptance decisions for the 0.2.0 candidate's first fix round."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import func, select

from bridge.auth import digest
from bridge.models import Artifact, BotAllowlist, Member, Message, MessageArtifact, Participant, Thread
from bridge.models_auth import OwnerInvitation
from conftest import bearer_headers
from test_multi_owner import participants, policies, send, tenants
from test_profiles import BASE, HEADERS, get, hidden, post, sign_in


def test_existing_thread_reply_allowed_after_other_member_wrote_despite_policy_revocation(tenants):
    app, _, _ = tenants
    policies(app, "intruder", "open")
    first = send(app)
    thread = first.json["thread_id"]
    assert "agent-a" not in participants(app, "intruder")
    assert send(app, sender="intruder", recipient="agent-a", ident="reply", thread_id=thread).status_code == 200
    policies(app, "intruder", "own_owner")
    assert send(app, ident="continued-reply", thread_id=thread).status_code == 200
    assert send(app, sender="intruder", recipient="agent-a", ident="continued-reverse", thread_id=thread).status_code == 200
    assert send(app, ident="new-thread-still-closed").status_code == 404


def test_existing_thread_blocks_recipient_who_never_wrote_and_does_not_accept(tenants):
    app, _, _ = tenants
    policies(app, "intruder", "open")
    first = send(app)
    policies(app, "intruder", "own_owner")
    assert send(app, ident="recipient-never-wrote", thread_id=first.json["thread_id"]).status_code == 404
    # Writing in a different thread cannot grant this thread's exception.
    assert send(app, sender="intruder", recipient="agent-a", ident="reply-first", thread_id=first.json["thread_id"]).status_code == 200
    with app.extensions["sessions"].begin() as db:
        db.add(Thread(id="empty-shared"))
        db.flush()
        db.add_all([Member(thread_id="empty-shared", participant_id=p) for p in ("agent-a", "intruder")])
    assert send(app, ident="other-thread-no-grant", thread_id="empty-shared").status_code == 404


@pytest.mark.parametrize("interface", ["rest", "mcp"])
@pytest.mark.parametrize("context", ["new", "unknown-thread", "existing-thread", "conflicting-message"])
def test_missing_inactive_and_unreachable_recipient_errors_are_identical(tenants, interface, context):
    app, _, _ = tenants
    client = app.test_client()
    responses = []
    if context in ("existing-thread", "conflicting-message"):
        with app.extensions["sessions"].begin() as db:
            db.add(Thread(id="oracle-thread"))
            db.flush()
            db.add_all([Member(thread_id="oracle-thread",participant_id=p) for p in ("agent-a","intruder")])
            if context == "conflicting-message":
                db.add(Message(id="existing-message",thread_id="oracle-thread",sender_id="agent-a",recipient_id="intruder",
                    text="Previously stored synthetic text",status="completed",needs_reply=False,sequence=1,fingerprint="synthetic-original"))
    for condition in ("missing", "inactive", "unreachable"):
        recipient = "missing-bot" if condition == "missing" else "intruder"
        with app.extensions["sessions"].begin() as db:
            db.get(Participant, "intruder").active = condition != "inactive"
        payload = dict(message_id="oracle-"+condition, recipient=recipient, text="Synthetic", status="received", needs_reply=False)
        if context in ("existing-thread", "unknown-thread"):
            payload["thread_id"] = "oracle-thread" if context == "existing-thread" else "missing-thread"
        if context == "conflicting-message": payload["message_id"] = "existing-message"
        if interface == "rest":
            response = client.post("/api/messages", json=payload, headers=bearer_headers(app, "agent-a"))
            responses.append((response.status_code, response.json))
        else:
            response = client.post("/mcp", headers=bearer_headers(app, "agent-a"), json=dict(
                jsonrpc="2.0", id=1, method="tools/call", params=dict(name="send_message", arguments=payload)))
            responses.append((response.status_code, response.json["error"]))
    assert responses[0] == responses[1] == responses[2]
    assert responses[0] == ((404, {"error":"Recipient is unavailable"}) if interface == "rest" else
                            (200, {"code":-32602, "message":"Recipient is unavailable"}))
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count()).select_from(Message)) == (1 if context == "conflicting-message" else 0)
        assert db.scalar(select(func.count()).select_from(Thread)) == (1 if context in ("existing-thread", "conflicting-message") else 0)


def test_allowlist_unknown_and_foreign_ids_are_stored_without_existence_feedback(tenants):
    app, first, _ = tenants
    client = sign_in(app, first)
    path = "/profiles/reachability?profile_id=agent-a"
    outcomes = []
    with app.extensions["sessions"].begin() as db:
        foreign = db.get(Participant,"intruder").owner_account_id
        db.add(Participant(id="amb_"+"a"*32, name="Public Bot", owner_account_id=foreign))
    for sender in ("amb_"+"a"*32, "amb_"+"b"*32):
        response = post(client, path, data=dict(csrf=hidden(get(client,path),"csrf"), policy="allowlist", sender_ids=sender))
        outcomes.append((response.status_code,response.location))
        with app.extensions["sessions"]() as db:
            assert list(db.scalars(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == "agent-a"))) == [sender]
    assert outcomes[0] == outcomes[1] == (303,path)
    assert ("amb_"+"b"*32).encode() in get(client,path).data


@pytest.mark.parametrize("sender", ["agent-a", "agent-b"])
def test_allowlist_rejects_self_and_same_owner_without_changing_saved_list(tenants, sender):
    app, first, _ = tenants
    receiver, peer = "amb_"+"c"*32, "amb_"+"d"*32
    with app.extensions["sessions"].begin() as db:
        db.add_all([Participant(id=ident, name="Synthetic", owner_account_id=first) for ident in (receiver,peer)])
    policies(app,receiver,"allowlist",("intruder",))
    client = sign_in(app,first)
    path = "/profiles/reachability?profile_id="+receiver
    submitted = receiver if sender == "agent-a" else peer
    response = post(client,path,data=dict(csrf=hidden(get(client,path),"csrf"),policy="allowlist",sender_ids=submitted))
    assert response.status_code == 400 and b"Use address IDs of bots owned by someone else." in response.data
    with app.extensions["sessions"]() as db:
        assert list(db.scalars(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == receiver))) == ["intruder"]


def test_allowlist_saved_ids_survive_other_policies_and_restore_without_javascript(tenants):
    app, first, _ = tenants
    policies(app,"agent-a","allowlist",("amb_"+"a"*32,"amb_"+"b"*32))
    client = sign_in(app,first)
    path = "/profiles/reachability?profile_id=agent-a"
    for policy in ("own_owner","open","allowlist"):
        # Hidden/stale text must be ignored for non-allowlist policies. Missing
        # text when switching back means reuse, while an explicit blank clears.
        data=dict(csrf=hidden(get(client,path),"csrf"),policy=policy)
        if policy != "allowlist": data["sender_ids"]="agent-a"
        assert post(client,path,data=data).status_code == 303
        with app.extensions["sessions"]() as db:
            assert set(db.scalars(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == "agent-a"))) == {"amb_"+"a"*32,"amb_"+"b"*32}
            assert db.get(Participant,"agent-a").reachability_policy == policy
    assert post(client,path,data=dict(csrf=hidden(get(client,path),"csrf"),policy="allowlist",sender_ids="")).status_code == 303
    with app.extensions["sessions"]() as db:
        assert not db.scalar(select(BotAllowlist.sender_id).where(BotAllowlist.receiver_id == "agent-a"))


def test_foreign_attachments_render_name_and_size_without_download_or_type(tenants):
    from test_files import FakeStore
    from test_web import rendered
    app, first, second = tenants
    policies(app,"agent-a","open")
    message=send(app,sender="intruder",recipient="agent-a",ident="foreign-file-message").json
    with app.extensions["sessions"].begin() as db:
        db.add(Artifact(id="foreign-file",owner_id="intruder",idempotency_key="file",object_key="foreign",filename="foreign-report.txt",
                        content_type="application/x-synthetic-private",size_bytes=1234,sha256="0"*64,state="ready"))
        db.flush()
        db.add(MessageArtifact(message_id=message["message_id"],artifact_id="foreign-file"))
    app.extensions["object_store"]=FakeStore()
    owner=sign_in(app,first)
    with rendered(app) as contexts:
        response=get(owner,"/conversation?thread_id="+message["thread_id"])
    from bridge.owner_web import _cursor
    from bridge.models_auth import BrowserOwner
    from urllib.parse import urlencode
    with app.test_request_context():
        with app.extensions["sessions"]() as db:
            cursor = _cursor(db.get(BrowserOwner,first),"owner-conversation","newer",0,25,message["thread_id"])
    feed=get(owner,"/conversation/messages?"+urlencode(dict(thread_id=message["thread_id"],cursor=cursor)))
    assert feed.status_code == 200
    rendered_pages = [response.data,get(owner,"/message?message_id="+message["message_id"]).data,feed.json["html"].encode()]
    for body in rendered_pages:
        assert b"foreign-report.txt" in body and b"1.2 kB" in body
        assert b'href="/files/foreign-file/download"' not in body and b"application/x-synthetic-private" not in body
    assert get(owner,"/files/foreign-file/download").status_code == 404
    uploader=sign_in(app,second)
    own_page=get(uploader,"/conversation?thread_id="+message["thread_id"])
    assert b'href="/files/foreign-file/download"' in own_page.data
    assert get(uploader,"/files/foreign-file/download").status_code == 302


def create_redirect(app):
    client=sign_in(app,"seed-admin")
    page=get(client,"/invitations")
    response=post(client,"/invitations",data=dict(csrf=hidden(page,"csrf"),action="create"))
    assert response.status_code == 303
    return client,response


def test_invitation_prg_reveal_once_and_configured_absolute_registration_url(bridge_app):
    import re
    app=bridge_app
    client,created=create_redirect(app)
    assert b'id="code"' not in created.data
    cookie=client.get_cookie("session",domain="bridge.example.com")
    client.set_cookie("session",cookie.value,domain="attacker.example.com",secure=True)
    shown=client.get(created.location,base_url="https://attacker.example.com",headers={**HEADERS,"X-Forwarded-Host":"attacker.example.com"})
    assert shown.status_code == 200
    code=re.search(rb'id="code" value="([^"]+)"',shown.data)[1].decode()
    assert b'href="https://bridge.example.com/register"' in shown.data and b"attacker.example.com/register" not in shown.data
    assert code not in created.location and code not in str(shown.headers)
    with client.session_transaction(base_url=BASE) as browser:
        assert code not in str(dict(browser))
    for _ in range(2):
        refresh=get(client,created.location)
        assert refresh.status_code == 303 and b'id="code"' not in refresh.data
    with app.extensions["sessions"]() as db:
        rows=list(db.scalars(select(OwnerInvitation)))
        assert len(rows)==1 and rows[0].code_hash == digest(code) and rows[0].displayed_at is not None


def test_invitation_concurrent_reveal_has_exactly_one_display(bridge_app):
    app=bridge_app
    _,created=create_redirect(app)
    clients=[sign_in(app,"seed-admin") for _ in range(2)]
    barrier=Barrier(2)
    def reveal(client):
        barrier.wait(10)
        return get(client,created.location)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(reveal,clients))
    assert sorted(r.status_code for r in responses)==[200,303]
    assert sum(b'id="code"' in r.data for r in responses)==1


def test_invitation_reveal_and_admin_label_remain_owner_guarded(tenants):
    app,first,second=tenants
    admin=sign_in(app,first)
    assert b'<span class="meta-label">Admin</span>' in get(admin,"/invitations").data
    owner=sign_in(app,second)
    assert b'<span class="meta-label">Owner</span>' in get(owner,"/profiles").data
    assert get(owner,"/invitations/created?invitation_id=unknown").status_code == 403
    assert app.test_client().get("/invitations/created?invitation_id=unknown",base_url=BASE).status_code == 403
