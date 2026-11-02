"""Two-Agent acceptance with a real bridge DB and synthetic file/network providers."""
import contextlib
import hashlib
import io
import json

from sqlalchemy import func, select

from bridge.models import Delivery, Message
from bridge.worker import deliver_one
from conftest import bearer_headers
from test_files import FakeStore, upload_params


def test_two_agent_file_message_roundtrip_and_closing_message(bridge_app):
    app, client = bridge_app, bridge_app.test_client()
    store = FakeStore()
    app.extensions["object_store"] = store
    agent_a, agent_b = bearer_headers(app, "agent-a"), bearer_headers(app, "agent-b")
    inbound = b"Synthetic source document for Agent B"
    reserved = client.post("/api/files/uploads", headers=agent_a, json=upload_params(inbound, idempotency_key="agent_a-source")).get_json()
    assert reserved["state"] == "pending"
    store.objects[store.put_keys[reserved["upload_url"]]] = inbound
    ready = client.post("/api/files/"+reserved["id"]+"/complete", headers=agent_a, json={}).get_json()
    assert ready["state"] == "ready" and ready["sha256"] == hashlib.sha256(inbound).hexdigest()
    assert client.get("/api/files/"+ready["id"], headers=agent_b).status_code == 404

    # Subscribe Agent B using its own reference-only event schema.
    import base64
    subscription = client.post("/mcp", headers=agent_b, json={"jsonrpc": "2.0", "id": 1, "method": "events/subscribe", "params": {
        "name": "bridge.message.received", "arguments": {}, "delivery": {"mode": "webhook", "url": "https://agent-b.example.com/wakeup", "secret": "whsec_"+base64.b64encode(b"s"*32).decode()}}}).get_json()
    assert "result" in subscription
    request = client.post("/api/messages", headers=agent_a, json={"message_id": "source-request", "recipient": "agent-b", "text": "Prepare the report", "status": "received", "needs_reply": True, "attachment_ids": [ready["id"]]}).get_json()
    delivered = []
    def post(url, body, headers): delivered.append((url, json.loads(body), headers)); return 200, b""
    assert deliver_one(app.extensions["sessions"], app.config, post=post)
    assert delivered[-1][1]["data"]["message_id"] == "source-request"
    assert "text" not in delivered[-1][1]["data"]
    fetched = client.get("/api/messages/source-request", headers=agent_b).get_json()
    assert fetched["attachment_ids"] == [ready["id"]]
    assert client.get("/api/files/"+ready["id"], headers=agent_b).get_json()["download_url"]
    assert client.post("/api/messages/source-request/claim", headers=agent_b, json={"claim_id": "agent_b-report-run"}).get_json()["acquired"]

    # Agent B' file parameter carries a transient URL, not an accessible local path.
    @contextlib.contextmanager
    def fetch_file(url): yield io.BytesIO(b"Synthetic completed report")
    app.extensions["file_fetcher"] = fetch_file
    result = client.post("/mcp", headers=agent_b, json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "upload_file", "arguments": {
        "idempotency_key": "agent_b-report", "file": {"file_id": "synthetic-chat-file", "download_url": "https://files.example.com/temporary-source", "file_name": "report.txt", "mime_type": "text/plain"}}}}).get_json()["result"]["structuredContent"]
    assert result["state"] == "ready"
    response = client.post("/api/messages", headers=agent_b, json={"message_id": "agent_b-result", "thread_id": request["thread_id"], "reply_to": "source-request", "recipient": "agent-a", "text": "Report completed", "status": "completed", "needs_reply": True, "attachment_ids": [result["id"]]}).get_json()
    assert response["reply_to"] == "source-request"
    assert deliver_one(app.extensions["sessions"], app.config, post=post)
    assert delivered[-1][2]["Authorization"] == "Bearer synthetic-webhook-bearer"
    assert delivered[-1][1]["data"]["message_id"] == "agent_b-result"
    assert client.get("/api/messages/agent_b-result", headers=agent_a).get_json()["attachment_ids"] == [result["id"]]
    assert client.get("/api/files/"+result["id"], headers=agent_a).status_code == 200

    closed = client.post("/api/messages", headers=agent_a, json={"message_id": "closed", "thread_id": request["thread_id"], "reply_to": "agent_b-result", "recipient": "agent-b", "text": "Thanks, all done", "status": "completed", "needs_reply": False}).get_json()
    assert closed["needs_reply"] is False
    assert deliver_one(app.extensions["sessions"], app.config, post=post)
    assert delivered[-1][1]["data"]["message_id"] == "closed"
    assert delivered[-1][1]["data"]["needs_reply"] is False
    assert "Authorization" not in delivered[-1][2]
    assert client.post("/api/messages/closed/claim", headers=agent_b, json={"claim_id":"synthetic-no-closing-claim"}).status_code == 400
    assert deliver_one(app.extensions["sessions"], app.config, post=post) is False
    with app.extensions["sessions"]() as db:
        assert db.scalar(select(func.count()).select_from(Delivery)) == 3
        assert db.scalar(select(func.count()).select_from(Message)) == 3
