"""Owner thread-list pair filtering and scoped conversation navigation regressions."""
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from flask import template_rendered
from sqlalchemy import event

from bridge.auth import digest
from bridge.models import Member, Message, Participant, Thread
from bridge.models_auth import BrowserOwner, User

BASE = "https://bridge.example.com"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}
LEFT, RIGHT = "alpha-user", "beta-user"
OTHER_LEFT, OTHER_RIGHT = "gamma-user", "delta-user"


def get(client, path):
    return client.get(path, base_url=BASE, headers=HEADERS)


def sign_in(app, client, ident="owner-a", kind="owner"):
    model = BrowserOwner if kind == "owner" else User
    with app.extensions["sessions"]() as db:
        credential = digest(db.get(model, ident).password_hash)
    with client.session_transaction(base_url=BASE) as session:
        session.clear()
        session.update(owner=ident, credential=credential, account_kind=kind)


@contextmanager
def rendered(app):
    contexts = []
    def capture(sender, template, context, **extra):
        contexts.append(context)
    template_rendered.connect(capture, app)
    try:
        yield contexts
    finally:
        template_rendered.disconnect(capture, app)


def page(app, client, path):
    with rendered(app) as contexts:
        response = get(client, path)
    assert response.status_code == 200, response.text
    return contexts[-1], response


def pair_url(a=LEFT, b=RIGHT, **extra):
    return "/?" + urlencode({"participant_a": a, "participant_b": b, **extra})


def test_filtered_message_details_round_trip_retains_pair(owner_pairs):
    app, client = owner_pairs
    with app.extensions["sessions"].begin() as db:
        db.get(Message, "pair-a-message-2").reply_to = "pair-a-message-1"
    conversation, _ = page(app, client, "/conversation?" + urlencode(
        {"thread_id": "pair-a", "participant_a": LEFT, "participant_b": RIGHT}))
    details_url = conversation["messages"][-1]["detail_url"]
    assert query(details_url)["participant_a"] == [LEFT]
    assert query(details_url)["participant_b"] == [RIGHT]
    details, _ = page(app, client, details_url)
    assert query(details["reply_url"])["participant_a"] == [LEFT]
    reply_details, _ = page(app, client, details["reply_url"])
    assert query(reply_details["back_url"])["participant_b"] == [RIGHT]
    returned, _ = page(app, client, details["back_url"])
    assert query(returned["list_url"])["participant_a"] == [LEFT]
    assert query(returned["list_url"])["participant_b"] == [RIGHT]
    listed, _ = page(app, client, returned["list_url"])
    assert {thread["thread_id"] for thread in listed["threads"]} == {"pair-a", "pair-a-second", "pair-b", "pair-empty"}
    wrong = query(details_url)
    wrong["participant_b"] = [OTHER_LEFT]
    assert get(client, "/message?" + urlencode(wrong, doseq=True)).status_code == 404
    sign_in(app, client, "agent-b", "participant")
    assert get(client, details_url).status_code == 400


def query(url):
    return parse_qs(urlsplit(url).query)


def add_pair_message(db, thread_id, sequence, sender, recipient, created_at=1704067200,
                     text_value=None):
    db.add(Message(id=f"{thread_id}-message-{sequence}", thread_id=thread_id,
        sender_id=sender, recipient_id=recipient, sequence=sequence,
        text=text_value or f"Synthetic {thread_id} {sequence}", status="completed",
        needs_reply=False, fingerprint=f"synthetic-{thread_id}-{sequence}", created_at=created_at))


@pytest.fixture
def owner_pairs(bridge_app):
    app = bridge_app
    with app.extensions["sessions"].begin() as db:
        db.add_all([BrowserOwner(id=ident, name=ident, email=ident+"@example.com",
            password_hash="synthetic-owner-password-hash", active=True) for ident in ("owner-a", "owner-b")])
        db.add_all([Participant(id=ident, name=name, active=True, sequence=0) for ident, name in (
            (LEFT, "Alpha User"), (RIGHT, "Beta User"),
            (OTHER_LEFT, "Gamma User"), (OTHER_RIGHT, "Delta User"))])
        db.add_all([Thread(id=ident, created_at=created, sequence=0) for ident, created in (
            ("pair-a", 10), ("pair-a-second", 11), ("pair-b", 12),
            ("pair-three", 13), ("pair-empty", 14), ("pair-other-empty", 15),
            ("pair-c", 16), ("pair-c-second", 17))])
        db.flush()
        db.add_all([Member(thread_id=thread_id, participant_id=ident) for thread_id, ids in (
            ("pair-a", (LEFT, RIGHT)), ("pair-a-second", (LEFT, RIGHT)),
            ("pair-b", (LEFT, RIGHT)), ("pair-three", (LEFT, RIGHT, OTHER_LEFT)),
            ("pair-empty", (LEFT, RIGHT)), ("pair-other-empty", (OTHER_LEFT, OTHER_RIGHT)),
            ("pair-c", (LEFT, OTHER_LEFT)), ("pair-c-second", (LEFT, OTHER_LEFT)))
            for ident in ids])
        # Three same-pair threads retain separate rows; one is empty. Dates tie
        # so stable ordering is determined by the existing thread-ID key.
        add_pair_message(db, "pair-a", 1, LEFT, RIGHT, text_value="Alpha opening")
        add_pair_message(db, "pair-a", 2, RIGHT, LEFT, text_value="Beta reply")
        add_pair_message(db, "pair-a-second", 1, RIGHT, LEFT, text_value="Second thread")
        add_pair_message(db, "pair-b", 1, LEFT, RIGHT, text_value="Other pair thread")
        add_pair_message(db, "pair-c", 1, LEFT, OTHER_LEFT, text_value="Cross pair first")
        add_pair_message(db, "pair-c-second", 1, OTHER_LEFT, LEFT, text_value="Cross pair second")
    client = app.test_client()
    sign_in(app, client)
    return app, client


def test_owner_pair_filter_selects_exact_pair_and_keeps_individual_threads(owner_pairs):
    app, client = owner_pairs
    listing, _ = page(app, client, pair_url(page_size=25))
    assert {thread["thread_id"] for thread in listing["threads"]} == {
        "pair-a", "pair-a-second", "pair-b", "pair-empty"}
    assert len(listing["threads"]) == 4
    assert "pair-three" not in {thread["thread_id"] for thread in listing["threads"]}
    assert "pair-other-empty" not in {thread["thread_id"] for thread in listing["threads"]}
    empty = next(thread for thread in listing["threads"] if thread["thread_id"] == "pair-empty")
    assert empty["last_message"] is None
    assert empty["participant_names"] == ["Alpha User", "Beta User"]
    reverse, _ = page(app, client, pair_url(RIGHT, LEFT, page_size=25))
    assert reverse["threads"] == listing["threads"]


@pytest.mark.parametrize("path", [
    "/?participant_a=alpha-user", "/?participant_b=beta-user",
    "/?participant_a=&participant_b=beta-user",
    "/?participant_a=alpha-user&participant_a=alpha-user&participant_b=beta-user",
    "/?participant_a=alpha-user&participant_b=beta-user&participant_b=beta-user",
    "/?participant_a=alpha-user&participant_b=alpha-user",
    "/?participant_a=alpha-user&participant_b=beta-user&extra=x",
])
def test_owner_pair_filter_rejects_malformed_or_self_pairs(owner_pairs, path):
    _, client = owner_pairs
    assert get(client, path).status_code == 400


def test_owner_pair_filter_rejects_unknown_participants_but_allows_known_empty_pair(owner_pairs):
    app, client = owner_pairs
    assert get(client, pair_url("missing-user", RIGHT)).status_code == 404
    assert get(client, pair_url(LEFT, "missing-user")).status_code == 404
    assert get(client, pair_url(" "+LEFT, RIGHT)).status_code == 404
    empty, _ = page(app, client, pair_url(LEFT, OTHER_RIGHT))
    assert empty["threads"] == []
    assert empty["pagination"]["older_url"] is None


def test_pair_keyset_pages_retain_filter_and_signed_cursors_bind_canonical_pair(owner_pairs):
    app, client = owner_pairs
    first, _ = page(app, client, pair_url(page_size=1))
    assert [thread["thread_id"] for thread in first["threads"]] == ["pair-b"]
    older_url = first["pagination"]["older_url"]
    assert older_url
    assert query(older_url)["participant_a"] == [LEFT]
    assert query(older_url)["participant_b"] == [RIGHT]
    second, _ = page(app, client, older_url)
    assert [thread["thread_id"] for thread in second["threads"]] == ["pair-a-second"]
    assert second["pagination"]["newer_url"]
    third, _ = page(app, client, second["pagination"]["older_url"])
    assert [thread["thread_id"] for thread in third["threads"]] == ["pair-a"]
    fourth, _ = page(app, client, third["pagination"]["older_url"])
    assert [thread["thread_id"] for thread in fourth["threads"]] == ["pair-empty"]
    assert fourth["pagination"]["older_url"] is None
    returned, _ = page(app, client, fourth["pagination"]["newer_url"])
    assert returned["threads"] == third["threads"]
    repeated, _ = page(app, client, older_url)
    assert repeated["threads"] == second["threads"]

    # Sorting the participant IDs is part of cursor identity, while the
    # unfiltered and differently paired cursors remain unusable here.
    assert get(client, changed_pair(older_url, LEFT, RIGHT)).status_code == 200
    all_listing, _ = page(app, client, "/?page_size=1")
    other_listing, _ = page(app, client, pair_url(LEFT, OTHER_LEFT, page_size=1))
    all_cursor = query(all_listing["pagination"]["older_url"])["cursor"][0]
    other_cursor = query(other_listing["pagination"]["older_url"])["cursor"][0]
    assert get(client, replace_cursor(older_url, all_cursor)).status_code == 400
    assert get(client, replace_cursor(older_url, other_cursor)).status_code == 400


def changed_pair(url, a, b):
    parsed = urlsplit(url)
    args = query(url)
    args["participant_a"], args["participant_b"] = [a], [b]
    return parsed.path + "?" + urlencode(args, doseq=True)


def replace_cursor(url, cursor):
    parsed = urlsplit(url)
    args = query(url)
    args["cursor"] = [cursor]
    return parsed.path + "?" + urlencode(args, doseq=True)


def test_owner_pair_query_bounds_page_and_reverse_existence_scans(owner_pairs):
    app, client = owner_pairs
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        normalized = statement.lower()
        if ("from threads" in normalized and "thread_members.thread_id = threads.id" in normalized):
            statements.append((statement, parameters))
    engine = app.extensions["engine"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        first, _ = page(app, client, pair_url(page_size=1))
        page(app, client, first["pagination"]["older_url"])
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    # One page query per request plus the reverse existence probe on the
    # second page. All must carry both participant IDs in their filter.
    assert len(statements) == 3, [sql[:180] for sql, _ in statements]
    assert all("thread_members" in sql.lower() for sql, _ in statements), [sql for sql, _ in statements]
    for sql, params in statements:
        values = repr(params)
        assert LEFT in values and RIGHT in values


class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.anchors.append(dict(attrs))


def test_filtered_owner_conversation_links_and_return_navigation_keep_list_scope(owner_pairs):
    app, client = owner_pairs
    listing, response = page(app, client, pair_url(page_size=25))
    parser = AnchorParser()
    parser.feed(response.text)
    listing_refresh = next(anchor["href"] for anchor in parser.anchors
        if "data-refresh-conversations" in anchor)
    assert query(listing_refresh).get("participant_a") == [LEFT]
    assert query(listing_refresh).get("participant_b") == [RIGHT]
    detail = next(anchor["href"] for anchor in parser.anchors
        if anchor.get("data-thread-id") == "pair-a")
    detail_args = query(detail)
    nested_list = detail_args.get("list_url", [""])[0]
    assert ((detail_args.get("participant_a") == [LEFT] and detail_args.get("participant_b") == [RIGHT])
        or query(nested_list).get("participant_a") == [LEFT]
        and query(nested_list).get("participant_b") == [RIGHT]
        or detail_args.get("selected_pair") == [LEFT+","+RIGHT])
    conversation, response = page(app, client, detail)
    assert get(client, f"/conversation?thread_id=pair-three&participant_a={LEFT}&participant_b={RIGHT}").status_code == 404
    parser = AnchorParser()
    parser.feed(response.text)
    back = next(anchor["href"] for anchor in parser.anchors if "data-back-list" in anchor)
    assert query(back).get("participant_a") == [LEFT]
    assert query(back).get("participant_b") == [RIGHT]
    assert query(conversation["newer_url"]).get("participant_a") == [LEFT]
    assert query(conversation["newer_url"]).get("participant_b") == [RIGHT]
    with app.extensions["sessions"].begin() as db:
        add_pair_message(db, "pair-c", 2, LEFT, OTHER_LEFT, text_value="Cross pair arrival")
    poll = get(client, conversation["newer_url"])
    assert poll.status_code == 200 and poll.get_json()["message_count"] == 0


def test_participant_inbox_pair_arguments_never_expand_membership_scope(owner_pairs):
    app, _ = owner_pairs
    with app.extensions["sessions"].begin() as db:
        db.add(User(id=LEFT, email="alpha@example.com", password_hash="synthetic-user-hash", active=True))
    participant = app.test_client()
    sign_in(app, participant, LEFT, "participant")
    response = get(participant, pair_url(LEFT, RIGHT))
    assert response.status_code in (200, 400)
    if response.status_code == 200:
        assert "Synthetic pair-a" in response.text
        assert "Other pair thread" not in response.text
        assert "pair-three" not in response.text


def bubble_classes(markup):
    result = {}
    for attrs in __import__("re").findall(r"<article\s+([^>]+)>", markup):
        class_name = __import__("re").search(r'class="([^"]+)"', attrs).group(1)
        message_id = __import__("re").search(r'data-message-id="([^"]+)"', attrs).group(1)
        result[message_id] = "conversation-message-alternate" in class_name.split()
    return result


def test_nonlegacy_participant_bubbles_keep_opposite_alignment_on_history_and_feed(owner_pairs):
    app, client = owner_pairs
    with app.extensions["sessions"].begin() as db:
        for sequence in range(3, 6):
            sender, recipient = ((LEFT, RIGHT) if sequence % 2 else (RIGHT, LEFT))
            add_pair_message(db, "pair-a", sequence, sender, recipient,
                created_at=1704067200 + (sequence % 2), text_value=f"Aligned {sequence}")
    initial, initial_response = page(app, client, "/conversation?thread_id=pair-a&page_size=2")
    initial_classes = bubble_classes(initial_response.text)
    assert set(initial_classes) == {"pair-a-message-4", "pair-a-message-5"}
    assert initial_classes["pair-a-message-4"] != initial_classes["pair-a-message-5"]
    older_url = initial["older_page_url"]
    older, older_response = page(app, client, older_url)
    older_classes = bubble_classes(older_response.text)
    assert set(older_classes) == {"pair-a-message-2", "pair-a-message-3"}
    assert older_classes["pair-a-message-2"] != older_classes["pair-a-message-3"]
    with app.extensions["sessions"].begin() as db:
        add_pair_message(db, "pair-a", 6, LEFT, RIGHT, text_value="Aligned 6")
        add_pair_message(db, "pair-a", 7, RIGHT, LEFT, text_value="Aligned 7")
    newer_feed = initial["newer_url"]
    feed_response = get(client, newer_feed)
    assert feed_response.status_code == 200
    feed_classes = bubble_classes(feed_response.get_json()["html"])
    assert feed_classes["pair-a-message-6"] != feed_classes["pair-a-message-7"]
