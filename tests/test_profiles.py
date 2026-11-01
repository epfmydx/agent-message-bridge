"""Local synthetic owner provisioning and repeatable schema upgrades."""
import base64
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event, inspect, select, text
from werkzeug.security import generate_password_hash

from bridge.app import bootstrap
from bridge.auth import digest
from bridge.models import Member, Participant, database
from bridge.models_auth import BrowserOwner, Family, User
from bridge.schema import ensure_profile_schema

BASE = "https://bridge.example.com"
HEADERS = {"X-Bridge-Origin": "synthetic-origin-secret-for-agent-message-bridge-1234567890",
           "X-Forwarded-Proto": "https", "CF-Connecting-IP": "8.8.8.8"}


def get(client, path, **kwargs):
    return client.get(path, base_url=BASE, headers=HEADERS, **kwargs)


def post(client, path, **kwargs):
    return client.post(path, base_url=BASE, headers=HEADERS, **kwargs)


def hidden(response, name):
    return re.search(('name="'+name+'" value="([^"]+)"').encode(), response.data)[1].decode()


@pytest.fixture
def profile_app(bridge_app):
    bridge_app.config["BROWSER_OWNERS"] = [dict(id="profile-owner", name="Synthetic Owner",
        email="owner@example.com", password_hash=generate_password_hash("synthetic-owner-password"))]
    with bridge_app.extensions["sessions"].begin() as db:
        bootstrap(db, bridge_app.config)
    return bridge_app


def sign_in(app, ident="profile-owner", kind="owner"):
    client = app.test_client()
    with app.extensions["sessions"]() as db:
        account = db.get(BrowserOwner if kind == "owner" else User, ident)
        credential = digest(account.password_hash)
    with client.session_transaction(base_url=BASE) as browser:
        browser.update(owner=ident, account_kind=kind, credential=credential)
        browser.permanent = True
    return client


def form(client, **fields):
    page = get(client, "/profiles/new")
    assert page.status_code == 200
    return dict(csrf=hidden(page, "csrf"), creation_token=hidden(page, "creation_token"),
                name="Synthetic Participant", profile_id="new-participant", auth_mode="api_key", email="", **fields)


def create(client, **fields):
    data = form(client)
    data.update(fields)
    return post(client, "/profiles/new", data=data)


def test_api_key_once_atomic_identity_and_replay(profile_app):
    client = sign_in(profile_app)
    data = form(client)
    response = post(client, "/profiles/new", data=data)
    assert response.status_code == 200
    raw = re.search(rb'id="profile-api-key">([^<]+)', response.data)[1].decode()
    assert response.headers["Cache-Control"] == "no-store"
    assert raw not in str(response.headers)
    with client.session_transaction(base_url=BASE) as browser:
        assert raw not in str(dict(browser))
        assert "profile_form" not in browser
    with profile_app.extensions["sessions"]() as db:
        user = db.get(User, "new-participant")
        assert user.email is None and user.password_hash == ""
        assert user.api_key_hash == digest(raw) and user.managed_source == "database"
        assert db.get(Participant, user.id).managed_source == "database"
        assert not list(db.scalars(select(Member).where(Member.participant_id == user.id)))
    bearer = profile_app.test_client().get("/api/profile", headers={"Authorization": "Bearer "+raw}, base_url=BASE)
    assert bearer.status_code == 200 and bearer.json["participant_id"] == "new-participant"
    assert post(client, "/profiles/new", data=data).status_code == 400
    listing = get(client, "/profiles")
    assert raw.encode() not in listing.data and b"None" not in listing.data
    assert raw.encode() not in get(client, "/profiles/new").data


@pytest.mark.parametrize("path", ["/profiles", "/profiles/new"])
def test_owner_only_and_origin_before_database(profile_app, path):
    assert get(profile_app.test_client(), path).status_code == 302
    assert get(sign_in(profile_app, "agent-b", "participant"), path).status_code == 403
    calls = []
    engine = profile_app.extensions["engine"]
    def before(*args): calls.append(True)
    event.listen(engine, "before_cursor_execute", before)
    try:
        assert profile_app.test_client().get(path, base_url=BASE).status_code == 403
        assert profile_app.test_client().post(path, base_url=BASE).status_code in (403, 405)
        assert not calls
    finally:
        event.remove(engine, "before_cursor_execute", before)


def test_csrf_session_revocation_and_untrusted_fields(profile_app):
    client = sign_in(profile_app)
    data = form(client)
    assert post(client, "/profiles/new", data={**data, "csrf": "wrong"}).status_code == 400
    response = post(client, "/profiles/new", data={**data, "managed_source": "config", "active": "false", "owner": "true"})
    assert response.status_code == 200
    with profile_app.extensions["sessions"].begin() as db:
        assert db.get(User, "new-participant").managed_source == "database"
        assert not db.get(BrowserOwner, "new-participant")
        db.get(BrowserOwner, "profile-owner").password_hash = "rotated-synthetic-hash"
    assert get(client, "/profiles").status_code == 302


@pytest.mark.parametrize("fields,error", [
    ({"profile_id": "agent-b"}, b"stable ID"),
    ({"profile_id": "profile-owner"}, b"stable ID"),
    ({"email": "AGENT-B@EXAMPLE.COM"}, b"email is already"),
    ({"email": "OWNER@EXAMPLE.COM"}, b"email is already"),
    ({"name": " "}, b"display name"),
    ({"auth_mode": "oauth", "email": "", "password": "synthetic-password-secret"}, b"Email and password"),
    ({"auth_mode": "oauth", "email": "new@example.com", "password": ""}, b"Email and password"),
])
def test_validation_no_partial_records_or_password_echo(profile_app, fields, error):
    response = create(sign_in(profile_app), **fields)
    assert response.status_code == 400 and error in response.data
    assert b"synthetic-password-secret" not in response.data
    with profile_app.extensions["sessions"]() as db:
        assert not db.get(Participant, "new-participant")
        assert not db.get(User, "new-participant")


def test_oauth_login_consent_and_optional_email(profile_app):
    owner = sign_in(profile_app)
    assert create(owner, auth_mode="oauth", email="NEW@EXAMPLE.COM", password="synthetic-new-password").status_code == 200
    client = profile_app.test_client()
    page = get(client, "/login")
    assert post(client, "/login", data=dict(csrf=hidden(page, "csrf"), email="new@example.com", password="synthetic-new-password")).status_code == 302
    registered = client.post("/oauth/register", base_url=BASE, json=dict(redirect_uris=["https://client.example.com/callback"], token_endpoint_auth_method="none"))
    verifier = "v"*64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    fields = dict(response_type="code", client_id=registered.json["client_id"], redirect_uri="https://client.example.com/callback", scope="bridge:messages", resource=BASE+"/mcp", code_challenge=challenge, code_challenge_method="S256")
    consent = get(client, "/oauth/authorize", query_string=fields)
    assert consent.status_code == 200
    approved = post(client, "/oauth/authorize", data=dict(fields, csrf=hidden(consent, "csrf"), approve="yes"))
    code = parse_qs(urlsplit(approved.location).query)["code"][0]
    token = client.post("/oauth/token", base_url=BASE, data=dict(grant_type="authorization_code", code=code, client_id=registered.json["client_id"], redirect_uri=fields["redirect_uri"], code_verifier=verifier, resource=BASE+"/mcp"))
    assert token.status_code == 200
    result = client.get("/api/profile", base_url=BASE, headers={"Authorization": "Bearer "+token.json["access_token"]})
    assert result.json["participant_id"] == "new-participant"
    assert create(owner, profile_id="email-api", email="OPTIONAL@EXAMPLE.COM").status_code == 200
    assert create(owner, profile_id="no-email-a").status_code == 200
    assert create(owner, profile_id="no-email-b").status_code == 200
    with profile_app.extensions["sessions"]() as db:
        assert db.get(User, "email-api").email == "optional@example.com"


def test_config_durability_revocation_and_takeover_rejection(profile_app):
    owner = sign_in(profile_app)
    assert create(owner, email="created@example.com").status_code == 200
    settings = dict(profile_app.config)
    settings["USERS"] = [u for u in settings["USERS"] if u["id"] != "intruder"]
    with profile_app.extensions["sessions"].begin() as db:
        bootstrap(db, settings)
        assert db.get(User, "new-participant").active
        assert db.get(User, "new-participant").api_key_hash
        assert db.get(Participant, "new-participant").active
        assert not db.get(User, "intruder").active
        assert db.get(User, "intruder").api_key_hash is None
    for replacement in (dict(settings["USERS"][0], id="new-participant"),
                        dict(settings["USERS"][0], email="CREATED@EXAMPLE.COM")):
        with pytest.raises(ValueError), profile_app.extensions["sessions"].begin() as db:
            bootstrap(db, dict(settings, USERS=[replacement]))
    with pytest.raises(ValueError), profile_app.extensions["sessions"].begin() as db:
        bootstrap(db, dict(settings, BROWSER_OWNERS=[dict(settings["BROWSER_OWNERS"][0], email="CREATED@EXAMPLE.COM")]))


def test_duplicate_submission_race_and_fresh_form_retry(profile_app):
    client = sign_in(profile_app)
    data = form(client)
    cookie = client.get_cookie("session", domain="bridge.example.com")
    def submit(_):
        racing = profile_app.test_client()
        racing.set_cookie("session", cookie.value, domain="bridge.example.com")
        return post(racing, "/profiles/new", data={**data, "profile_id": ""}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == [200, 400]
    with profile_app.extensions["sessions"]() as db:
        assert len(list(db.scalars(select(User).where(User.managed_source == "database")))) == 1
    assert create(client, profile_id="retry-profile").status_code == 200


def test_profile_list_pagination(profile_app):
    client = sign_in(profile_app)
    page = get(client, "/profiles?page_size=1")
    assert page.status_code == 200
    next_url = re.search(rb'href="(/profiles\?[^\"]*cursor=[^\"]+)"', page.data)[1].decode().replace("&amp;", "&")
    assert get(client, next_url).status_code == 200
    assert get(client, "/profiles?page_size=101").status_code == 400
    assert get(client, "/profiles?cursor=invalid").status_code == 400


def _old_schema(engine):
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE participants (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, active BOOLEAN NOT NULL, sequence INTEGER NOT NULL)")
        db.exec_driver_sql("CREATE TABLE oauth_users (id VARCHAR PRIMARY KEY REFERENCES participants(id), email VARCHAR NOT NULL UNIQUE, password_hash VARCHAR NOT NULL, api_key_hash VARCHAR UNIQUE, active BOOLEAN NOT NULL)")
        db.exec_driver_sql("CREATE TABLE oauth_families (id VARCHAR PRIMARY KEY, owner_id VARCHAR REFERENCES oauth_users(id))")
        db.exec_driver_sql("CREATE INDEX synthetic_email_index ON oauth_users (email)")
        db.exec_driver_sql("INSERT INTO participants VALUES ('old', 'Synthetic', true, 0)")
        db.exec_driver_sql("INSERT INTO oauth_users VALUES ('old', 'old@example.com', 'synthetic-hash', NULL, true)")
        db.exec_driver_sql("INSERT INTO oauth_families VALUES ('family', 'old')")


def test_sqlite_existing_schema_upgrade_retains_foreign_keys_indexes_data_and_old_writers(tmp_path):
    engine, _ = database("sqlite:///"+str(tmp_path/"old.sqlite"))
    _old_schema(engine)
    with engine.begin() as db:
        db.exec_driver_sql("CREATE TABLE synthetic_audit (id VARCHAR)")
        db.exec_driver_sql("CREATE TRIGGER synthetic_user_audit AFTER INSERT ON oauth_users BEGIN INSERT INTO synthetic_audit VALUES (NEW.id); END")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ensure_profile_schema(engine), range(2)))
    ensure_profile_schema(engine)
    assert next(c for c in inspect(engine).get_columns("oauth_users") if c["name"] == "email")["nullable"]
    assert "synthetic_email_index" in {i["name"] for i in inspect(engine).get_indexes("oauth_users")}
    with engine.begin() as db:
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert not db.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert db.exec_driver_sql("SELECT owner_id FROM oauth_families").scalar() == "old"
        assert db.exec_driver_sql("SELECT managed_source FROM oauth_users").scalar() == "config"
        db.exec_driver_sql("INSERT INTO participants (id,name,active,sequence) VALUES ('new','New',true,0)")
        db.exec_driver_sql("INSERT INTO oauth_users (id,email,password_hash,active) VALUES ('new',NULL,'',true)")
        assert db.exec_driver_sql("SELECT managed_source FROM oauth_users WHERE id='new'").scalar() == "config"
        assert db.exec_driver_sql("SELECT id FROM synthetic_audit").scalar() == "new"
    engine.dispose()


def test_sqlite_failed_upgrade_rolls_back_and_retry(tmp_path):
    engine, _ = database("sqlite:///"+str(tmp_path/"retry.sqlite"))
    _old_schema(engine)
    def fail(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("DROP TABLE oauth_users"):
            raise RuntimeError("synthetic interruption")
    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError):
            ensure_profile_schema(engine)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    with engine.connect() as db:
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert db.exec_driver_sql("SELECT email FROM oauth_users").scalar() == "old@example.com"
        assert not inspect(db).has_table("oauth_users__profiles_upgrade")
    ensure_profile_schema(engine)
    engine.dispose()


def test_fresh_schema_upgrade_idempotent(profile_app):
    ensure_profile_schema(profile_app.extensions["engine"])
    ensure_profile_schema(profile_app.extensions["engine"])


@pytest.mark.parametrize("collision", ["id", "email"])
def test_distinct_form_duplicate_race_is_atomic(profile_app, collision):
    clients = [sign_in(profile_app), sign_in(profile_app)]
    forms = [form(client) for client in clients]
    if collision == "email":
        forms[0].update(profile_id="race-a", email="RACE@EXAMPLE.COM")
        forms[1].update(profile_id="race-b", email="race@example.com")
    def submit(pair):
        return post(pair[0], "/profiles/new", data=pair[1]).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, zip(clients, forms))) == [200, 400]
    with profile_app.extensions["sessions"]() as db:
        users = list(db.scalars(select(User).where(User.managed_source == "database")))
        participants = list(db.scalars(select(Participant).where(Participant.managed_source == "database")))
        assert len(users) == len(participants) == 1


def test_duplicate_database_failure_rolls_back_both_records(profile_app, monkeypatch):
    import bridge.profiles as profiles
    from sqlalchemy.exc import IntegrityError
    def interrupted(*args, **kwargs):
        raise IntegrityError("synthetic duplicate", {}, Exception("synthetic"))
    monkeypatch.setattr(profiles, "generate_password_hash", interrupted)
    response = create(sign_in(profile_app), auth_mode="oauth", email="new@example.com", password="synthetic-password")
    assert response.status_code == 400
    with profile_app.extensions["sessions"]() as db:
        assert not db.get(Participant, "new-participant") and not db.get(User, "new-participant")


def test_expired_cookie_cannot_provision(profile_app, monkeypatch):
    import itsdangerous.timed
    client = sign_in(profile_app)
    data = form(client)
    real_time = itsdangerous.timed.time.time
    monkeypatch.setattr(itsdangerous.timed.time, "time", lambda: real_time() + 9*3600)
    assert post(client, "/profiles/new", data=data).status_code == 302
    with profile_app.extensions["sessions"]() as db:
        assert not db.get(Participant, "new-participant")


def test_new_password_method_and_email_absent_login_have_equal_work(profile_app, monkeypatch):
    import bridge.auth as auth
    import bridge.profiles as profiles
    monkeypatch.setattr(profiles, "generate_password_hash", lambda value: generate_password_hash(value, method="pbkdf2:sha256:1000"))
    owner = sign_in(profile_app)
    assert create(owner, auth_mode="oauth", email="new@example.com", password="synthetic-password").status_code == 200
    assert create(owner, profile_id="key-no-email").status_code == 200
    original_check = auth.check_password_hash
    calls = []
    def check(value, password):
        calls.append(value.split("$", 1)[0])
        return original_check(value, password)
    monkeypatch.setattr(auth, "check_password_hash", check)
    for email in ("unknown@example.com", "", "new@example.com"):
        client = profile_app.test_client()
        page = get(client, "/login")
        calls.clear()
        response = post(client, "/login", data=dict(csrf=hidden(page, "csrf"), email=email, password="synthetic-password"))
        assert len(calls) == 2 and set(calls) == {"scrypt:32768:8:1", "pbkdf2:sha256:1000"}
        assert response.status_code == (302 if email == "new@example.com" else 200)


@pytest.mark.parametrize("headers", [
    {**HEADERS, "X-Bridge-Origin": "wrong"},
    {**HEADERS, "X-Forwarded-Proto": "http"},
    {**HEADERS, "CF-Connecting-IP": "127.0.0.1"},
    {k: v for k, v in HEADERS.items() if k != "CF-Connecting-IP"},
])
def test_profile_origin_failures_precede_database(profile_app, headers):
    calls = []
    engine = profile_app.extensions["engine"]
    def query(*args): calls.append(True)
    event.listen(engine, "before_cursor_execute", query)
    try:
        for path in ("/profiles", "/profiles/new"):
            response = profile_app.test_client().post(path, base_url=BASE, headers=headers)
            assert response.status_code in (400, 403)
        assert not calls
    finally:
        event.remove(engine, "before_cursor_execute", query)


def test_postgres_existing_upgrade_and_transaction_rollback(profile_app):
    engine = profile_app.extensions["engine"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires disposable PostgreSQL test database")
    with engine.begin() as db:
        db.exec_driver_sql("ALTER TABLE oauth_users ALTER COLUMN email SET NOT NULL")
        db.exec_driver_sql("ALTER TABLE oauth_users DROP COLUMN managed_source")
        db.exec_driver_sql("ALTER TABLE participants DROP COLUMN managed_source")
        db.exec_driver_sql("ALTER TABLE oauth_users DROP COLUMN creation_token_hash")
    def fail(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_users_creation_token_hash"):
            raise RuntimeError("synthetic interruption")
    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError):
            ensure_profile_schema(engine)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    assert "managed_source" not in {c["name"] for c in inspect(engine).get_columns("oauth_users")}
    assert not next(c for c in inspect(engine).get_columns("oauth_users") if c["name"] == "email")["nullable"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ensure_profile_schema(engine), range(2)))
    ensure_profile_schema(engine)
    with profile_app.extensions["sessions"]() as db:
        user = db.get(User, "agent-b")
        assert user.email == "agent-b@example.com" and user.managed_source == "config"
        assert db.get(Participant, user.id).managed_source == "config"
    assert next(c for c in inspect(engine).get_columns("oauth_users") if c["name"] == "email")["nullable"]


def test_two_open_forms_create_independently_and_replay_never_displays_key(profile_app):
    client = sign_in(profile_app)
    first = form(client)
    second = form(client)
    assert first["creation_token"] != second["creation_token"]
    first["profile_id"], second["profile_id"] = "tab-one", "tab-two"
    responses = [post(client, "/profiles/new", data=data) for data in (first, second)]
    assert [response.status_code for response in responses] == [200, 200]
    keys = [re.search(rb'id="profile-api-key">([^<]+)', response.data)[1] for response in responses]
    assert keys[0] != keys[1]
    for data in (first, second):
        replay = post(client, "/profiles/new", data=data)
        assert replay.status_code == 400
        assert all(key not in replay.data for key in keys)
    with profile_app.extensions["sessions"]() as db:
        assert len(list(db.scalars(select(User).where(User.managed_source == "database")))) == 2


def test_creation_token_requires_matching_owner_and_valid_csrf(profile_app):
    first = sign_in(profile_app)
    stolen = form(first)
    with profile_app.extensions["sessions"].begin() as db:
        db.add(BrowserOwner(id="second-owner", name="Second Owner", email="second-owner@example.com",
                            password_hash="synthetic-password-hash"))
    second = sign_in(profile_app, "second-owner")
    own = form(second)
    assert post(second, "/profiles/new", data={**stolen, "csrf": own["csrf"]}).status_code == 400
    assert post(first, "/profiles/new", data={**stolen, "csrf": "wrong"}).status_code == 400
    assert post(profile_app.test_client(), "/profiles/new", data=stolen).status_code == 302
    assert post(sign_in(profile_app, "agent-b", "participant"), "/profiles/new", data=stolen).status_code == 403
    assert post(first, "/profiles/new", data={**stolen, "creation_token": stolen["creation_token"]+"tampered"}).status_code == 400
    with profile_app.extensions["sessions"]() as db:
        assert not db.get(Participant, "new-participant")


@pytest.mark.parametrize("legacy_alter", [0, 1])
@pytest.mark.parametrize("foreign_keys", [0, 1])
@pytest.mark.parametrize("interrupted", [False, True])
def test_sqlite_upgrade_preserves_external_views_triggers_and_connection_modes(tmp_path, legacy_alter, foreign_keys, interrupted):
    engine, _ = database("sqlite:///" + str(tmp_path / "external-references.sqlite"))
    _old_schema(engine)
    with engine.begin() as db:
        db.exec_driver_sql("PRAGMA legacy_alter_table=" + str(legacy_alter))
        db.exec_driver_sql("PRAGMA foreign_keys=" + str(foreign_keys))
        db.exec_driver_sql("CREATE VIEW synthetic_profiles AS SELECT id, email FROM oauth_users")
        db.exec_driver_sql("CREATE VIEW synthetic_profile_emails AS SELECT email FROM synthetic_profiles")
        db.exec_driver_sql("CREATE TABLE synthetic_profile_requests (id VARCHAR REFERENCES oauth_users(id))")
        db.exec_driver_sql("CREATE TABLE synthetic_profile_audit (email VARCHAR)")
        db.exec_driver_sql("CREATE TRIGGER synthetic_external_profile_audit AFTER INSERT ON synthetic_profile_requests BEGIN INSERT INTO synthetic_profile_audit SELECT email FROM oauth_users WHERE id=NEW.id; END")
        db.exec_driver_sql("CREATE TRIGGER synthetic_owned_profile_audit AFTER INSERT ON oauth_users BEGIN INSERT INTO synthetic_profile_audit VALUES (NEW.email); END")
        retained = dict(db.exec_driver_sql("SELECT name, sql FROM sqlite_master WHERE type IN ('view', 'trigger')").all())
    def fail(connection, cursor, statement, parameters, context, executemany):
        if statement == "ALTER TABLE oauth_users__profiles_upgrade RENAME TO oauth_users":
            raise RuntimeError("synthetic interruption after old table removal")
    if interrupted:
        event.listen(engine, "before_cursor_execute", fail)
        try:
            with pytest.raises(RuntimeError, match="synthetic interruption"):
                ensure_profile_schema(engine)
        finally:
            event.remove(engine, "before_cursor_execute", fail)
        with engine.begin() as db:
            assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert db.exec_driver_sql("PRAGMA legacy_alter_table").scalar() == legacy_alter
            assert db.exec_driver_sql("SELECT email FROM synthetic_profile_emails").scalar() == "old@example.com"
            assert not inspect(db).has_table("oauth_users__profiles_upgrade")
            assert not next(c for c in inspect(db).get_columns("oauth_users") if c["name"] == "email")["nullable"]
            assert dict(db.exec_driver_sql("SELECT name, sql FROM sqlite_master WHERE type IN ('view', 'trigger')").all()) == retained
            db.exec_driver_sql("INSERT INTO synthetic_profile_requests VALUES ('old')")
            assert db.exec_driver_sql("SELECT email FROM synthetic_profile_audit").scalar() == "old@example.com"
            db.exec_driver_sql("DELETE FROM synthetic_profile_audit")
    ensure_profile_schema(engine)
    ensure_profile_schema(engine)
    with engine.begin() as db:
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
        assert db.exec_driver_sql("PRAGMA legacy_alter_table").scalar() == legacy_alter
        assert not db.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert db.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"
        assert dict(db.exec_driver_sql("SELECT name, sql FROM sqlite_master WHERE type IN ('view', 'trigger')").all()) == retained
        assert db.exec_driver_sql("SELECT email FROM synthetic_profile_emails").scalar() == "old@example.com"
        assert db.exec_driver_sql("SELECT owner_id FROM oauth_families").scalar() == "old"
        assert "synthetic_email_index" in {i["name"] for i in inspect(db).get_indexes("oauth_users")}
        db.exec_driver_sql("INSERT INTO synthetic_profile_requests VALUES ('old')")
        assert db.exec_driver_sql("SELECT email FROM synthetic_profile_audit").scalar() == "old@example.com"
        db.exec_driver_sql("INSERT INTO participants (id,name,active,sequence) VALUES ('new','New',true,0)")
        db.exec_driver_sql("INSERT INTO oauth_users (id,email,password_hash,active) VALUES ('new',NULL,'',true)")
        assert db.exec_driver_sql("SELECT COUNT(*) FROM synthetic_profile_audit WHERE email IS NULL").scalar() == 1
        assert db.exec_driver_sql("SELECT COUNT(*) FROM synthetic_profiles").scalar() == 2
    engine.dispose()
