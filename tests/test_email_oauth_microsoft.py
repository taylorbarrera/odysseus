"""Tests for the Microsoft OAuth2 email helpers.

Mirrors tests/test_email_oauth.py for the Microsoft identity platform v2.0 /
Exchange Online IMAP+SMTP XOAUTH2 flow. Odysseus talks to Exchange Online over
IMAP/SMTP (not the Graph mail REST API) since Microsoft still fully supports
OAuth2 on IMAP/SMTP — only *basic* auth is being retired — so this reuses the
same `make_oauth_state`/XOAUTH2 plumbing as Google, just with a second
`oauth_provider` value and Microsoft's endpoints/hosts.

Covers:
- `_refresh_microsoft_token` — token refresh stores the result encrypted, can
  rotate the refresh token, and fails silently (no token/secret leaks).
- `_get_valid_microsoft_token` — uses the cached token when fresh; calls
  refresh when expired or missing.
- `_imap_connect` / `_send_smtp_message` — Microsoft OAuth accounts use
  XOAUTH2, not `.login()`.
- `microsoft_oauth_callback` (real route) — invalid/tampered/missing state and
  provider errors return generic redirects with no PII; owner mismatch and
  mailbox-identity mismatches refuse the token write; a valid owner writes
  encrypted tokens only to the intended account.
- `microsoft_oauth_authorize` (real route) — requires
  `MICROSOFT_OAUTH_CLIENT_ID`, signs state, and builds the Microsoft identity
  platform v2.0 authorize URL with a tenant and Outlook IMAP/SMTP scopes.
- `/accounts/test-connection` — Microsoft OAuth is host/transport restricted
  the same way Google OAuth is (imap host must be outlook.office365.com on
  993/no-STARTTLS; smtp host must be smtp.office365.com on 587/STARTTLS).
"""

import time
import unittest.mock as mock
from types import SimpleNamespace

import pytest


def _make_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from core.database import Base
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Factory = sessionmaker(bind=engine)
    return Factory(), Factory


def _make_account(session, account_id="acct-1", owner="alice", **kwargs):
    from core.database import EmailAccount
    row = EmailAccount(
        id=account_id,
        owner=owner,
        name=kwargs.get("name", "Test"),
        from_address=kwargs.get("from_address", "test@example.com"),
        imap_host=kwargs.get("imap_host", "outlook.office365.com"),
        imap_port=kwargs.get("imap_port", 993),
        imap_user=kwargs.get("imap_user", "test@example.com"),
        smtp_host=kwargs.get("smtp_host", "smtp.office365.com"),
        smtp_port=kwargs.get("smtp_port", 587),
        smtp_user=kwargs.get("smtp_user", "test@example.com"),
    )
    for k, v in kwargs.items():
        if hasattr(row, k):
            setattr(row, k, v)
    session.add(row)
    session.commit()
    return row


# ── Token refresh / encryption at rest ────────────────────────────

def test_refresh_microsoft_token_stored_encrypted_not_raw():
    from src.secret_storage import decrypt as _dec, encrypt as _enc
    from core.database import EmailAccount

    raw_token = "eyJ.microsoft.test_access_token_raw"

    db, Factory = _make_db()
    _make_account(db, account_id="acct-r", owner="bob",
                  oauth_refresh_token=_enc("refresh-tok-xyz"))
    db.close()

    fake_resp = mock.MagicMock()
    fake_resp.raise_for_status = mock.MagicMock()
    fake_resp.json.return_value = {"access_token": raw_token, "expires_in": 3600}

    with mock.patch("httpx.post", return_value=fake_resp), \
         mock.patch("core.database.SessionLocal", Factory), \
         mock.patch("routes.email_helpers.os.environ.get", side_effect=lambda k, d="": {
             "MICROSOFT_OAUTH_CLIENT_ID": "cid", "MICROSOFT_OAUTH_CLIENT_SECRET": "csec"
         }.get(k, d)):
        from routes.email_helpers import _refresh_microsoft_token
        result = _refresh_microsoft_token("acct-r")

    verify_db = Factory()
    row = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-r").first()
    stored = row.oauth_access_token
    verify_db.close()

    assert result == raw_token
    assert stored != raw_token, "raw token must not be stored directly in the DB"
    assert _dec(stored) == raw_token


def test_refresh_microsoft_token_rotates_refresh_token_when_provided():
    """Microsoft may rotate the refresh token on each exchange — the new one
    must replace the stored (encrypted) value."""
    from src.secret_storage import decrypt as _dec, encrypt as _enc
    from core.database import EmailAccount

    db, Factory = _make_db()
    _make_account(db, account_id="acct-rot", owner="bob",
                  oauth_refresh_token=_enc("old-refresh"))
    db.close()

    fake_resp = mock.MagicMock()
    fake_resp.raise_for_status = mock.MagicMock()
    fake_resp.json.return_value = {
        "access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600,
    }

    with mock.patch("httpx.post", return_value=fake_resp), \
         mock.patch("core.database.SessionLocal", Factory), \
         mock.patch("routes.email_helpers.os.environ.get", side_effect=lambda k, d="": {
             "MICROSOFT_OAUTH_CLIENT_ID": "cid", "MICROSOFT_OAUTH_CLIENT_SECRET": "csec"
         }.get(k, d)):
        from routes.email_helpers import _refresh_microsoft_token
        _refresh_microsoft_token("acct-rot")

    verify_db = Factory()
    row = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-rot").first()
    verify_db.close()
    assert _dec(row.oauth_refresh_token) == "new-refresh"


def test_refresh_microsoft_token_returns_none_without_client_credentials():
    from core.database import EmailAccount

    db, Factory = _make_db()
    from src.secret_storage import encrypt as _enc
    _make_account(db, account_id="acct-noclient", owner="bob",
                  oauth_refresh_token=_enc("ref-tok"))
    db.close()

    with mock.patch("routes.email_helpers.os.environ.get", side_effect=lambda k, d="": {
        "MICROSOFT_OAUTH_CLIENT_ID": "",
        "MICROSOFT_OAUTH_CLIENT_SECRET": "",
    }.get(k, d)):
        from routes.email_helpers import _refresh_microsoft_token
        assert _refresh_microsoft_token("acct-noclient") is None


def test_get_valid_microsoft_token_uses_cached_token_when_fresh():
    from routes.email_helpers import _get_valid_microsoft_token
    from src.secret_storage import encrypt as _enc

    future_expiry = str(int(time.time()) + 3600)
    cfg = {
        "oauth_access_token": _enc("fresh-token"),
        "oauth_token_expiry": future_expiry,
    }
    with mock.patch("routes.email_helpers._refresh_microsoft_token") as refresh:
        token = _get_valid_microsoft_token("acct-1", cfg)
    refresh.assert_not_called()
    assert token == "fresh-token"


def test_get_valid_microsoft_token_refreshes_when_expired():
    from routes.email_helpers import _get_valid_microsoft_token
    from src.secret_storage import encrypt as _enc

    past_expiry = str(int(time.time()) - 100)
    cfg = {
        "oauth_access_token": _enc("stale-token"),
        "oauth_token_expiry": past_expiry,
    }
    with mock.patch("routes.email_helpers._refresh_microsoft_token", return_value="new-token") as refresh:
        token = _get_valid_microsoft_token("acct-1", cfg)
    refresh.assert_called_once_with("acct-1")
    assert token == "new-token"


# ── _smtp_ready / _imap_connect / _send_smtp_message use XOAUTH2 ──

def test_smtp_ready_true_for_microsoft_oauth_account_without_password():
    from routes.email_routes import _smtp_ready

    cfg = {
        "smtp_host": "smtp.office365.com",
        "smtp_user": "me@outlook.com",
        "smtp_password": "",
        "oauth_provider": "microsoft",
    }
    assert _smtp_ready(cfg) is True


def test_imap_connect_uses_xoauth2_for_microsoft_accounts():
    """Microsoft OAuth accounts must call conn.authenticate('XOAUTH2', ...) and
    must NOT call conn.login() with a password."""
    from src.secret_storage import encrypt as _enc

    future_expiry = str(int(time.time()) + 3600)
    fake_cfg = {
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "imap_starttls": False,
        "imap_user": "me@outlook.com",
        "imap_password": "",
        "oauth_provider": "microsoft",
        "account_id": "acct-oauth",
        "oauth_access_token": _enc("eyJ.live_token"),
        "oauth_token_expiry": future_expiry,
    }
    fake_conn = mock.MagicMock()
    with mock.patch("routes.email_helpers._get_email_config", return_value=fake_cfg), \
         mock.patch("routes.email_helpers._open_imap_connection", return_value=fake_conn):
        from routes.email_helpers import _imap_connect
        _imap_connect("acct-oauth", owner="alice")

    fake_conn.login.assert_not_called()
    assert fake_conn.authenticate.call_args[0][0] == "XOAUTH2"


def test_send_smtp_message_uses_xoauth2_for_microsoft_accounts():
    from src.secret_storage import encrypt as _enc

    future_expiry = str(int(time.time()) + 3600)
    cfg = {
        "smtp_host": "smtp.office365.com",
        "smtp_port": 587,
        "smtp_security": "starttls",
        "smtp_user": "me@outlook.com",
        "smtp_password": "",
        "oauth_provider": "microsoft",
        "account_id": "acct-oauth",
        "oauth_access_token": _enc("eyJ.live_token"),
        "oauth_token_expiry": future_expiry,
    }
    fake_smtp = mock.MagicMock()
    fake_smtp_ctx = mock.MagicMock()
    fake_smtp_ctx.__enter__ = mock.MagicMock(return_value=fake_smtp)
    fake_smtp_ctx.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("smtplib.SMTP", return_value=fake_smtp_ctx):
        from routes.email_helpers import _send_smtp_message
        _send_smtp_message(cfg, "me@outlook.com", ["you@example.com"], "hello")

    fake_smtp.login.assert_not_called()
    assert fake_smtp.auth.call_args[0][0] == "XOAUTH2"


# ── Real OAuth authorize route ────────────────────────────────────

def _authorize_endpoint():
    from routes.email_routes import setup_email_routes
    router = setup_email_routes()
    for route in router.routes:
        if route.path == "/api/email/oauth/microsoft/authorize" and "GET" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("microsoft_oauth_authorize route not found")


class _FakeRequest:
    def __init__(self, scheme="http", host="localhost:7000"):
        self.headers = {"host": host}
        self.url = SimpleNamespace(scheme=scheme)


@pytest.mark.asyncio
async def test_authorize_requires_client_id(monkeypatch):
    monkeypatch.delenv("MICROSOFT_OAUTH_CLIENT_ID", raising=False)
    from fastapi import HTTPException
    authorize = _authorize_endpoint()
    with pytest.raises(HTTPException):
        await authorize(account_id="acct-a", request=_FakeRequest(), owner="")


@pytest.mark.asyncio
async def test_authorize_builds_microsoft_v2_url_with_outlook_scopes(monkeypatch):
    import urllib.parse

    monkeypatch.setenv("MICROSOFT_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.delenv("MICROSOFT_OAUTH_TENANT", raising=False)
    monkeypatch.delenv("MICROSOFT_OAUTH_REDIRECT_URI", raising=False)

    authorize = _authorize_endpoint()
    resp = await authorize(account_id="acct-a", request=_FakeRequest(), owner="")

    location = resp.headers["location"]
    assert location.startswith("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    assert query["client_id"] == ["client-id"]
    assert "IMAP.AccessAsUser.All" in query["scope"][0]
    assert "SMTP.Send" in query["scope"][0]
    assert "offline_access" in query["scope"][0]


# ── Real OAuth callback route ──────────────────────────────────────

def _callback_endpoint():
    from routes.email_routes import setup_email_routes
    router = setup_email_routes()
    for route in router.routes:
        if route.path == "/api/email/oauth/microsoft/callback" and "GET" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("microsoft_oauth_callback route not found")


def _location(resp):
    return resp.headers["location"]


@pytest.mark.asyncio
async def test_callback_missing_code_returns_generic_error():
    from routes.email_helpers import make_oauth_state

    callback = _callback_endpoint()
    state = make_oauth_state("acct-1", "alice")
    resp = await callback(code=None, state=state, error=None, request=_FakeRequest())

    loc = _location(resp)
    assert "email_oauth_error=missing_code" in loc
    assert "acct-1" not in loc
    assert "alice" not in loc


@pytest.mark.asyncio
async def test_callback_provider_error_returns_generic_error():
    callback = _callback_endpoint()
    resp = await callback(code=None, state=None, error="access_denied", request=_FakeRequest())

    loc = _location(resp)
    assert "email_oauth_error=microsoft_error" in loc
    assert "access_denied" not in loc


@pytest.mark.asyncio
async def test_callback_tampered_state_returns_generic_error_no_leak():
    callback = _callback_endpoint()
    resp = await callback(code="secret-auth-code", state="not-a-valid-state",
                          error=None, request=_FakeRequest())

    loc = _location(resp)
    assert "email_oauth_error=invalid_state" in loc
    assert "secret-auth-code" not in loc


@pytest.mark.asyncio
async def test_callback_owner_mismatch_does_not_write_tokens():
    from routes.email_helpers import make_oauth_state
    from core.database import EmailAccount

    db, Factory = _make_db()
    _make_account(db, account_id="acct-x", owner="alice")
    db.close()

    token_resp = mock.MagicMock()
    token_resp.raise_for_status = mock.MagicMock()
    token_resp.json.return_value = {"access_token": "eyJ.attacker", "refresh_token": "r", "expires_in": 3600}
    graph_me_resp = mock.MagicMock()
    graph_me_resp.is_success = True
    graph_me_resp.json.return_value = {"mail": "bob@evil.com", "displayName": "Bob"}

    state = make_oauth_state("acct-x", "bob")

    with mock.patch("httpx.post", return_value=token_resp), \
         mock.patch("httpx.get", return_value=graph_me_resp), \
         mock.patch("core.database.SessionLocal", Factory):
        callback = _callback_endpoint()
        resp = await callback(code="code", state=state, error=None, request=_FakeRequest())

    loc = _location(resp)
    assert "email_oauth_error=ownership_error" in loc

    verify_db = Factory()
    row = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-x").first()
    verify_db.close()
    assert row.oauth_access_token is None


@pytest.mark.asyncio
async def test_callback_valid_owner_writes_encrypted_tokens_to_intended_account():
    from routes.email_helpers import make_oauth_state
    from src.secret_storage import decrypt as _dec
    from core.database import EmailAccount

    db, Factory = _make_db()
    _make_account(
        db,
        account_id="acct-v",
        owner="alice",
        imap_host="",
        smtp_host="",
        imap_user="alice@outlook.com",
        smtp_user="ALICE@OUTLOOK.COM",
    )
    _make_account(db, account_id="acct-other", owner="alice")
    db.close()

    raw_access = "eyJ.legit_access_token"
    raw_refresh = "M.legit_refresh_token"
    token_resp = mock.MagicMock()
    token_resp.raise_for_status = mock.MagicMock()
    token_resp.json.return_value = {"access_token": raw_access, "refresh_token": raw_refresh, "expires_in": 3600}
    graph_me_resp = mock.MagicMock()
    graph_me_resp.is_success = True
    graph_me_resp.json.return_value = {"mail": "alice@outlook.com", "displayName": "Alice"}

    state = make_oauth_state("acct-v", "alice")

    with mock.patch("httpx.post", return_value=token_resp), \
         mock.patch("httpx.get", return_value=graph_me_resp), \
         mock.patch("core.database.SessionLocal", Factory):
        callback = _callback_endpoint()
        resp = await callback(code="code", state=state, error=None, request=_FakeRequest())

    assert "email_oauth_success=1" in _location(resp)

    verify_db = Factory()
    target = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-v").first()
    other = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-other").first()
    verify_db.close()

    assert target.oauth_provider == "microsoft"
    assert target.oauth_access_token != raw_access
    assert _dec(target.oauth_access_token) == raw_access
    assert _dec(target.oauth_refresh_token) == raw_refresh
    assert other.oauth_access_token is None
    # Auto-filled Exchange Online defaults for a previously blank host.
    assert target.imap_host == "outlook.office365.com"
    assert target.smtp_host == "smtp.office365.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("me_result", [None, {}, {"mail": None, "userPrincipalName": None}])
async def test_callback_requires_verified_mailbox_identity(me_result):
    from routes.email_helpers import make_oauth_state
    from core.database import EmailAccount

    db, Factory = _make_db()
    _make_account(db, account_id="acct-noid", owner="alice", imap_user="alice@outlook.com")
    db.close()

    token_resp = mock.MagicMock()
    token_resp.raise_for_status = mock.MagicMock()
    token_resp.json.return_value = {"access_token": "eyJ.tok", "refresh_token": "r", "expires_in": 3600}
    graph_me_resp = mock.MagicMock()
    if me_result is None:
        graph_me_resp.is_success = False
    else:
        graph_me_resp.is_success = True
        graph_me_resp.json.return_value = me_result

    state = make_oauth_state("acct-noid", "alice")
    with mock.patch("httpx.post", return_value=token_resp), \
         mock.patch("httpx.get", return_value=graph_me_resp), \
         mock.patch("core.database.SessionLocal", Factory):
        callback = _callback_endpoint()
        resp = await callback(code="code", state=state, error=None, request=_FakeRequest())

    assert "email_oauth_error=identity_verification_failed" in _location(resp)
    verify_db = Factory()
    row = verify_db.query(EmailAccount).filter(EmailAccount.id == "acct-noid").first()
    verify_db.close()
    assert row.oauth_provider is None
    assert row.oauth_access_token is None


# ── /accounts/test host + transport restrictions ──────────────────

def _test_connection_endpoint():
    from routes.email_routes import setup_email_routes
    router = setup_email_routes()
    for route in router.routes:
        if route.path == "/api/email/accounts/test" and "POST" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("test_connection route not found")


@pytest.mark.asyncio
async def test_test_connection_rejects_non_microsoft_imap_host_for_saved_account():
    """oauth_provider is server-owned and can only come from a saved account row
    (inline test payloads cannot select the OAuth branch), so this exercises the
    host allowlist via a saved Microsoft account with a mismatched IMAP host."""
    from src.secret_storage import encrypt as _enc

    future_expiry = str(int(time.time()) + 7200)
    db, Factory = _make_db()
    _make_account(
        db, account_id="acct-ms-badhost", owner="alice",
        imap_host="imap.gmail.com",  # wrong host for a Microsoft OAuth account
        imap_starttls=False,
        oauth_provider="microsoft",
        oauth_access_token=_enc("eyJ.live"),
        oauth_refresh_token=_enc("M.refresh"),
        oauth_token_expiry=future_expiry,
    )
    db.close()

    endpoint = _test_connection_endpoint()

    class _FakeReq:
        async def json(self):
            return {"account_id": "acct-ms-badhost"}

    with mock.patch("core.database.SessionLocal", Factory), \
         mock.patch("routes.email_routes._get_valid_microsoft_token") as token_getter:
        result = await endpoint(req=_FakeReq(), owner="alice")

    token_getter.assert_not_called()
    assert result["imap"]["ok"] is False
    assert "outlook.office365.com" in result["imap"]["error"]


@pytest.mark.asyncio
async def test_test_connection_uses_xoauth2_for_saved_microsoft_account():
    """The saved-account connection test must use XOAUTH2, not conn.login()."""
    from src.secret_storage import encrypt as _enc

    future_expiry = str(int(time.time()) + 7200)
    db, Factory = _make_db()
    _make_account(
        db, account_id="acct-ms-test", owner="alice",
        imap_starttls=False,
        oauth_provider="microsoft",
        oauth_access_token=_enc("eyJ.live"),
        oauth_refresh_token=_enc("M.refresh"),
        oauth_token_expiry=future_expiry,
    )
    db.close()

    endpoint = _test_connection_endpoint()
    mock_imap_conn = mock.MagicMock()
    mock_smtp_conn = mock.MagicMock()

    class _FakeReq:
        async def json(self):
            return {"account_id": "acct-ms-test"}

    with mock.patch("core.database.SessionLocal", Factory), \
         mock.patch("routes.email_routes._open_imap_connection", return_value=mock_imap_conn), \
         mock.patch("routes.email_routes.smtplib.SMTP", return_value=mock_smtp_conn), \
         mock.patch("routes.email_routes.smtplib.SMTP_SSL", return_value=mock_smtp_conn), \
         mock.patch("routes.email_routes._get_valid_microsoft_token", return_value="eyJ.live") as token_getter:
        result = await endpoint(req=_FakeReq(), owner="alice")

    assert result["imap"].get("ok") is True, f"OAuth IMAP test must succeed, got: {result['imap']}"
    mock_imap_conn.authenticate.assert_called_once()
    assert mock_imap_conn.authenticate.call_args[0][0] == "XOAUTH2"
    mock_imap_conn.login.assert_not_called()
    token_getter.assert_called_once()
