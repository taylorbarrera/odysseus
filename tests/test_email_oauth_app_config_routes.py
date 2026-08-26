"""Tests for the inline Google/Microsoft OAuth "app credential" endpoints.

The Client ID/Secret for the Google/Entra app registration used by the
"Connect with Google/Microsoft" button is instance-wide (shared by every
email account), so it's configured contextually from the account form the
first time it's needed rather than via a disconnected global settings page.
Saving is gated to admins (or trusted callers in single-user/no-auth-yet
setups) via `_email_oauth_app_config_allowed`, mirroring the same three-way
branch `_require_auth` uses elsewhere in this file.

Covers:
- `_email_oauth_app_config_allowed` — auth disabled / no AuthManager / no
  users configured yet all trust the caller; once users exist, only an
  admin may configure the app credentials.
- `GET /oauth/{provider}/app-status` — reports whether the app is configured
  (via the existing setting-or-env credential getters) and whether the
  caller is allowed to configure it, without ever leaking the secret value.
  Also returns the (non-secret) client_id/tenant to callers who are allowed
  to configure the app, once it's configured, so the UI can pre-fill an
  "Edit OAuth app credentials" form. Unknown providers 404.
- `POST /oauth/{provider}/app-config` — persists client_id/client_secret(/
  tenant) through `src.settings.save_settings` (so the client secret is
  encrypted at rest, unlike `routes.email_helpers._save_settings`, which
  would silently bypass encryption). Rejects non-admins, a missing
  client_id, and unknown providers. A blank client_secret keeps the
  existing stored secret unchanged (so an admin can fix a typo'd Client ID
  or switch tenants without re-pasting the secret) but is rejected outright
  when no secret has ever been saved for that provider.
"""

from types import SimpleNamespace

import pytest


class _FakeAuthManager:
    def __init__(self, is_configured=True, admins=None):
        self.is_configured = is_configured
        self._admins = set(admins or ())

    def is_admin(self, username):
        return username in self._admins


class _FakeAppState:
    def __init__(self, auth_manager=None):
        self.auth_manager = auth_manager


class _FakeApp:
    def __init__(self, auth_manager=None):
        self.state = _FakeAppState(auth_manager)


class _FakeRequest:
    def __init__(self, auth_manager=None, client_host="127.0.0.1"):
        self.app = _FakeApp(auth_manager)
        self.client = SimpleNamespace(host=client_host)
        self.headers = {"host": "localhost:7000"}
        self.url = SimpleNamespace(scheme="http")
        self._json_body = {}

    async def json(self):
        return self._json_body


# ── _email_oauth_app_config_allowed ────────────────────────────────

def test_allowed_when_auth_disabled(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    from routes.email_helpers import _email_oauth_app_config_allowed
    assert _email_oauth_app_config_allowed(_FakeRequest(), "") is True


def test_allowed_when_no_auth_manager_attached(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from routes.email_helpers import _email_oauth_app_config_allowed
    assert _email_oauth_app_config_allowed(_FakeRequest(auth_manager=None), "") is True


def test_allowed_first_run_before_any_users_exist(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from routes.email_helpers import _email_oauth_app_config_allowed
    mgr = _FakeAuthManager(is_configured=False)
    assert _email_oauth_app_config_allowed(_FakeRequest(auth_manager=mgr), "") is True


def test_admin_allowed_once_configured(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from routes.email_helpers import _email_oauth_app_config_allowed
    mgr = _FakeAuthManager(is_configured=True, admins={"alice"})
    assert _email_oauth_app_config_allowed(_FakeRequest(auth_manager=mgr), "alice") is True


def test_non_admin_rejected_once_configured(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from routes.email_helpers import _email_oauth_app_config_allowed
    mgr = _FakeAuthManager(is_configured=True, admins={"alice"})
    assert _email_oauth_app_config_allowed(_FakeRequest(auth_manager=mgr), "bob") is False


# ── Route wiring helpers ────────────────────────────────────────────

def _find_endpoint(method, path):
    from routes.email_routes import setup_email_routes
    router = setup_email_routes()
    for route in router.routes:
        if route.path == path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"{method} {path} route not found")


def _status_endpoint():
    return _find_endpoint("GET", "/api/email/oauth/{provider}/app-status")


def _config_endpoint():
    return _find_endpoint("POST", "/api/email/oauth/{provider}/app-config")


# ── GET /oauth/{provider}/app-status ────────────────────────────────

@pytest.mark.asyncio
async def test_app_status_unknown_provider_404():
    from fastapi import HTTPException
    status = _status_endpoint()
    with pytest.raises(HTTPException) as exc:
        await status(provider="yahoo", request=_FakeRequest(), owner="")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_app_status_not_configured_reports_can_configure(monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("AUTH_ENABLED", "false")
    import unittest.mock as mock
    with mock.patch("src.settings.get_setting", return_value=""):
        status = _status_endpoint()
        result = await status(provider="google", request=_FakeRequest(), owner="")
    assert result["configured"] is False
    assert result["can_configure"] is True
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_status_configured_when_id_and_secret_present(monkeypatch):
    monkeypatch.setenv("MICROSOFT_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("MICROSOFT_OAUTH_CLIENT_SECRET", "csecret")
    import unittest.mock as mock
    with mock.patch("src.settings.get_setting", return_value=""):
        status = _status_endpoint()
        result = await status(provider="microsoft", request=_FakeRequest(), owner="")
    assert result["configured"] is True
    # never leak the secret value back to the client
    assert "csecret" not in str(result)
    assert "client_secret" not in result


@pytest.mark.asyncio
async def test_app_status_non_admin_cannot_configure(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    mgr = _FakeAuthManager(is_configured=True, admins={"alice"})
    status = _status_endpoint()
    result = await status(provider="google", request=_FakeRequest(auth_manager=mgr), owner="bob")
    assert result["can_configure"] is False


@pytest.mark.asyncio
async def test_app_status_exposes_client_id_and_tenant_to_admin_when_configured(monkeypatch, tmp_path):
    # An admin needs to see the currently-saved (non-secret) Client ID/Tenant
    # so the "Edit OAuth app credentials" UI can pre-fill them — but the
    # secret itself must never come back from this endpoint.
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)
    from src.settings import save_settings, load_settings
    current = load_settings()
    current["microsoft_oauth_client_id"] = "saved-client-id"
    current["microsoft_oauth_client_secret"] = "saved-secret"
    current["microsoft_oauth_tenant"] = "consumers"
    save_settings(current)

    status = _status_endpoint()
    result = await status(provider="microsoft", request=_FakeRequest(), owner="")
    assert result["configured"] is True
    assert result["client_id"] == "saved-client-id"
    assert result["tenant"] == "consumers"
    assert "client_secret" not in result
    assert "saved-secret" not in str(result)
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_status_omits_client_id_when_caller_cannot_configure(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)
    from src.settings import save_settings, load_settings
    current = load_settings()
    current["microsoft_oauth_client_id"] = "saved-client-id"
    current["microsoft_oauth_client_secret"] = "saved-secret"
    save_settings(current)

    mgr = _FakeAuthManager(is_configured=True, admins={"alice"})
    status = _status_endpoint()
    result = await status(provider="microsoft", request=_FakeRequest(auth_manager=mgr), owner="bob")
    assert result["configured"] is True
    assert result["can_configure"] is False
    assert "client_id" not in result
    assert "tenant" not in result
    monkeypatch.setenv("AUTH_ENABLED", "true")


# ── POST /oauth/{provider}/app-config ───────────────────────────────

@pytest.mark.asyncio
async def test_app_config_unknown_provider_404():
    from fastapi import HTTPException
    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "x", "client_secret": "y"}
    with pytest.raises(HTTPException) as exc:
        await config(provider="yahoo", request=req, owner="")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_app_config_rejects_non_admin(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from fastapi import HTTPException
    mgr = _FakeAuthManager(is_configured=True, admins={"alice"})
    config = _config_endpoint()
    req = _FakeRequest(auth_manager=mgr)
    req._json_body = {"client_id": "x", "client_secret": "y"}
    with pytest.raises(HTTPException) as exc:
        await config(provider="google", request=req, owner="bob")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_app_config_requires_client_id(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    from fastapi import HTTPException
    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "", "client_secret": ""}
    with pytest.raises(HTTPException) as exc:
        await config(provider="google", request=req, owner="")
    assert exc.value.status_code == 400
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_config_requires_secret_on_first_save(monkeypatch, tmp_path):
    # No existing secret saved yet — omitting it must be rejected rather
    # than silently persisting an app with no secret at all.
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)
    from fastapi import HTTPException
    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "new-client-id", "client_secret": ""}
    with pytest.raises(HTTPException) as exc:
        await config(provider="microsoft", request=req, owner="")
    assert exc.value.status_code == 400
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_config_blank_secret_keeps_existing_secret_when_editing(monkeypatch, tmp_path):
    # Editing an already-configured app (e.g. to fix a typo'd Client ID or
    # switch Microsoft's tenant to "consumers") should not require
    # re-entering the Client Secret — leaving it blank keeps the one
    # already on disk.
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)
    from src.settings import save_settings, load_settings, get_setting
    current = load_settings()
    current["microsoft_oauth_client_id"] = "old-client-id"
    current["microsoft_oauth_client_secret"] = "original-secret"
    current["microsoft_oauth_tenant"] = "common"
    save_settings(current)

    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "fixed-client-id", "client_secret": "", "tenant": "consumers"}
    result = await config(provider="microsoft", request=req, owner="")

    assert result == {"ok": True, "configured": True}
    assert get_setting("microsoft_oauth_client_id") == "fixed-client-id"
    assert get_setting("microsoft_oauth_client_secret") == "original-secret"
    assert get_setting("microsoft_oauth_tenant") == "consumers"
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_config_nonblank_secret_replaces_existing_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)
    from src.settings import save_settings, load_settings, get_setting
    current = load_settings()
    current["microsoft_oauth_client_id"] = "old-client-id"
    current["microsoft_oauth_client_secret"] = "original-secret"
    save_settings(current)

    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "old-client-id", "client_secret": "brand-new-secret", "tenant": "consumers"}
    result = await config(provider="microsoft", request=req, owner="")

    assert result == {"ok": True, "configured": True}
    assert get_setting("microsoft_oauth_client_secret") == "brand-new-secret"
    monkeypatch.setenv("AUTH_ENABLED", "true")


@pytest.mark.asyncio
async def test_app_config_saves_encrypted_via_src_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr("src.settings.SETTINGS_FILE", settings_file)
    monkeypatch.setattr("src.settings._settings_cache", None)

    config = _config_endpoint()
    req = _FakeRequest()
    req._json_body = {"client_id": "my-client-id", "client_secret": "super-secret", "tenant": "contoso"}
    result = await config(provider="microsoft", request=req, owner="")

    assert result == {"ok": True, "configured": True}

    # The value on disk must not be the raw secret (encrypted at rest).
    raw = settings_file.read_text(encoding="utf-8")
    assert "super-secret" not in raw
    assert "my-client-id" in raw  # client id is not secret-shaped, stays plaintext

    # But it must resolve back to the raw secret through the normal getters.
    from src.settings import get_setting
    assert get_setting("microsoft_oauth_client_secret") == "super-secret"
    assert get_setting("microsoft_oauth_client_id") == "my-client-id"
    assert get_setting("microsoft_oauth_tenant") == "contoso"
    monkeypatch.setenv("AUTH_ENABLED", "true")
