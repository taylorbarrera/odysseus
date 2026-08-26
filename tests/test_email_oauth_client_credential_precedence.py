"""Tests for OAuth app credential precedence in routes/email_helpers.py.

`_google_oauth_client_id/_secret` and `_microsoft_oauth_client_id/_secret`
(and `_microsoft_oauth_tenant`) resolve to a UI-configured setting (set from
the email account form's "Connect with Google/Microsoft" step, or via the
/api/email/oauth/{provider}/app-config route) when present, falling back to
the GOOGLE_OAUTH_*/MICROSOFT_OAUTH_* env vars for existing .env-only setups.
A setting takes priority over the env var of the same name when both are set.
"""

import unittest.mock as mock


def test_google_client_id_prefers_setting_over_env(monkeypatch):
    from routes.email_helpers import _google_oauth_client_id

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "env-client-id")
    with mock.patch("src.settings.get_setting", return_value="setting-client-id"):
        assert _google_oauth_client_id() == "setting-client-id"


def test_google_client_id_falls_back_to_env_when_setting_unset(monkeypatch):
    from routes.email_helpers import _google_oauth_client_id

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "env-client-id")
    with mock.patch("src.settings.get_setting", return_value=""):
        assert _google_oauth_client_id() == "env-client-id"


def test_google_client_secret_prefers_setting_over_env(monkeypatch):
    from routes.email_helpers import _google_oauth_client_secret

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "env-secret")
    with mock.patch("src.settings.get_setting", return_value="setting-secret"):
        assert _google_oauth_client_secret() == "setting-secret"


def test_microsoft_client_id_prefers_setting_over_env(monkeypatch):
    from routes.email_helpers import _microsoft_oauth_client_id

    monkeypatch.setenv("MICROSOFT_OAUTH_CLIENT_ID", "env-ms-id")
    with mock.patch("src.settings.get_setting", return_value="setting-ms-id"):
        assert _microsoft_oauth_client_id() == "setting-ms-id"


def test_microsoft_client_secret_falls_back_to_env_when_setting_unset(monkeypatch):
    from routes.email_helpers import _microsoft_oauth_client_secret

    monkeypatch.setenv("MICROSOFT_OAUTH_CLIENT_SECRET", "env-ms-secret")
    with mock.patch("src.settings.get_setting", return_value=""):
        assert _microsoft_oauth_client_secret() == "env-ms-secret"


def test_microsoft_tenant_prefers_setting_over_env(monkeypatch):
    from routes.email_helpers import _microsoft_oauth_tenant

    monkeypatch.setenv("MICROSOFT_OAUTH_TENANT", "env-tenant")
    with mock.patch("src.settings.get_setting", return_value="contoso.onmicrosoft.com"):
        assert _microsoft_oauth_tenant() == "contoso.onmicrosoft.com"


def test_microsoft_tenant_defaults_to_common_when_nothing_set(monkeypatch):
    from routes.email_helpers import _microsoft_oauth_tenant

    monkeypatch.delenv("MICROSOFT_OAUTH_TENANT", raising=False)
    with mock.patch("src.settings.get_setting", return_value=""):
        assert _microsoft_oauth_tenant() == "common"


def test_credentials_empty_when_neither_setting_nor_env_configured(monkeypatch):
    from routes.email_helpers import _google_oauth_client_id, _google_oauth_client_secret

    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    with mock.patch("src.settings.get_setting", return_value=""):
        assert _google_oauth_client_id() == ""
        assert _google_oauth_client_secret() == ""
