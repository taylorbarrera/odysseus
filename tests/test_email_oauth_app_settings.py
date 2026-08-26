"""Tests for at-rest encryption of OAuth app client-secret settings.

Covers src/settings.py's `_ENCRYPTED_SETTING_KEYS` handling:

- `save_settings()` encrypts `google_oauth_client_secret` /
  `microsoft_oauth_client_secret` before writing to disk (never stores the
  raw secret in data/settings.json).
- `load_settings()` / `get_setting()` transparently decrypt those keys back
  to plaintext for callers (routes/email_helpers.py's OAuth flows expect a
  ready-to-use secret, not an "enc:"-prefixed blob).
- Non-secret keys (client IDs, tenant) are round-tripped unmodified — no
  double-encryption, no accidental encryption of unrelated settings.
- A pre-existing plaintext value (e.g. a hand-edited settings.json from
  before this feature existed) still loads correctly and gets encrypted on
  the next save (matches the same migrate-on-write pattern already used by
  src/integrations.py for Integration.api_key).
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

_TMP = Path(tempfile.mkdtemp(prefix="odysseus-settings-oauth-test-"))
os.environ.setdefault("DATA_DIR", str(_TMP))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP / 'app.db'}")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _fresh(tmp_path):
    """Return a (settings_module, settings_path) pair with an isolated,
    cache-cleared settings file for this test."""
    import src.settings as s
    settings_path = tmp_path / "settings.json"
    s._settings_cache = None
    return s, settings_path


def test_save_settings_encrypts_client_secrets_on_disk():
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            s.save_settings({
                **s.DEFAULT_SETTINGS,
                "google_oauth_client_secret": "raw-google-secret",
                "microsoft_oauth_client_secret": "raw-microsoft-secret",
            })
            raw_text = settings_path.read_text(encoding="utf-8")
            raw_on_disk = json.loads(raw_text)

    assert raw_on_disk["google_oauth_client_secret"] != "raw-google-secret"
    assert raw_on_disk["microsoft_oauth_client_secret"] != "raw-microsoft-secret"
    assert "raw-google-secret" not in raw_text
    assert "raw-microsoft-secret" not in raw_text


def test_load_settings_decrypts_client_secrets_for_callers():
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            s.save_settings({
                **s.DEFAULT_SETTINGS,
                "google_oauth_client_secret": "raw-google-secret",
            })
            s._settings_cache = None
            loaded = s.load_settings()

    assert loaded["google_oauth_client_secret"] == "raw-google-secret"


def test_get_setting_returns_decrypted_client_secret():
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            s.save_settings({**s.DEFAULT_SETTINGS, "microsoft_oauth_client_secret": "ms-secret-xyz"})
            s._settings_cache = None
            assert s.get_setting("microsoft_oauth_client_secret") == "ms-secret-xyz"


def test_client_id_and_tenant_are_not_encrypted():
    """Only the *_client_secret keys are sensitive enough to warrant at-rest
    encryption; client IDs and the tenant are not secret (a client ID is
    already visible in outbound OAuth redirect URLs)."""
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            s.save_settings({
                **s.DEFAULT_SETTINGS,
                "google_oauth_client_id": "plain-client-id",
                "microsoft_oauth_tenant": "contoso.onmicrosoft.com",
            })
            raw_on_disk = json.loads(settings_path.read_text(encoding="utf-8"))

    assert raw_on_disk["google_oauth_client_id"] == "plain-client-id"
    assert raw_on_disk["microsoft_oauth_tenant"] == "contoso.onmicrosoft.com"


def test_preexisting_plaintext_secret_still_loads_and_is_encrypted_on_resave():
    """A hand-edited settings.json written before this feature existed has a
    plaintext client secret. It must still load correctly (secret_storage's
    decrypt() passes through non-"enc:"-prefixed values unchanged), and the
    next save must encrypt it (migrate-on-write, mirroring
    src/integrations.py's _has_plaintext_api_key handling)."""
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        settings_path.write_text(
            json.dumps({"google_oauth_client_secret": "legacy-plaintext-secret"}),
            encoding="utf-8",
        )
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            loaded = s.load_settings()
            assert loaded["google_oauth_client_secret"] == "legacy-plaintext-secret"

            s.save_settings(loaded)
            raw_on_disk = json.loads(settings_path.read_text(encoding="utf-8"))

    assert raw_on_disk["google_oauth_client_secret"] != "legacy-plaintext-secret"


def test_empty_client_secret_round_trips_as_empty_string():
    """An empty/unset secret must not be encrypted into a non-empty blob —
    that would make "not configured" indistinguishable from "configured"."""
    import src.settings as s
    with tempfile.TemporaryDirectory() as d:
        settings_path = Path(d) / "settings.json"
        s._settings_cache = None
        with patch.object(s, "SETTINGS_FILE", str(settings_path)):
            s.save_settings({**s.DEFAULT_SETTINGS, "google_oauth_client_secret": ""})
            raw_on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
            s._settings_cache = None
            loaded = s.load_settings()

    assert raw_on_disk["google_oauth_client_secret"] == ""
    assert loaded["google_oauth_client_secret"] == ""
