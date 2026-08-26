"""Regression coverage for Microsoft OAuth configuration in Docker Compose."""

from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_PATHS = tuple(
    ROOT / name
    for name in (
        "docker-compose.yml",
        "docker-compose.gpu-nvidia.yml",
        "docker-compose.gpu-amd.yml",
    )
)
ENV_EXAMPLE_PATH = ROOT / ".env.example"


def _env_example():
    if not ENV_EXAMPLE_PATH.exists():
        pytest.skip("this checkout does not include the optional .env.example file")
    return ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


def _odysseus_environment(path):
    compose = yaml.safe_load(path.read_text(encoding="utf-8"))
    return set(compose["services"]["odysseus"]["environment"])


@pytest.mark.parametrize(
    "key",
    (
        "MICROSOFT_OAUTH_CLIENT_ID",
        "MICROSOFT_OAUTH_CLIENT_SECRET",
        "MICROSOFT_OAUTH_TENANT",
        "MICROSOFT_OAUTH_REDIRECT_URI",
    ),
)
def test_microsoft_oauth_setting_is_forwarded(key):
    expected = f"{key}=${{{key}:-}}"
    for path in COMPOSE_PATHS:
        assert expected in _odysseus_environment(path), path.name


@pytest.mark.parametrize(
    "key",
    (
        "MICROSOFT_OAUTH_CLIENT_ID",
        "MICROSOFT_OAUTH_CLIENT_SECRET",
        "MICROSOFT_OAUTH_TENANT",
        "MICROSOFT_OAUTH_REDIRECT_URI",
    ),
)
def test_microsoft_oauth_setting_is_documented(key):
    assert f"# {key}=" in _env_example()


def test_microsoft_oauth_example_uses_a_neutral_secret_placeholder():
    env_example = _env_example()
    assert "MICROSOFT_OAUTH_CLIENT_SECRET=replace-with-client-secret" in env_example


def test_microsoft_redirect_documentation_covers_https_and_reverse_proxies():
    oauth_section = _env_example().split("# Microsoft OAuth2", 1)[1].split("# Origin the MCP OAuth callback", 1)[0]
    assert "HTTPS" in oauth_section
    assert "reverse-proxy" in oauth_section
    assert "exactly match a redirect URI" in oauth_section
