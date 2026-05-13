from __future__ import annotations

import json
import re
from pathlib import Path


HOSTED_URL = "https://web-production-62b0d.up.railway.app/mcp"

SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"sk-ant-api[A-Za-z0-9_\-]{20,}"),
]

AUTH_KEY_PATTERNS = [
    # Catch any line that looks like a real key assignment (not a placeholder or env var reference)
    re.compile(r'(?:client_key|admin_key)\s*[:=]\s*"(?!YOUR_|change-me|change-this)[A-Za-z0-9_\-]{16,}"'),
]


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _assert_no_real_secrets(text: str, source: str) -> None:
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), f"{source} contains secret-looking value: {pattern.pattern}"


# ── HOSTED_DEMO.md ────────────────────────────────────────────────────────────

def test_hosted_demo_doc_exists():
    p = Path("docs/HOSTED_DEMO.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_hosted_demo_doc_contains_live_url():
    text = _read("docs/HOSTED_DEMO.md")
    assert HOSTED_URL in text, f"docs/HOSTED_DEMO.md missing live URL: {HOSTED_URL}"


def test_hosted_demo_doc_mentions_auth():
    text = _read("docs/HOSTED_DEMO.md")
    assert "client_key" in text
    assert "admin_key" in text
    assert "health_check" in text


def test_hosted_demo_doc_no_real_secrets():
    _assert_no_real_secrets(_read("docs/HOSTED_DEMO.md"), "docs/HOSTED_DEMO.md")


# ── README.md ─────────────────────────────────────────────────────────────────

def test_readme_contains_hosted_url():
    text = _read("README.md")
    assert HOSTED_URL in text, f"README.md missing live URL: {HOSTED_URL}"


def test_readme_no_real_secrets():
    _assert_no_real_secrets(_read("README.md"), "README.md")


def test_readme_lists_hosted_demo_doc():
    text = _read("README.md")
    assert "HOSTED_DEMO" in text


# ── DEPLOY_RAILWAY.md ─────────────────────────────────────────────────────────

def test_deploy_railway_contains_hosted_url():
    text = _read("DEPLOY_RAILWAY.md")
    assert HOSTED_URL in text, f"DEPLOY_RAILWAY.md missing live URL: {HOSTED_URL}"


def test_deploy_railway_has_status_section():
    text = _read("DEPLOY_RAILWAY.md")
    assert "live" in text.lower()
    assert "health_check" in text


def test_deploy_railway_no_real_secrets():
    _assert_no_real_secrets(_read("DEPLOY_RAILWAY.md"), "DEPLOY_RAILWAY.md")


# ── docs/CLIENT_CONFIGS.md ────────────────────────────────────────────────────

def test_client_configs_contains_hosted_url():
    text = _read("docs/CLIENT_CONFIGS.md")
    assert HOSTED_URL in text, f"docs/CLIENT_CONFIGS.md missing live URL: {HOSTED_URL}"


def test_client_configs_keeps_placeholder():
    text = _read("docs/CLIENT_CONFIGS.md")
    assert "YOUR_DOMAIN" in text, "Placeholder should remain for custom deployments"


def test_client_configs_no_real_secrets():
    _assert_no_real_secrets(_read("docs/CLIENT_CONFIGS.md"), "docs/CLIENT_CONFIGS.md")


# ── discovery/client_connection_examples.json ────────────────────────────────

def test_connection_examples_contains_hosted_url():
    text = _read("discovery/client_connection_examples.json")
    assert HOSTED_URL in text


def test_connection_examples_is_valid_json():
    data = json.loads(_read("discovery/client_connection_examples.json"))
    assert isinstance(data, dict)


def test_connection_examples_live_url_field():
    data = json.loads(_read("discovery/client_connection_examples.json"))
    streamable = data.get("shadowgate_mcp_connection_examples", {}).get("streamable_http", {})
    assert streamable.get("url_hosted_live") == HOSTED_URL


def test_connection_examples_no_real_secrets():
    _assert_no_real_secrets(
        _read("discovery/client_connection_examples.json"),
        "discovery/client_connection_examples.json",
    )


# ── discovery/shadowgate_manifest.json ───────────────────────────────────────

def test_manifest_contains_production_url():
    data = json.loads(_read("discovery/shadowgate_manifest.json"))
    production_url = data.get("transport", {}).get("production_url")
    assert production_url == HOSTED_URL, f"Manifest production_url should be {HOSTED_URL}, got {production_url}"


def test_manifest_keeps_placeholder():
    data = json.loads(_read("discovery/shadowgate_manifest.json"))
    placeholder = data.get("transport", {}).get("production_url_placeholder", "")
    assert "YOUR_DOMAIN" in placeholder or "RAILWAY_URL" in placeholder


def test_manifest_no_real_secrets():
    _assert_no_real_secrets(
        _read("discovery/shadowgate_manifest.json"),
        "discovery/shadowgate_manifest.json",
    )


# ── release_check lists HOSTED_DEMO.md ───────────────────────────────────────

def test_release_check_lists_hosted_demo():
    text = _read("scripts/release_check.py")
    assert "docs/HOSTED_DEMO.md" in text
