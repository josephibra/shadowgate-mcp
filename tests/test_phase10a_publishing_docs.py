from __future__ import annotations

import re
from pathlib import Path


GITHUB_URL = "https://github.com/josephibra/shadowgate-mcp"
HOSTED_URL = "https://web-production-62b0d.up.railway.app/mcp"
RELEASE_TAG = "shadowgate-v0.4.0-hardened"

SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"sk-ant-api[A-Za-z0-9_\-]{20,}"),
    re.compile(r"0x[0-9a-fA-F]{40}"),
]


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _no_real_secrets(text: str, source: str) -> None:
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), f"{source} may contain a real secret: {pattern.pattern}"


# ── docs/PUBLISHING.md ────────────────────────────────────────────────────────

def test_publishing_doc_exists():
    p = Path("docs/PUBLISHING.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_publishing_doc_contains_github_url():
    text = _read("docs/PUBLISHING.md")
    assert GITHUB_URL in text, f"docs/PUBLISHING.md missing GitHub URL: {GITHUB_URL}"


def test_publishing_doc_contains_hosted_url():
    text = _read("docs/PUBLISHING.md")
    assert HOSTED_URL in text, f"docs/PUBLISHING.md missing hosted URL: {HOSTED_URL}"


def test_publishing_doc_contains_release_tag():
    text = _read("docs/PUBLISHING.md")
    assert RELEASE_TAG in text, f"docs/PUBLISHING.md missing release tag: {RELEASE_TAG}"


def test_publishing_doc_has_smithery_checklist():
    text = _read("docs/PUBLISHING.md")
    assert "Smithery" in text
    assert "smithery.yaml" in text


def test_publishing_doc_has_mcp_registry_checklist():
    text = _read("docs/PUBLISHING.md")
    assert "MCP Registry" in text or "modelcontextprotocol" in text


def test_publishing_doc_has_recommended_tools():
    text = _read("docs/PUBLISHING.md")
    for tool in ["analyze_text", "gate_mcp_tool_call", "gate_mcp_response",
                 "evaluate_mcp_transaction", "review_mcp_manifest",
                 "approve_mcp_manifest_identity", "create_security_report"]:
        assert tool in text, f"docs/PUBLISHING.md missing recommended tool: {tool}"


def test_publishing_doc_warns_against_secrets():
    text = _read("docs/PUBLISHING.md")
    assert "SHADOWGATE_ADMIN_KEY" in text
    assert "SHADOWGATE_CLIENT_KEY" in text


def test_publishing_doc_no_real_secrets():
    _no_real_secrets(_read("docs/PUBLISHING.md"), "docs/PUBLISHING.md")


# ── discovery/mcp_registry_submission.md ─────────────────────────────────────

def test_mcp_registry_submission_exists():
    p = Path("discovery/mcp_registry_submission.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_mcp_registry_submission_contains_github_url():
    text = _read("discovery/mcp_registry_submission.md")
    assert GITHUB_URL in text


def test_mcp_registry_submission_contains_hosted_url():
    text = _read("discovery/mcp_registry_submission.md")
    assert HOSTED_URL in text


def test_mcp_registry_submission_contains_release_tag():
    text = _read("discovery/mcp_registry_submission.md")
    assert RELEASE_TAG in text


def test_mcp_registry_submission_has_required_fields():
    text = _read("discovery/mcp_registry_submission.md")
    for phrase in ["Name", "Description", "License", "Maintainer",
                   "Transport", "Auth", "Security Model", "SHADOWGATE_HOST"]:
        assert phrase in text or phrase.lower() in text.lower(), (
            f"mcp_registry_submission.md missing expected content: {phrase!r}"
        )


def test_mcp_registry_submission_lists_public_tools():
    text = _read("discovery/mcp_registry_submission.md")
    for tool in ["health_check", "analyze_text", "gate_mcp_tool_call",
                 "gate_mcp_response", "create_security_report"]:
        assert tool in text


def test_mcp_registry_submission_has_auth_note():
    text = _read("discovery/mcp_registry_submission.md")
    assert "client_key" in text
    assert "admin_key" in text


def test_mcp_registry_submission_no_real_secrets():
    _no_real_secrets(
        _read("discovery/mcp_registry_submission.md"),
        "discovery/mcp_registry_submission.md",
    )


# ── smithery.yaml ─────────────────────────────────────────────────────────────

def test_smithery_yaml_has_real_github_url():
    text = _read("smithery.yaml")
    assert GITHUB_URL in text, f"smithery.yaml should reference real GitHub URL: {GITHUB_URL}"


def test_smithery_yaml_has_hosted_endpoint():
    text = _read("smithery.yaml")
    assert HOSTED_URL in text, f"smithery.yaml should reference hosted endpoint: {HOSTED_URL}"


def test_smithery_yaml_no_placeholder_repo():
    text = _read("smithery.yaml")
    assert "YOUR_USERNAME" not in text, "smithery.yaml still has placeholder GitHub username"


def test_smithery_yaml_no_real_secrets():
    _no_real_secrets(_read("smithery.yaml"), "smithery.yaml")


# ── README.md ─────────────────────────────────────────────────────────────────

def test_readme_has_publishing_section():
    text = _read("README.md")
    assert "Publishing and Discovery" in text or "Publishing and discovery" in text


def test_readme_links_to_publishing_doc():
    text = _read("README.md")
    assert "docs/PUBLISHING.md" in text


def test_readme_links_to_registry_submission():
    text = _read("README.md")
    assert "discovery/mcp_registry_submission.md" in text


def test_readme_links_to_smithery_yaml():
    text = _read("README.md")
    assert "smithery.yaml" in text


def test_readme_links_to_payment_xpay():
    text = _read("README.md")
    assert "PAYMENT_XPAY" in text


def test_readme_has_github_url():
    text = _read("README.md")
    assert GITHUB_URL in text


# ── release_check lists new files ────────────────────────────────────────────

def test_release_check_lists_publishing_doc():
    text = _read("scripts/release_check.py")
    assert "docs/PUBLISHING.md" in text


def test_release_check_lists_registry_submission():
    text = _read("scripts/release_check.py")
    assert "discovery/mcp_registry_submission.md" in text
