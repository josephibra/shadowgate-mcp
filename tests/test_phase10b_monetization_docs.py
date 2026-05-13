from __future__ import annotations

import re
from pathlib import Path


GITHUB_URL = "https://github.com/josephibra/shadowgate-mcp"
HOSTED_URL = "https://web-production-62b0d.up.railway.app/mcp"

SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"sk-ant-api[A-Za-z0-9_\-]{20,}"),
    re.compile(r"0x[0-9a-fA-F]{40}"),
]

WALLET_PATTERNS = [
    re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
]


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _no_real_secrets(text: str, source: str) -> None:
    for pattern in SECRET_PATTERNS:
        assert not pattern.search(text), f"{source} may contain a real secret: {pattern.pattern}"


def _no_wallet_addresses(text: str, source: str) -> None:
    for pattern in WALLET_PATTERNS:
        assert not pattern.search(text), f"{source} may contain a wallet address: {pattern.pattern}"


# ── docs/PAYMENT_XPAY.md ─────────────────────────────────────────────────────

def test_payment_xpay_exists():
    p = Path("docs/PAYMENT_XPAY.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_payment_xpay_has_hosted_url():
    text = _read("docs/PAYMENT_XPAY.md")
    assert HOSTED_URL in text, f"docs/PAYMENT_XPAY.md missing hosted Railway URL: {HOSTED_URL}"


def test_payment_xpay_has_monetization_flow():
    text = _read("docs/PAYMENT_XPAY.md")
    assert "XPay" in text or "x402" in text
    assert "proxy" in text.lower()


def test_payment_xpay_mentions_free_self_hosted():
    text = _read("docs/PAYMENT_XPAY.md")
    assert "self-host" in text.lower() or "self hosted" in text.lower()


def test_payment_xpay_warns_against_secrets():
    text = _read("docs/PAYMENT_XPAY.md")
    assert "SHADOWGATE_ADMIN_KEY" in text or "SHADOWGATE_CLIENT_KEY" in text


def test_payment_xpay_no_real_secrets():
    _no_real_secrets(_read("docs/PAYMENT_XPAY.md"), "docs/PAYMENT_XPAY.md")


def test_payment_xpay_no_wallet_addresses():
    _no_wallet_addresses(_read("docs/PAYMENT_XPAY.md"), "docs/PAYMENT_XPAY.md")


# ── docs/PRICING_MODEL.md ────────────────────────────────────────────────────

def test_pricing_model_exists():
    p = Path("docs/PRICING_MODEL.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_pricing_model_has_free_tier():
    text = _read("docs/PRICING_MODEL.md")
    assert "free" in text.lower() or "self-host" in text.lower()


def test_pricing_model_has_paid_tools():
    text = _read("docs/PRICING_MODEL.md")
    for tool in ["analyze_text", "gate_mcp_tool_call", "gate_mcp_response",
                 "evaluate_mcp_transaction", "review_mcp_manifest", "create_security_report"]:
        assert tool in text, f"docs/PRICING_MODEL.md missing tool: {tool}"


def test_pricing_model_has_rationale():
    text = _read("docs/PRICING_MODEL.md")
    assert "volume" in text.lower() or "per-call" in text.lower() or "usage" in text.lower()


def test_pricing_model_has_disclaimer():
    text = _read("docs/PRICING_MODEL.md")
    assert "calibrat" in text.lower() or "adjust" in text.lower() or "illustrative" in text.lower()


def test_pricing_model_no_real_secrets():
    _no_real_secrets(_read("docs/PRICING_MODEL.md"), "docs/PRICING_MODEL.md")


def test_pricing_model_no_wallet_addresses():
    _no_wallet_addresses(_read("docs/PRICING_MODEL.md"), "docs/PRICING_MODEL.md")


# ── docs/PASSIVE_PLATFORMS.md ────────────────────────────────────────────────

def test_passive_platforms_exists():
    p = Path("docs/PASSIVE_PLATFORMS.md")
    assert p.exists()
    assert p.stat().st_size > 0


def test_passive_platforms_has_github_url():
    text = _read("docs/PASSIVE_PLATFORMS.md")
    assert GITHUB_URL in text


def test_passive_platforms_has_railway_url():
    text = _read("docs/PASSIVE_PLATFORMS.md")
    assert HOSTED_URL in text


def test_passive_platforms_covers_essential_platforms():
    text = _read("docs/PASSIVE_PLATFORMS.md")
    for platform in ["GitHub", "Railway", "Smithery", "MCP Registry", "XPay"]:
        assert platform in text, f"docs/PASSIVE_PLATFORMS.md missing platform: {platform}"


def test_passive_platforms_covers_optional_platforms():
    text = _read("docs/PASSIVE_PLATFORMS.md")
    for platform in ["Product Hunt", "Hacker News", "Reddit"]:
        assert platform in text, f"docs/PASSIVE_PLATFORMS.md missing optional platform: {platform}"


def test_passive_platforms_no_real_secrets():
    _no_real_secrets(_read("docs/PASSIVE_PLATFORMS.md"), "docs/PASSIVE_PLATFORMS.md")


# ── README.md ─────────────────────────────────────────────────────────────────

def test_readme_has_passive_discovery_section():
    text = _read("README.md")
    assert "Passive" in text and "Discovery" in text


def test_readme_links_to_payment_xpay():
    text = _read("README.md")
    assert "docs/PAYMENT_XPAY.md" in text


def test_readme_links_to_pricing_model():
    text = _read("README.md")
    assert "docs/PRICING_MODEL.md" in text


def test_readme_links_to_passive_platforms():
    text = _read("README.md")
    assert "docs/PASSIVE_PLATFORMS.md" in text


# ── release_check lists new files ────────────────────────────────────────────

def test_release_check_lists_pricing_model():
    text = _read("scripts/release_check.py")
    assert "docs/PRICING_MODEL.md" in text


def test_release_check_lists_passive_platforms():
    text = _read("scripts/release_check.py")
    assert "docs/PASSIVE_PLATFORMS.md" in text
