from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any


ADMIN_KEY_ENV = "SHADOWGATE_ADMIN_KEY"
CLIENT_KEY_ENV = "SHADOWGATE_CLIENT_KEY"


PROTECTED_ADMIN_TOOLS = [
    "set_policy_mode",
    "set_mcp_server_trust",
    "get_server_registry",
    "get_audit_summary",
    "get_recent_audit_events",
    "create_security_report",
]


PROTECTED_CLIENT_TOOLS = [
    "scan_text",
    "redact_secrets",
    "get_risk_score",
    "decide_policy",
    "inspect_mcp_response",
    "inspect_mcp_tool_call",
    "gate_mcp_tool_call",
    "gate_mcp_response",
    "evaluate_mcp_transaction",
    "inspect_tool_schema",
    "review_mcp_manifest",
    "scan_batch",
    "simulate_policy_modes",
]


def _configured_admin_key() -> str:
    return os.environ.get(ADMIN_KEY_ENV, "").strip()


def _configured_client_key() -> str:
    return os.environ.get(CLIENT_KEY_ENV, "").strip()


def _key_fingerprint(key: str) -> str | None:
    if not key:
        return None
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def require_admin_key(provided_key: str | None = None) -> dict[str, Any]:
    configured = _configured_admin_key()

    if not configured:
        return {
            "ok": True,
            "auth_required": False,
            "auth_type": "admin",
            "mode": "dev_no_admin_key",
        }

    provided = (provided_key or "").strip()

    if secrets.compare_digest(provided, configured):
        return {
            "ok": True,
            "auth_required": True,
            "auth_type": "admin",
            "mode": "admin_key_valid",
            "admin_key_fingerprint": _key_fingerprint(configured),
        }

    return {
        "ok": False,
        "auth_required": True,
        "auth_type": "admin",
        "error": "Invalid or missing admin key.",
        "admin_key_env_var": ADMIN_KEY_ENV,
    }


def require_client_key(provided_key: str | None = None) -> dict[str, Any]:
    configured = _configured_client_key()

    if not configured:
        return {
            "ok": True,
            "auth_required": False,
            "auth_type": "client",
            "mode": "dev_no_client_key",
        }

    provided = (provided_key or "").strip()

    if secrets.compare_digest(provided, configured):
        return {
            "ok": True,
            "auth_required": True,
            "auth_type": "client",
            "mode": "client_key_valid",
            "client_key_fingerprint": _key_fingerprint(configured),
        }

    return {
        "ok": False,
        "auth_required": True,
        "auth_type": "client",
        "error": "Invalid or missing client key.",
        "client_key_env_var": CLIENT_KEY_ENV,
    }


def get_security_config() -> dict[str, Any]:
    admin_key = _configured_admin_key()
    client_key = _configured_client_key()

    return {
        "admin_auth_enabled": bool(admin_key),
        "admin_key_env_var": ADMIN_KEY_ENV,
        "admin_key_fingerprint": _key_fingerprint(admin_key),
        "protected_admin_tools": PROTECTED_ADMIN_TOOLS,
        "client_auth_enabled": bool(client_key),
        "client_key_env_var": CLIENT_KEY_ENV,
        "client_key_fingerprint": _key_fingerprint(client_key),
        "protected_client_tools": PROTECTED_CLIENT_TOOLS,
        "dev_mode": not bool(admin_key) and not bool(client_key),
    }
