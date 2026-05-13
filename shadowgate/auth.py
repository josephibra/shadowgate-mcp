from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any


ADMIN_KEY_ENV = "SHADOWGATE_ADMIN_KEY"
CLIENT_KEY_ENV = "SHADOWGATE_CLIENT_KEY"
AUDIT_MAX_EVENTS_ENV = "SHADOWGATE_AUDIT_MAX_EVENTS"
AUDIT_RETENTION_DAYS_ENV = "SHADOWGATE_AUDIT_RETENTION_DAYS"
RATE_LIMIT_PER_MINUTE_ENV = "SHADOWGATE_RATE_LIMIT_PER_MINUTE"
RATE_LIMIT_BURST_ENV = "SHADOWGATE_RATE_LIMIT_BURST"

WEAK_KEY_VALUES = {
    "change-me-admin-key",
    "change-me-client-key",
    "your-secret-admin-key",
    "your-client-key",
    "admin",
    "password",
    "secret",
    "test",
}

HOSTING_ENV_VARS = [
    "RAILWAY_ENVIRONMENT",
    "RAILWAY_PROJECT_ID",
    "FLY_APP_NAME",
    "RENDER",
    "RENDER_SERVICE_ID",
]


PROTECTED_ADMIN_TOOLS = [
    "set_policy_mode",
    "set_mcp_server_trust",
    "approve_mcp_manifest_identity",
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


def _is_weak_key(key: str) -> bool:
    return key.lower().strip() in WEAK_KEY_VALUES


def _server_host() -> str:
    return os.environ.get("SHADOWGATE_HOST", os.environ.get("HOST", "127.0.0.1")).strip()


def _is_hosted_mode() -> bool:
    host = _server_host()
    return (
        host == "0.0.0.0"
        or bool(os.environ.get("PORT", "").strip())
        or any(os.environ.get(name, "").strip() for name in HOSTING_ENV_VARS)
    )


def _positive_int_config(env_var: str) -> dict[str, Any]:
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return {
            "env_var": env_var,
            "configured": False,
            "value": None,
            "valid": True,
        }

    try:
        value = int(raw)
    except ValueError:
        return {
            "env_var": env_var,
            "configured": True,
            "value": None,
            "valid": False,
        }

    return {
        "env_var": env_var,
        "configured": True,
        "value": value if value > 0 else None,
        "valid": value > 0,
    }


def _data_dir_config() -> dict[str, Any]:
    raw = os.environ.get("SHADOWGATE_DATA_DIR", "").strip()
    return {
        "env_var": "SHADOWGATE_DATA_DIR",
        "configured": bool(raw),
        "value": raw or ".",
        "uses_default_local_dir": not raw or raw == ".",
    }


def get_hosting_security_warnings() -> list[dict[str, str]]:
    admin_key = _configured_admin_key()
    client_key = _configured_client_key()
    hosted = _is_hosted_mode()
    data_dir = _data_dir_config()
    audit_max_events = _positive_int_config(AUDIT_MAX_EVENTS_ENV)
    audit_retention_days = _positive_int_config(AUDIT_RETENTION_DAYS_ENV)
    rate_limit_per_minute = _positive_int_config(RATE_LIMIT_PER_MINUTE_ENV)
    rate_limit_burst = _positive_int_config(RATE_LIMIT_BURST_ENV)

    warnings: list[dict[str, str]] = []

    def add(code: str, message: str, severity: str = "warning") -> None:
        warnings.append({"code": code, "severity": severity, "message": message})

    if hosted and not admin_key:
        add(
            "hosted_admin_key_missing",
            "Hosted mode should set SHADOWGATE_ADMIN_KEY.",
            "critical",
        )

    if hosted and not client_key:
        add(
            "hosted_client_key_missing",
            "Hosted mode should set SHADOWGATE_CLIENT_KEY.",
            "critical",
        )

    if admin_key and _is_weak_key(admin_key):
        add("weak_admin_key", "SHADOWGATE_ADMIN_KEY appears to use a placeholder.")

    if client_key and _is_weak_key(client_key):
        add("weak_client_key", "SHADOWGATE_CLIENT_KEY appears to use a placeholder.")

    if hosted and data_dir["uses_default_local_dir"]:
        add(
            "hosted_data_dir_not_persistent",
            "Hosted mode should set SHADOWGATE_DATA_DIR to a persistent path such as /data.",
        )

    if hosted and not audit_max_events["configured"]:
        add("audit_max_events_unset", "Hosted mode should set SHADOWGATE_AUDIT_MAX_EVENTS.")

    if hosted and not audit_retention_days["configured"]:
        add(
            "audit_retention_days_unset",
            "Hosted mode should set SHADOWGATE_AUDIT_RETENTION_DAYS.",
        )

    if hosted and not rate_limit_per_minute["configured"]:
        add(
            "rate_limit_per_minute_unset",
            "Hosted mode should set SHADOWGATE_RATE_LIMIT_PER_MINUTE.",
        )

    if hosted and not rate_limit_burst["configured"]:
        add("rate_limit_burst_unset", "Hosted mode should set SHADOWGATE_RATE_LIMIT_BURST.")

    for item in [
        audit_max_events,
        audit_retention_days,
        rate_limit_per_minute,
        rate_limit_burst,
    ]:
        if item["configured"] and not item["valid"]:
            add(
                f"{item['env_var'].lower()}_invalid",
                f"{item['env_var']} must be a positive integer.",
            )

    return warnings


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
    audit_config = {
        "max_events": _positive_int_config(AUDIT_MAX_EVENTS_ENV),
        "retention_days": _positive_int_config(AUDIT_RETENTION_DAYS_ENV),
    }
    rate_limit_config = {
        "per_minute": _positive_int_config(RATE_LIMIT_PER_MINUTE_ENV),
        "burst": _positive_int_config(RATE_LIMIT_BURST_ENV),
    }
    hosted_mode = _is_hosted_mode()
    warnings = get_hosting_security_warnings()

    return {
        "admin_auth_enabled": bool(admin_key),
        "admin_key_env_var": ADMIN_KEY_ENV,
        "admin_key_fingerprint": _key_fingerprint(admin_key),
        "admin_key_weak": bool(admin_key) and _is_weak_key(admin_key),
        "protected_admin_tools": PROTECTED_ADMIN_TOOLS,
        "client_auth_enabled": bool(client_key),
        "client_key_env_var": CLIENT_KEY_ENV,
        "client_key_fingerprint": _key_fingerprint(client_key),
        "client_key_weak": bool(client_key) and _is_weak_key(client_key),
        "protected_client_tools": PROTECTED_CLIENT_TOOLS,
        "dev_mode": not bool(admin_key) and not bool(client_key),
        "hosted_mode": hosted_mode,
        "server_host": _server_host(),
        "data_dir": _data_dir_config(),
        "audit_retention": audit_config,
        "rate_limit": rate_limit_config,
        "production_warnings": warnings,
        "production_warning_count": len(warnings),
    }
