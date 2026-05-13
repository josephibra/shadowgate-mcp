from __future__ import annotations

import json
import os
from pathlib import Path

from shadowgate.server import health_check
from shadowgate.auth import get_security_config
from shadowgate.storage import get_data_paths


REQUIRED_FILES = [
    "Dockerfile",
    "Procfile",
    ".env.example",
    "README.md",
    "pyproject.toml",
    "requirements.txt",
    "shadowgate/server.py",
    "shadowgate/auth.py",
    "shadowgate/storage.py",
    "shadowgate/policy.py",
    "shadowgate/registry.py",
    "shadowgate/scanner.py",
    "discovery/shadowgate_manifest.json",
    "discovery/client_connection_examples.json",
    "discovery/agent_routing_policy.json",
    "discovery/registry_listing.md",
    "docs/CONNECT.md",
    "docs/CLIENT_CONFIGS.md",
    "docs/AGENT_USAGE.md",
    "docs/SECURITY_MODEL.md",
]


def fail(message: str) -> None:
    raise SystemExit(f"PRODUCTION CHECK FAILED: {message}")


def check_file(path: str) -> None:
    p = Path(path)
    if not p.exists():
        fail(f"missing file: {path}")
    if p.stat().st_size <= 0:
        fail(f"empty file: {path}")


def load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON in {path}: {exc}")


def main() -> None:
    print("=== ShadowGate Production Readiness Check ===")

    for path in REQUIRED_FILES:
        print("checking file:", path)
        check_file(path)

    health = health_check()
    print("version:", health.get("version"))

    if not health.get("ok"):
        fail("health_check ok is not true")

    tools = set(health.get("tools", []))
    required_tools = {
        "scan_text",
        "gate_mcp_tool_call",
        "gate_mcp_response",
        "evaluate_mcp_transaction",
        "review_mcp_manifest",
        "get_security_config",
        "get_data_paths",
    }

    missing_tools = sorted(required_tools - tools)
    if missing_tools:
        fail(f"missing tools: {missing_tools}")

    security = get_security_config()
    print("admin_auth_enabled:", security.get("admin_auth_enabled"))
    print("client_auth_enabled:", security.get("client_auth_enabled"))
    if "production_warnings" not in security:
        fail("security config missing production_warnings")
    if "audit_retention" not in security:
        fail("security config missing audit_retention")
    if "rate_limit" not in security:
        fail("security config missing rate_limit")

    paths = get_data_paths()
    print("data_dir:", paths.get("data_dir"))
    print("audit_file:", paths.get("audit_file"))

    manifest = load_json("discovery/shadowgate_manifest.json")
    if manifest.get("transport", {}).get("type") != "streamable-http":
        fail("manifest transport is not streamable-http")
    if manifest.get("transport", {}).get("path") != "/mcp":
        fail("manifest MCP path is not /mcp")

    routing = load_json("discovery/agent_routing_policy.json")
    if "routing_rules" not in routing:
        fail("routing policy missing routing_rules")

    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    if "SHADOWGATE_HOST=0.0.0.0" not in dockerfile:
        fail("Dockerfile missing SHADOWGATE_HOST=0.0.0.0")
    if "python\", \"-m\", \"shadowgate.server" not in dockerfile:
        fail("Dockerfile missing python -m shadowgate.server CMD")

    procfile = Path("Procfile").read_text(encoding="utf-8")
    if "python -m shadowgate.server" not in procfile:
        fail("Procfile missing server command")

    env_example = Path(".env.example").read_text(encoding="utf-8")
    for key in [
        "SHADOWGATE_HOST",
        "PORT",
        "SHADOWGATE_DATA_DIR",
        "SHADOWGATE_ADMIN_KEY",
        "SHADOWGATE_CLIENT_KEY",
        "SHADOWGATE_AUDIT_MAX_EVENTS",
        "SHADOWGATE_AUDIT_RETENTION_DAYS",
        "SHADOWGATE_RATE_LIMIT_PER_MINUTE",
        "SHADOWGATE_RATE_LIMIT_BURST",
    ]:
        if key not in env_example:
            fail(f".env.example missing {key}")

    original_env = {
        key: os.environ.get(key)
        for key in [
            "SHADOWGATE_HOST",
            "PORT",
            "SHADOWGATE_ADMIN_KEY",
            "SHADOWGATE_CLIENT_KEY",
            "SHADOWGATE_DATA_DIR",
        ]
    }
    try:
        os.environ["SHADOWGATE_HOST"] = "0.0.0.0"
        os.environ["PORT"] = "8000"
        os.environ.pop("SHADOWGATE_ADMIN_KEY", None)
        os.environ.pop("SHADOWGATE_CLIENT_KEY", None)
        os.environ.pop("SHADOWGATE_DATA_DIR", None)
        hosted_security = get_security_config()
        warning_codes = {
            item.get("code")
            for item in hosted_security.get("production_warnings", [])
        }
        if "hosted_admin_key_missing" not in warning_codes:
            fail("hosted-mode warning missing admin key recommendation")
        if "hosted_client_key_missing" not in warning_codes:
            fail("hosted-mode warning missing client key recommendation")

        os.environ["SHADOWGATE_ADMIN_KEY"] = "production-check-admin-key"
        os.environ["SHADOWGATE_CLIENT_KEY"] = "production-check-client-key"
        rendered = json.dumps(get_security_config(), sort_keys=True)
        if "production-check-admin-key" in rendered:
            fail("security config exposes raw admin key")
        if "production-check-client-key" in rendered:
            fail("security config exposes raw client key")
    finally:
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    print("PRODUCTION CHECK PASSED")


if __name__ == "__main__":
    main()
