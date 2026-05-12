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
    ]:
        if key not in env_example:
            fail(f".env.example missing {key}")

    print("PRODUCTION CHECK PASSED")


if __name__ == "__main__":
    main()
