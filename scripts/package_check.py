from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


PACKAGE_VERSION = "0.4.0"
RELEASE_VERSION = "0.4.0-hardened"

REQUIRED_DOCS = [
    Path("README.md"),
    Path("RELEASE_NOTES.md"),
    Path("DEPLOY_RAILWAY.md"),
    Path("RELEASE_CHECKLIST.md"),
    Path("docs/CONNECT.md"),
    Path("docs/CLIENT_CONFIGS.md"),
    Path("docs/AGENT_USAGE.md"),
    Path("docs/SECURITY_MODEL.md"),
    Path("docs/TOOL_SURFACE.md"),
]

RECOMMENDED_TOOLS = [
    "health_check",
    "analyze_text",
    "gate_mcp_tool_call",
    "gate_mcp_response",
    "evaluate_mcp_transaction",
    "review_mcp_manifest",
    "approve_mcp_manifest_identity",
    "create_security_report",
]

SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{20,}\b"),
]


def fail(message: str) -> None:
    raise SystemExit(f"PACKAGE CHECK FAILED: {message}")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> dict:
    try:
        return json.loads(read(path))
    except Exception as exc:
        fail(f"invalid JSON in {path}: {exc}")


def main() -> None:
    print("=== ShadowGate Package Check ===")

    pyproject = tomllib.loads(read(Path("pyproject.toml")))
    if pyproject.get("project", {}).get("version") != PACKAGE_VERSION:
        fail("pyproject version mismatch")

    server = read(Path("shadowgate/server.py"))
    if f'VERSION = "{RELEASE_VERSION}"' not in server:
        fail("server VERSION mismatch")

    for path in REQUIRED_DOCS:
        print("checking:", path)
        if not path.exists() or path.stat().st_size <= 0:
            fail(f"missing or empty doc: {path}")

    readme = read(Path("README.md"))
    release_notes = read(Path("RELEASE_NOTES.md"))
    if RELEASE_VERSION not in readme:
        fail("README missing release version")
    if RELEASE_VERSION not in release_notes:
        fail("release notes missing release version")

    manifest = load_json(Path("discovery/shadowgate_manifest.json"))
    if manifest.get("version") != RELEASE_VERSION:
        fail("discovery manifest version mismatch")

    payloads_text = read(Path("examples/client_payloads.json"))
    load_json(Path("examples/client_payloads.json"))
    load_json(Path("discovery/client_connection_examples.json"))

    for pattern in SECRET_PATTERNS:
        if pattern.search(payloads_text):
            fail("client payload examples contain secret-looking value")

    recommended = set(manifest.get("recommended_public_tools", []))
    missing = sorted(set(RECOMMENDED_TOOLS) - recommended)
    if missing:
        fail(f"recommended public tools missing: {missing}")

    print("PACKAGE CHECK PASSED")


if __name__ == "__main__":
    main()
