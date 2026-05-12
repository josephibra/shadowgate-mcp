from __future__ import annotations

import json
from pathlib import Path


REQUIRED_FILES = [
    Path("discovery/shadowgate_manifest.json"),
    Path("discovery/client_connection_examples.json"),
    Path("discovery/registry_listing.md"),
    Path("discovery/agent_routing_policy.json"),
    Path("docs/CONNECT.md"),
    Path("docs/CLIENT_CONFIGS.md"),
    Path("docs/AGENT_USAGE.md"),
    Path("docs/SECURITY_MODEL.md"),
    Path("docs/TOOL_SURFACE.md"),
]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"DISCOVERY VALIDATION FAILED: {message}")


def main() -> None:
    print("=== ShadowGate Discovery Validation ===")

    for path in REQUIRED_FILES:
        print("checking:", path)
        assert_true(path.exists(), f"missing file: {path}")
        assert_true(path.stat().st_size > 0, f"empty file: {path}")

    manifest = load_json(Path("discovery/shadowgate_manifest.json"))
    examples = load_json(Path("discovery/client_connection_examples.json"))
    routing = load_json(Path("discovery/agent_routing_policy.json"))

    assert_true(manifest.get("name") == "ShadowGate MCP", "bad manifest name")
    assert_true(manifest.get("transport", {}).get("type") == "streamable-http", "bad transport type")
    assert_true(manifest.get("transport", {}).get("path") == "/mcp", "bad MCP path")
    assert_true("gate_mcp_tool_call" in manifest.get("main_tools", []), "missing gate_mcp_tool_call")
    assert_true("gate_mcp_response" in manifest.get("main_tools", []), "missing gate_mcp_response")

    recommended = set(manifest.get("recommended_public_tools", []))
    assert_true("analyze_text" in recommended, "recommended tools missing analyze_text")
    assert_true("gate_mcp_tool_call" in recommended, "recommended tools missing gate_mcp_tool_call")
    assert_true("gate_mcp_response" in recommended, "recommended tools missing gate_mcp_response")
    assert_true("review_mcp_manifest" in recommended, "recommended tools missing review_mcp_manifest")

    compatibility = set(manifest.get("compatibility_tools", []))
    assert_true("scan_text" in compatibility, "compatibility tools missing scan_text")
    assert_true("redact_secrets" in compatibility, "compatibility tools missing redact_secrets")


    root = examples.get("shadowgate_mcp_connection_examples", {})
    assert_true(root.get("streamable_http", {}).get("transport") == "streamable-http", "bad example transport")
    assert_true(root.get("streamable_http", {}).get("url_local", "").endswith("/mcp"), "bad local URL")
    assert_true("example_tool_call_gate" in root, "missing tool call gate example")
    assert_true("example_response_gate" in root, "missing response gate example")

    assert_true(routing.get("name") == "ShadowGate Agent Routing Policy", "bad routing policy name")
    assert_true("routing_rules" in routing, "missing routing rules")
    assert_true(len(routing["routing_rules"]) >= 4, "not enough routing rules")
    assert_true("block" in routing.get("actions", {}), "missing block action")
    assert_true("allow_with_warning" in routing.get("actions", {}), "missing warning action")

    print("DISCOVERY VALIDATION PASSED")


if __name__ == "__main__":
    main()
