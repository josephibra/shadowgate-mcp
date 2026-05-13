from pathlib import Path

from shadowgate.server import gate_mcp_tool_call


EXPECTED_ANNOTATIONS = [
    "ANN_HEALTH",
    "ANN_SCAN",
    "ANN_REDACT",
    "ANN_RISK",
    "ANN_POLICY",
    "ANN_RESPONSE",
    "ANN_TOOL_CALL",
    "ANN_GATE_CALL",
    "ANN_GATE_RESPONSE",
    "ANN_TRANSACTION",
    "ANN_SCHEMA",
    "ANN_MANIFEST",
    "ANN_BATCH",
    "ANN_SIMULATE",
    "ANN_CONFIG_READ",
    "ANN_AUDIT_READ",
    "ANN_REPORT",
    "ANN_REGISTRY_READ",
    "ANN_ADMIN_WRITE",
    "ANN_APPROVAL",
]


CRITICAL_TOOLS = [
    "health_check",
    "scan_text",
    "analyze_text",
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
    "get_policy",
    "set_policy_mode",
    "get_recent_audit_events",
    "get_audit_summary",
    "create_security_report",
    "get_server_registry",
    "get_mcp_server_trust",
    "set_mcp_server_trust",
    "approve_mcp_manifest_identity",
    "get_data_paths",
    "get_security_config",
]


def test_tool_annotations_are_defined_for_smithery():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    assert "from mcp.types import ToolAnnotations" in source
    assert "readOnlyHint" in source
    assert "destructiveHint" in source
    assert "idempotentHint" in source
    assert "openWorldHint" in source

    for name in EXPECTED_ANNOTATIONS:
        assert name in source


def test_critical_tool_names_remain_unchanged():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    for tool_name in CRITICAL_TOOLS:
        assert f"def {tool_name}(" in source or f"async def {tool_name}(" in source


def test_tool_decorators_include_annotations():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    # Enough checks to ensure public/admin/gateway tools are covered.
    assert "@mcp.tool(annotations=ANN_HEALTH)" in source
    assert "annotations=ANN_GATE_CALL" in source
    assert "annotations=ANN_GATE_RESPONSE" in source
    assert "annotations=ANN_MANIFEST" in source
    assert "annotations=ANN_ADMIN_WRITE" in source
    assert "annotations=ANN_APPROVAL" in source


def test_safe_risky_tool_call_still_allow_with_warning_after_annotations():
    result = gate_mcp_tool_call(
        server_name="example-shell-agent",
        tool_name="run_command",
        arguments_json='{"command":"echo hello"}',
        client_key="",
    )

    assert result["allow_execution"] is True
    assert result["gateway_action"] == "allow_with_warning"
