import json

from shadowgate.capabilities import assess_mcp_tool_capabilities
from shadowgate.server import (
    _scan_tool_call,
    gate_mcp_tool_call,
    inspect_tool_schema,
    review_mcp_manifest,
)


def test_capability_classifier_detects_shell_execution():
    result = assess_mcp_tool_capabilities(
        tool_name="run_command",
        payload='{"description":"Execute bash commands on the host"}',
    )

    assert result["risk_score"] >= 90
    assert result["risk_level"] == "critical"
    assert result["requires_human_approval"] is True
    assert any(item["id"] == "shell_execution" for item in result["capabilities"])


def test_tool_call_scan_attaches_capability_assessment_without_auto_blocking():
    result = _scan_tool_call(
        server_name="unknown",
        tool_name="run_command",
        arguments_json='{"command":"echo hello"}',
    )

    assert result["risk_score"] < 80
    assert "tool_risk" in result["categories"]
    assert result["capability_assessment"]["capability_count"] >= 1
    assert any(
        item["id"] == "shell_execution"
        for item in result["capability_assessment"]["capabilities"]
    )
    assert not any(f["rule_id"] == "capability_shell_execution" for f in result["findings"])


def test_safe_risky_tool_call_is_warning_not_block():
    result = gate_mcp_tool_call(
        server_name="unknown",
        tool_name="run_command",
        arguments_json='{"command":"echo hello"}',
    )

    assert result["allow_execution"] is True
    assert result["gateway_action"] == "allow_with_warning"
    assert result["requires_human_approval"] is True
    assert result["scan"]["capability_assessment"]["capability_count"] >= 1


def test_schema_inspection_detects_sensitive_file_capability():
    schema = json.dumps(
        {
            "name": "read_file",
            "description": "Read local files such as .env or SSH keys",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
            },
        }
    )

    result = inspect_tool_schema(
        server_name="local-filesystem",
        tool_name="read_file",
        schema_json=schema,
    )

    assert result["risk_score"] >= 75
    assert "tool_capability" in result["categories"]
    assert result["capability_assessment"]["capability_count"] >= 1


def test_manifest_review_surfaces_capability_assessment():
    manifest = json.dumps(
        {
            "name": "dangerous-server",
            "tools": [
                {
                    "name": "run_command",
                    "description": "Execute shell commands",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"}
                        },
                    },
                }
            ],
        }
    )

    result = review_mcp_manifest(
        server_name="dangerous-server",
        manifest_json=manifest,
    )

    assert result["overall_decision"] in {"block", "allow_with_warning"}
    assert result["highest_risk_score"] >= 90
    assert result["tools"][0]["capability_assessment"]["capability_count"] >= 1
