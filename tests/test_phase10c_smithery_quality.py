from pathlib import Path

from shadowgate.server import gate_mcp_tool_call


def test_server_has_smithery_parameter_metadata_aliases():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    assert "ClientKeyParam = Annotated" in source
    assert "AdminKeyParam = Annotated" in source
    assert "ServerNameParam = Annotated" in source
    assert "ToolNameParam = Annotated" in source
    assert "ArgumentsJsonParam = Annotated" in source
    assert "ResponseTextParam = Annotated" in source
    assert "ManifestJsonParam = Annotated" in source


def test_protected_tool_parameters_use_descriptive_aliases():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    assert "client_key: ClientKeyParam" in source
    assert "admin_key: AdminKeyParam" in source
    assert "server_name: ServerNameParam" in source
    assert "tool_name: ToolNameParam" in source
    assert "arguments_json: ArgumentsJsonParam" in source


def test_safe_risky_tool_call_still_allow_with_warning():
    result = gate_mcp_tool_call(
        server_name="example-shell-agent",
        tool_name="run_command",
        arguments_json='{"command":"echo hello"}',
        client_key="",
    )

    assert result["allow_execution"] is True
    assert result["gateway_action"] == "allow_with_warning"


def test_smithery_link_still_present_in_readme():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "https://smithery.ai/servers/josephibrahim/shadowgate-mcp" in readme


def test_smithery_yaml_has_no_real_secret_values():
    text = Path("smithery.yaml").read_text(encoding="utf-8").lower()

    forbidden = [
        "sk-live",
        "akia",
        "github_pat_",
        "xoxb-",
        "shadowgate_admin_key=",
        "shadowgate_client_key=",
    ]

    for marker in forbidden:
        assert marker not in text


def test_remaining_smithery_parameter_aliases_are_present():
    source = Path("shadowgate/server.py").read_text(encoding="utf-8")

    assert "StrictParam = Annotated" in source
    assert "BatchItemsParam = Annotated" in source
    assert "strict: StrictParam" in source
    assert "items: BatchItemsParam" in source
    assert "trust_level: TrustLevelParam" in source
