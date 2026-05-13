import json
import re
from pathlib import Path


CLIENT_PAYLOADS = Path("examples/client_payloads.json")
DISCOVERY_EXAMPLES = Path("discovery/client_connection_examples.json")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_client_payload_examples_parse_as_json():
    data = _load_json(CLIENT_PAYLOADS)

    assert isinstance(data.get("examples"), list)
    assert data["examples"]


def test_discovery_connection_examples_parse_as_json():
    data = _load_json(DISCOVERY_EXAMPLES)

    assert "shadowgate_mcp_connection_examples" in data


def test_client_payload_examples_include_expected_names_and_keys():
    data = _load_json(CLIENT_PAYLOADS)
    examples = {item["name"]: item for item in data["examples"]}

    expected_names = {
        "health_check",
        "analyze_text_safe_text",
        "gate_mcp_tool_call_safe_risky_run_command",
        "gate_mcp_tool_call_dangerous_env_read_attempt",
        "gate_mcp_response_malicious_prompt_injection",
        "evaluate_mcp_transaction",
        "review_mcp_manifest",
        "approve_mcp_manifest_identity",
        "create_security_report",
    }

    assert expected_names.issubset(examples)
    assert examples["gate_mcp_tool_call_safe_risky_run_command"]["payload"][
        "arguments_json"
    ] == '{"command":"echo hello"}'
    assert "client_key" in examples["gate_mcp_response_malicious_prompt_injection"][
        "payload"
    ]
    assert "admin_key" in examples["approve_mcp_manifest_identity"]["payload"]
    assert "admin_key" in examples["create_security_report"]["payload"]


def test_client_payload_examples_do_not_contain_real_secret_looking_values():
    text = CLIENT_PAYLOADS.read_text(encoding="utf-8")

    forbidden_patterns = [
        r"sk_live_[A-Za-z0-9]{20,}",
        r"\bAKIA[A-Z0-9]{16}\b",
        r"github_pat_[A-Za-z0-9_]{40,}",
        r"\bxoxb-[A-Za-z0-9-]{20,}\b",
    ]

    for pattern in forbidden_patterns:
        assert re.search(pattern, text) is None


def test_docs_mention_gateway_and_admin_tools():
    docs = "\n".join(
        [
            Path("README.md").read_text(encoding="utf-8"),
            Path("docs/CLIENT_CONFIGS.md").read_text(encoding="utf-8"),
            Path("docs/CONNECT.md").read_text(encoding="utf-8"),
            Path("docs/AGENT_USAGE.md").read_text(encoding="utf-8"),
        ]
    )

    for tool_name in [
        "gate_mcp_tool_call",
        "gate_mcp_response",
        "review_mcp_manifest",
        "approve_mcp_manifest_identity",
        "create_security_report",
    ]:
        assert tool_name in docs
