import json

from shadowgate.audit import write_audit_event
from shadowgate.registry import set_server_trust
from shadowgate.server import (
    approve_mcp_manifest_identity,
    create_security_report,
)


def _manifest(tools: list[dict[str, str]]) -> str:
    return json.dumps({"tools": tools}, sort_keys=True)


def _write_report_events() -> None:
    write_audit_event(
        {
            "action": "gate_mcp_response",
            "decision": "block",
            "risk_score": 95,
            "risk_level": "critical",
            "categories": ["injection", "secret"],
            "severities": ["critical"],
            "gateway": {"requires_human_approval": False},
            "raw_scanned_text": "DO_NOT_LEAK_RAW_AUDIT_TEXT",
        }
    )
    write_audit_event(
        {
            "action": "gate_mcp_tool_call",
            "decision": "allow",
            "risk_score": 45,
            "risk_level": "medium",
            "categories": ["tool_risk"],
            "severities": ["medium"],
            "gateway": {
                "requires_human_approval": True,
                "approval_reason": "Tool has risky capability.",
            },
        }
    )


def test_security_report_includes_structured_sections(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    _write_report_events()

    report = create_security_report(limit=20)

    assert report["version"]
    assert report["summary"]["total_events"] == 2
    assert report["recent_block_count"] == 1
    assert report["recent_warning_count"] == 1
    assert report["auth"]["ok"] is True

    sections = report["report_sections"]
    assert "risk_overview" in sections
    assert "server_trust_overview" in sections
    assert "manifest_identity_overview" in sections
    assert "capability_risk_overview" in sections
    assert "recommendations" in sections
    assert sections["risk_overview"]["highest_recent_risk_score"] == 95
    assert sections["risk_overview"]["highest_recent_risk_level"] == "critical"


def test_approved_manifest_identity_appears_in_report(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    manifest = _manifest(
        [{"name": "read_file", "description": "Read local files such as .env"}]
    )

    approve_mcp_manifest_identity(
        server_name="filesystem-server",
        manifest_json=manifest,
        reason="approved baseline",
    )

    report = create_security_report()
    identity_overview = report["report_sections"]["manifest_identity_overview"]

    assert identity_overview["servers_with_trust_identity"] == 1
    assert identity_overview["servers"][0]["server_name"] == "filesystem-server"
    assert identity_overview["servers"][0]["tool_count"] == 1
    assert identity_overview["servers"][0]["capability_ids"] == ["filesystem_read"]


def test_capability_ids_are_aggregated_in_report(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    approve_mcp_manifest_identity(
        server_name="filesystem-server",
        manifest_json=_manifest(
            [{"name": "read_file", "description": "Read local files such as .env"}]
        ),
    )
    approve_mcp_manifest_identity(
        server_name="shell-server",
        manifest_json=_manifest(
            [{"name": "run_command", "description": "Execute shell commands"}]
        ),
    )

    report = create_security_report()
    capability = report["report_sections"]["capability_risk_overview"]

    assert capability["capability_ids"]["filesystem_read"] == 1
    assert capability["capability_ids"]["shell_execution"] == 1
    assert capability["highest_capability_risk_score"] >= 95
    assert {
        item["server_name"]
        for item in capability["servers_with_high_capability_risk"]
    } == {"filesystem-server", "shell-server"}


def test_security_report_markdown_has_new_sections_and_no_raw_text(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    _write_report_events()

    report = create_security_report(limit=20)
    markdown = report["markdown"]
    rendered = json.dumps(report, sort_keys=True)

    assert "## Risk overview" in markdown
    assert "## Server trust overview" in markdown
    assert "## Manifest identity overview" in markdown
    assert "## Capability risk overview" in markdown
    assert "## Recent blocked events" in markdown
    assert "## Recent human-review warnings" in markdown
    assert "## Recommendations" in markdown
    assert "DO_NOT_LEAK_RAW_AUDIT_TEXT" not in markdown
    assert "DO_NOT_LEAK_RAW_AUDIT_TEXT" not in rendered


def test_security_report_includes_server_trust_recommendations(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    set_server_trust("blocked-server", "blocked", "blocked in test")
    set_server_trust("monitor-server", "monitor", "monitor in test")
    set_server_trust("trusted-server", "trusted", "trusted in test")

    report = create_security_report()
    sections = report["report_sections"]
    trust = sections["server_trust_overview"]

    assert trust["counts"]["blocked"] == 1
    assert trust["counts"]["monitor"] == 1
    assert trust["counts"]["trusted"] == 1
    assert trust["blocked_servers"] == ["blocked-server"]
    assert trust["monitored_servers"] == ["monitor-server"]
    assert trust["trusted_servers"] == ["trusted-server"]
    assert "Review blocked server list." in sections["recommendations"]
    assert (
        "Approve baseline identities for trusted MCP servers."
        in sections["recommendations"]
    )


def test_security_report_admin_auth_failure_is_preserved(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHADOWGATE_ADMIN_KEY", "admin-secret")

    report = create_security_report(admin_key="")

    assert report["auth"]["ok"] is False
    assert report["markdown"] == ""
    assert "report_sections" not in report
