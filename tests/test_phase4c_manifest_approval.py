import json

from shadowgate.registry import get_server_trust, load_registry
from shadowgate.server import (
    approve_mcp_manifest_identity,
    review_mcp_manifest,
    set_mcp_server_trust,
)


def _manifest(tools: list[dict[str, str]]) -> str:
    return json.dumps({"tools": tools}, sort_keys=True)


def test_approve_manifest_identity_persists_baseline_without_admin_auth(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])

    result = approve_mcp_manifest_identity(
        server_name="approved-server",
        manifest_json=manifest,
        reason="approved test server",
    )

    assert result["updated"] is True
    assert result["trust_level"] == "trusted"
    assert result["trust_identity"]["tool_names"] == ["summarize"]

    entry = load_registry()["servers"]["approved-server"]
    assert entry["trust_level"] == "trusted"
    assert entry["reason"] == "approved test server"
    assert entry["trust_identity"] == result["trust_identity"]
    assert entry["manifest_sha256"] == result["trust_identity"]["manifest_sha256"]
    assert entry["tool_names"] == ["summarize"]
    assert entry["tool_count"] == 1


def test_review_after_approval_has_baseline_and_no_drift(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    approve_mcp_manifest_identity(
        server_name="stable-server",
        manifest_json=manifest,
    )

    result = review_mcp_manifest(
        server_name="stable-server",
        manifest_json=manifest,
    )

    drift = result["manifest_drift"]
    assert drift["known_server"] is True
    assert drift["baseline_available"] is True
    assert drift["manifest_changed"] is False
    assert drift["recommended_action"] == "no_action"


def test_changed_manifest_after_approval_reports_drift(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    old_manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    new_manifest = _manifest(
        [
            {"name": "summarize", "description": "Summarize text"},
            {"name": "lookup", "description": "Lookup public data"},
        ]
    )
    approve_mcp_manifest_identity(
        server_name="changed-server",
        manifest_json=old_manifest,
    )

    result = review_mcp_manifest(
        server_name="changed-server",
        manifest_json=new_manifest,
    )

    drift = result["manifest_drift"]
    assert drift["baseline_available"] is True
    assert drift["manifest_changed"] is True
    assert drift["added_tools"] == ["lookup"]
    assert drift["removed_tools"] == []
    assert drift["recommended_action"] == "human_review_required"


def test_increased_capability_risk_after_approval_reports_risk_drift(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    old_manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    new_manifest = _manifest(
        [{"name": "run_command", "description": "Execute shell commands"}]
    )
    approve_mcp_manifest_identity(
        server_name="risk-approved-server",
        manifest_json=old_manifest,
    )

    result = review_mcp_manifest(
        server_name="risk-approved-server",
        manifest_json=new_manifest,
    )

    drift = result["manifest_drift"]
    assert drift["baseline_available"] is True
    assert drift["manifest_changed"] is True
    assert drift["capability_risk_changed"] is True
    assert drift["recommended_action"] == "block_until_review"


def test_review_redacts_previous_identity_details_without_admin_key(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHADOWGATE_ADMIN_KEY", "admin-secret")
    old_manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    new_manifest = _manifest(
        [
            {"name": "summarize", "description": "Summarize text"},
            {"name": "lookup", "description": "Lookup public data"},
        ]
    )
    approve_mcp_manifest_identity(
        server_name="redacted-server",
        manifest_json=old_manifest,
        admin_key="admin-secret",
    )

    result = review_mcp_manifest(
        server_name="redacted-server",
        manifest_json=new_manifest,
    )

    drift = result["manifest_drift"]
    assert drift["known_server"] is True
    assert drift["baseline_available"] is True
    assert drift["manifest_changed"] is True
    assert drift["previous_details_redacted"] is True
    assert drift["previous_manifest_sha256"] is None
    assert drift["previous_tool_names"] is None
    assert drift["previous_highest_capability_risk_score"] is None
    assert drift["added_tools"] is None
    assert drift["removed_tools"] is None
    assert drift["redaction_reason"] == "admin_key_required_for_previous_identity_details"


def test_invalid_approval_trust_level_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])

    result = approve_mcp_manifest_identity(
        server_name="invalid-trust-server",
        manifest_json=manifest,
        trust_level="owner",
    )

    assert result["updated"] is False
    assert "Invalid trust level" in result["error"]
    assert "invalid-trust-server" not in load_registry()["servers"]


def test_invalid_manifest_approval_does_not_persist(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))

    result = approve_mcp_manifest_identity(
        server_name="invalid-manifest-server",
        manifest_json='{"tools": [',
    )

    assert result["updated"] is False
    assert result["error"] == "Invalid manifest JSON."
    assert "invalid-manifest-server" not in load_registry()["servers"]


def test_existing_set_mcp_server_trust_behavior_still_works(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))

    result = set_mcp_server_trust(
        server_name="legacy-trust-server",
        trust_level="monitor",
        reason="legacy flow",
    )

    assert result["updated"] is True
    trust = get_server_trust("legacy-trust-server")
    assert trust["trust_level"] == "monitor"
    assert trust["source"] == "registry"
    assert trust["reason"] == "legacy flow"

    review = review_mcp_manifest(
        server_name="legacy-trust-server",
        manifest_json=_manifest([{"name": "summarize", "description": "Summarize text"}]),
    )
    assert review["manifest_drift"]["known_server"] is True
    assert review["manifest_drift"]["baseline_available"] is False
    assert (
        review["manifest_drift"]["recommended_action"]
        == "approve_manifest_identity_before_drift_detection"
    )
