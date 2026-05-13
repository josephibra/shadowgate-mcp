import hashlib
import json

from shadowgate.registry import save_registry
from shadowgate.server import review_mcp_manifest


def _manifest(tools: list[dict[str, str]]) -> str:
    return json.dumps({"tools": tools}, sort_keys=True)


def _identity(
    *,
    server_name: str,
    manifest: str,
    tool_names: list[str],
    highest_capability_risk_score: int = 0,
) -> dict[str, object]:
    return {
        "server_name": server_name,
        "manifest_sha256": hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
        "tool_count": len(tool_names),
        "tool_names": tool_names,
        "highest_capability_risk_score": highest_capability_risk_score,
        "capability_ids": [],
        "identity_version": "1",
    }


def _seed_registry(server_name: str, trust_identity: dict[str, object]) -> None:
    save_registry(
        {
            "default_trust": "untrusted",
            "servers": {
                server_name: {
                    "trust_level": "trusted",
                    "reason": "test baseline",
                    "trust_identity": trust_identity,
                    "updated_at": "2026-05-13T00:00:00+00:00",
                }
            },
        }
    )


def test_unknown_manifest_drift_recommends_review_before_trust(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])

    result = review_mcp_manifest(
        server_name="unknown-drift-server",
        manifest_json=manifest,
    )

    drift = result["manifest_drift"]
    assert drift["known_server"] is False
    assert drift["previous_manifest_sha256"] is None
    assert drift["current_manifest_sha256"] == result["manifest_sha256"]
    assert drift["manifest_changed"] is False
    assert drift["recommended_action"] == "review_before_trust"


def test_same_registry_identity_returns_no_manifest_drift(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    server_name = "same-drift-server"
    manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    _seed_registry(
        server_name,
        _identity(
            server_name=server_name,
            manifest=manifest,
            tool_names=["summarize"],
        ),
    )

    result = review_mcp_manifest(server_name=server_name, manifest_json=manifest)

    drift = result["manifest_drift"]
    assert drift["known_server"] is True
    assert drift["manifest_changed"] is False
    assert drift["capability_risk_changed"] is False
    assert drift["added_tools"] == []
    assert drift["removed_tools"] == []
    assert drift["recommended_action"] == "no_action"


def test_changed_tool_list_reports_added_and_removed_tools(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    server_name = "tool-list-drift-server"
    old_manifest = _manifest(
        [
            {"name": "summarize", "description": "Summarize text"},
            {"name": "old_lookup", "description": "Old lookup tool"},
        ]
    )
    new_manifest = _manifest(
        [
            {"name": "summarize", "description": "Summarize text"},
            {"name": "new_lookup", "description": "New lookup tool"},
        ]
    )
    _seed_registry(
        server_name,
        _identity(
            server_name=server_name,
            manifest=old_manifest,
            tool_names=["summarize", "old_lookup"],
        ),
    )

    result = review_mcp_manifest(server_name=server_name, manifest_json=new_manifest)

    drift = result["manifest_drift"]
    assert drift["known_server"] is True
    assert drift["manifest_changed"] is True
    assert drift["previous_tool_names"] == ["summarize", "old_lookup"]
    assert drift["current_tool_names"] == ["summarize", "new_lookup"]
    assert drift["added_tools"] == ["new_lookup"]
    assert drift["removed_tools"] == ["old_lookup"]
    assert drift["recommended_action"] == "human_review_required"


def test_increased_capability_risk_reports_risk_drift(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    server_name = "risk-drift-server"
    old_manifest = _manifest([{"name": "summarize", "description": "Summarize text"}])
    new_manifest = _manifest(
        [{"name": "run_command", "description": "Execute shell commands"}]
    )
    _seed_registry(
        server_name,
        _identity(
            server_name=server_name,
            manifest=old_manifest,
            tool_names=["summarize"],
        ),
    )

    result = review_mcp_manifest(server_name=server_name, manifest_json=new_manifest)

    drift = result["manifest_drift"]
    assert drift["known_server"] is True
    assert drift["manifest_changed"] is True
    assert drift["capability_risk_changed"] is True
    assert drift["previous_highest_capability_risk_score"] == 0
    assert drift["current_highest_capability_risk_score"] >= 90
    assert drift["recommended_action"] == "block_until_review"
