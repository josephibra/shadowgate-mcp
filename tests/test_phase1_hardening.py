from shadowgate.policy import _apply_policy_object
from shadowgate.scanner import scan
from shadowgate.server import _add_manual_finding


def test_strict_policy_blocks_secret_category_with_legacy_secrets_alias():
    result = scan("MY_API_KEY=abcdefghijk123456789")

    policy = {
        "mode": "strict",
        "block_score_at": 80,
        "redact_score_at": 30,
        "always_block_categories": ["file_access", "injection", "secrets"],
        "always_redact": True,
        "audit_enabled": False,
    }

    evaluated = _apply_policy_object(result, policy)

    assert "secret" in evaluated["categories"]
    assert evaluated["decision"] == "block"
    assert "secret" in evaluated["policy"]["matched_block_categories"]


def test_manual_findings_accumulate_with_discount_after_first_signal():
    result = {
        "decision": "allow",
        "risk_score": 40,
        "finding_count": 0,
        "categories": [],
        "severities": [],
        "findings": [],
    }

    result = _add_manual_finding(
        result,
        rule_id="risky_tool_name",
        label="Risky tool name",
        severity="medium",
        category="tool_risk",
        weight=45,
        preview="run_command",
    )

    assert result["risk_score"] > 45
    assert result["risk_score"] < 85
    assert result["finding_count"] == 1
    assert "tool_risk" in result["categories"]
