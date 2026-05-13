import hashlib
import json

from shadowgate.server import review_mcp_manifest


def test_manifest_review_returns_fingerprint_summary_and_trust_identity():
    manifest = json.dumps(
        {
            "name": "phase4a-server",
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read local files such as .env",
                },
                {
                    "name": "send_email",
                    "description": "Send an email message through SMTP",
                },
            ],
        },
        sort_keys=True,
    )

    result = review_mcp_manifest(
        server_name="phase4a-server",
        manifest_json=manifest,
    )

    expected_hash = hashlib.sha256(manifest.encode("utf-8")).hexdigest()

    assert result["manifest_sha256"] == expected_hash
    assert result["tool_count"] == 2
    assert result["tool_names"] == ["read_file", "send_email"]
    assert result["capability_summary"]["highest_capability_risk_score"] >= 75
    assert result["capability_summary"]["capability_ids"] == [
        "email_messaging",
        "filesystem_read",
    ]

    assert result["trust_identity"] == {
        "server_name": "phase4a-server",
        "manifest_sha256": expected_hash,
        "tool_count": 2,
        "tool_names": ["read_file", "send_email"],
        "highest_capability_risk_score": result["capability_summary"][
            "highest_capability_risk_score"
        ],
        "capability_ids": ["email_messaging", "filesystem_read"],
        "identity_version": "1",
    }


def test_invalid_manifest_review_still_returns_empty_trust_identity():
    manifest = '{"tools": ['

    result = review_mcp_manifest(
        server_name="broken-server",
        manifest_json=manifest,
    )

    expected_hash = hashlib.sha256(manifest.encode("utf-8")).hexdigest()

    assert result["valid_json"] is False
    assert result["manifest_sha256"] == expected_hash
    assert result["tool_count"] == 0
    assert result["tool_names"] == []
    assert result["capability_summary"]["highest_capability_risk_score"] == 0
    assert result["capability_summary"]["capability_ids"] == []
    assert result["trust_identity"] == {
        "server_name": "broken-server",
        "manifest_sha256": expected_hash,
        "tool_count": 0,
        "tool_names": [],
        "highest_capability_risk_score": 0,
        "capability_ids": [],
        "identity_version": "1",
    }
