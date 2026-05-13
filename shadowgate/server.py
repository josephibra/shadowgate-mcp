from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import Field

from mcp.server.fastmcp import FastMCP

from .audit import read_audit_events, summarize_audit_log, write_audit_event
from .capabilities import assess_mcp_tool_capabilities
from .auth import get_security_config as _get_security_config, require_admin_key, require_client_key
from .policy import apply_policy, load_policy, simulate_policy_modes as simulate_modes, update_policy_mode
from .registry import ALLOWED_TRUST_LEVELS, get_registry, get_server_trust, load_registry, save_registry, set_server_trust
from .scanner import policy_decision, redact, risk_score, scan, scan_mcp_response
from .storage import get_data_paths as _get_data_paths

VERSION = "0.4.0-hardened"
TRUST_IDENTITY_VERSION = "1"

SERVER_HOST = os.environ.get("SHADOWGATE_HOST", os.environ.get("HOST", "127.0.0.1"))
SERVER_PORT = int(os.environ.get("SHADOWGATE_PORT", os.environ.get("PORT", "8000")))


# ---------------------------------------------------------------------------
# MCP parameter metadata
# ---------------------------------------------------------------------------
# These aliases preserve the public Python/API behavior while giving MCP
# clients and Smithery better input schema descriptions.

TextParam = Annotated[str, Field(description="Text payload to scan for leaked secrets, prompt injection, risky commands, or sensitive file paths.")]
TextsJsonParam = Annotated[str, Field(description="JSON array of text payloads to scan in a batch.")]
SourceParam = Annotated[str, Field(description="Optional source label used in audit metadata, for example manual, mcp_response, or gateway.")]
ClientKeyParam = Annotated[str, Field(description="Client key required for protected scan/gateway tools when SHADOWGATE_CLIENT_KEY is configured.")]
AdminKeyParam = Annotated[str, Field(description="Admin key required for protected administrative tools when SHADOWGATE_ADMIN_KEY is configured.")]
ServerNameParam = Annotated[str, Field(description="Name of the external MCP server or agent being inspected, gated, trusted, or reviewed.")]
ToolNameParam = Annotated[str, Field(description="Name of the MCP tool being inspected, gated, or reviewed.")]
ArgumentsJsonParam = Annotated[str, Field(description="JSON string containing the outgoing MCP tool arguments to inspect before execution.")]
ResponseTextParam = Annotated[str, Field(description="Text returned by an external MCP server/tool before the agent trusts or consumes it.")]
SchemaJsonParam = Annotated[str, Field(description="JSON string containing an MCP tool schema or input schema to inspect for risky capabilities.")]
ManifestJsonParam = Annotated[str, Field(description="JSON string containing an MCP server manifest to review before onboarding or trusting the server.")]
TrustLevelParam = Annotated[str, Field(description="Trust level for an MCP server. Expected values are trusted, monitor, untrusted, or blocked.")]
ReasonParam = Annotated[str, Field(description="Human-readable reason for a trust, policy, approval, or registry change.")]
PolicyModeParam = Annotated[str, Field(description="Policy mode to apply. Expected values are monitor, balanced, or strict.")]
LimitParam = Annotated[int, Field(description="Maximum number of audit, registry, or result records to return.")]

mcp = FastMCP("ShadowGate MCP", json_response=True, host=SERVER_HOST, port=SERVER_PORT)


def _safe_json_loads(value: str) -> tuple[bool, Any]:
    try:
        return True, json.loads(value)
    except Exception as exc:
        return False, {"parse_error": str(exc), "raw": value}


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _manifest_sha256(manifest_json: ManifestJsonParam) -> str:
    return hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()


def _capability_summary(
    reviewed_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    capability_ids: set[str] = set()
    highest_capability_risk_score = 0
    requires_human_approval = False

    for tool in reviewed_tools:
        assessment = tool.get("capability_assessment", {})
        highest_capability_risk_score = max(
            highest_capability_risk_score,
            int(assessment.get("risk_score", 0)),
        )
        requires_human_approval = requires_human_approval or bool(
            assessment.get("requires_human_approval")
        )
        for capability in assessment.get("capabilities", []):
            capability_id = capability.get("id")
            if capability_id:
                capability_ids.add(str(capability_id))

    return {
        "highest_capability_risk_score": highest_capability_risk_score,
        "risk_level": _risk_level(highest_capability_risk_score),
        "capability_count": len(capability_ids),
        "capability_ids": sorted(capability_ids),
        "requires_human_approval": requires_human_approval,
    }


def _trust_identity(
    *,
    server_name: ServerNameParam,
    manifest_sha256: str,
    tool_names: list[str],
    capability_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "server_name": server_name,
        "manifest_sha256": manifest_sha256,
        "tool_count": len(tool_names),
        "tool_names": tool_names,
        "highest_capability_risk_score": capability_summary.get(
            "highest_capability_risk_score",
            0,
        ),
        "capability_ids": capability_summary.get("capability_ids", []),
        "identity_version": TRUST_IDENTITY_VERSION,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _registry_trust_identity(server_name: ServerNameParam) -> tuple[bool, dict[str, Any] | None]:
    registry = get_registry()
    servers = registry.get("servers", {})

    if not isinstance(servers, dict) or server_name not in servers:
        return False, None

    entry = servers.get(server_name, {})
    if not isinstance(entry, dict):
        return True, None

    identity = entry.get("trust_identity") or entry.get("manifest_identity")
    if isinstance(identity, dict):
        return True, identity

    if "manifest_sha256" in entry:
        return True, entry

    return True, None


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _list_value(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _manifest_drift(
    *,
    server_name: ServerNameParam,
    trust_identity: dict[str, Any],
    include_previous_details: bool,
) -> dict[str, Any]:
    known_server, previous_identity = _registry_trust_identity(server_name)

    current_hash = str(trust_identity.get("manifest_sha256", ""))
    current_tool_names = _list_value(trust_identity.get("tool_names", []))
    current_risk = _int_value(
        trust_identity.get("highest_capability_risk_score"),
        0,
    )

    previous_hash = None
    previous_tool_names: list[str] = []
    previous_risk = 0

    if previous_identity:
        previous_hash = previous_identity.get("manifest_sha256")
        previous_tool_names = _list_value(previous_identity.get("tool_names", []))
        previous_risk = _int_value(
            previous_identity.get("highest_capability_risk_score"),
            0,
        )

    manifest_changed = bool(previous_hash) and previous_hash != current_hash
    added_tools = sorted(set(current_tool_names) - set(previous_tool_names))
    removed_tools = sorted(set(previous_tool_names) - set(current_tool_names))
    capability_risk_changed = bool(previous_identity) and previous_risk != current_risk
    risk_increase = current_risk - previous_risk

    if not known_server:
        recommended_action = "review_before_trust"
    elif not previous_identity:
        recommended_action = "approve_manifest_identity_before_drift_detection"
    elif risk_increase >= 30 or (current_risk >= 85 and current_risk > previous_risk):
        recommended_action = "block_until_review"
    elif manifest_changed or capability_risk_changed:
        recommended_action = "human_review_required"
    else:
        recommended_action = "no_action"

    drift = {
        "known_server": known_server,
        "baseline_available": bool(previous_identity),
        "current_manifest_sha256": current_hash,
        "manifest_changed": manifest_changed,
        "current_tool_names": current_tool_names,
        "added_tools": added_tools,
        "removed_tools": removed_tools,
        "capability_risk_changed": capability_risk_changed,
        "current_highest_capability_risk_score": current_risk,
        "recommended_action": recommended_action,
        "previous_details_redacted": False,
    }

    if include_previous_details:
        drift["previous_manifest_sha256"] = previous_hash
        drift["previous_tool_names"] = previous_tool_names
        drift["previous_highest_capability_risk_score"] = previous_risk
        return drift

    drift["previous_manifest_sha256"] = None
    drift["previous_tool_names"] = None
    drift["previous_highest_capability_risk_score"] = None
    drift["added_tools"] = None
    drift["removed_tools"] = None

    if previous_identity:
        drift["previous_details_redacted"] = True
        drift["redaction_reason"] = "admin_key_required_for_previous_identity_details"

    return drift


def _manifest_identity_from_parsed(
    *,
    server_name: ServerNameParam,
    manifest_sha256: str,
    parsed: Any,
) -> dict[str, Any]:
    tools = parsed.get("tools", []) if isinstance(parsed, dict) else []
    reviewed_tools: list[dict[str, Any]] = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        name = str(tool.get("name", "unknown_tool"))
        assessment = assess_mcp_tool_capabilities(
            tool_name=name,
            payload=_safe_json_dumps(tool),
        )
        reviewed_tools.append(
            {
                "tool_name": name,
                "capability_assessment": assessment,
            }
        )

    tool_names = [str(tool.get("tool_name", "unknown_tool")) for tool in reviewed_tools]
    capability_summary = _capability_summary(reviewed_tools)
    trust_identity = _trust_identity(
        server_name=server_name,
        manifest_sha256=manifest_sha256,
        tool_names=tool_names,
        capability_summary=capability_summary,
    )

    return {
        "tool_names": tool_names,
        "capability_summary": capability_summary,
        "trust_identity": trust_identity,
    }


def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _looks_like_risky_tool_name(tool_name: ToolNameParam) -> bool:
    risky_words = [
        "run",
        "exec",
        "execute",
        "shell",
        "terminal",
        "command",
        "bash",
        "powershell",
        "delete",
        "remove",
        "write_file",
        "read_file",
        "filesystem",
        "file",
        "ssh",
        "env",
        "secret",
        "token",
        "credential",
        "cookie",
        "session",
    ]
    clean = tool_name.lower().strip()
    return any(word in clean for word in risky_words)


def _add_manual_finding(
    result: dict[str, Any],
    *,
    rule_id: str,
    label: str,
    severity: str,
    category: str,
    weight: int,
    preview: str,
) -> dict[str, Any]:
    finding = {
        "rule_id": rule_id,
        "label": label,
        "severity": severity,
        "category": category,
        "weight": weight,
        "start": 0,
        "end": 0,
        "preview": preview[:160],
    }

    result.setdefault("findings", []).append(finding)

    categories = set(result.get("categories", []))
    categories.add(category)
    result["categories"] = sorted(categories)

    severities = set(result.get("severities", []))
    severities.add(severity)
    result["severities"] = sorted(severities)

    result["finding_count"] = len(result.get("findings", []))
    existing_score = int(result.get("risk_score", 0))
    increment = weight if existing_score == 0 else max(1, int(weight * 0.75))
    result["risk_score"] = min(100, existing_score + increment)

    return result


def _apply_capability_assessment(
    result: dict[str, Any],
    *,
    tool_name: ToolNameParam,
    payload: str,
    add_findings: bool = True,
) -> dict[str, Any]:
    assessment = assess_mcp_tool_capabilities(tool_name=tool_name, payload=payload)
    result["capability_assessment"] = assessment

    # Important:
    # For live tool calls, capability alone should not automatically block.
    # Example: run_command {"command":"echo hello"} should be allow_with_warning,
    # not block. The actual payload scanner still blocks dangerous arguments.
    #
    # For schemas/manifests, add_findings=True so dangerous capabilities affect
    # onboarding decisions strongly.
    if not add_findings:
        return result

    for capability in assessment.get("capabilities", []):
        result = _add_manual_finding(
            result,
            rule_id=f"capability_{capability.get('id', 'unknown')}",
            label=str(capability.get("label", "Risky MCP tool capability")),
            severity=str(capability.get("severity", "medium")),
            category=str(capability.get("category", "tool_capability")),
            weight=int(capability.get("weight", 40)),
            preview=str(capability.get("evidence", tool_name)),
        )

    return result



def _audit(action: str, result: dict[str, Any]) -> dict[str, Any]:
    event = {
        "action": action,
        "decision": result.get("decision"),
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("risk_level"),
        "finding_count": result.get("finding_count"),
        "categories": result.get("categories", []),
        "severities": result.get("severities", []),
        "text_sha256": result.get("text_sha256"),
        "source": result.get("source", {}),
        "policy": result.get("policy", {}),
        "gateway": result.get("gateway", {}),
        "server_trust": result.get("server_trust", {}),
    }
    return write_audit_event(event)


def _enrich_scan_result(result: dict[str, Any]) -> dict[str, Any]:
    score = int(result.get("risk_score", 0))
    categories = set(result.get("categories", []))
    severities = set(result.get("severities", []))
    decision = result.get("decision", "allow")

    result["risk_level"] = _risk_level(score)

    requires_approval = False
    approval_reason = None

    if decision == "redact":
        requires_approval = True
        approval_reason = "Policy allowed only after redaction."

    if "tool_risk" in categories and decision != "block":
        requires_approval = True
        approval_reason = "Tool has risky capability and should be approved by a human."

    if "command" in categories and decision != "block":
        requires_approval = True
        approval_reason = "Command-related activity should be reviewed before execution."

    if "server_policy" in categories and decision != "block":
        requires_approval = True
        approval_reason = "MCP server is untrusted or monitored and should be reviewed before use."

    if "critical" in severities and decision != "block":
        requires_approval = True
        approval_reason = "Critical finding observed outside blocking mode."

    result["gateway"] = {
        "requires_human_approval": requires_approval,
        "approval_reason": approval_reason,
        "risk_level": result["risk_level"],
    }

    return result


def _finalize(action: str, result: dict[str, Any]) -> dict[str, Any]:
    result = apply_policy(result)
    result = _enrich_scan_result(result)

    policy = load_policy()

    if policy.get("audit_enabled", True):
        result["audit"] = _audit(action, result)

    return result


def _scan_tool_call(server_name: ServerNameParam, tool_name: ToolNameParam, arguments_json: ArgumentsJsonParam) -> dict[str, Any]:
    result = scan(arguments_json)
    result["source"] = {
        "server_name": server_name,
        "tool_name": tool_name,
        "kind": "mcp_tool_call",
    }

    ok, parsed = _safe_json_loads(arguments_json)
    if not ok:
        result = _add_manual_finding(
            result,
            rule_id="invalid_arguments_json",
            label="Tool arguments are not valid JSON",
            severity="medium",
            category="tool_risk",
            weight=35,
            preview=str(parsed.get("parse_error", "invalid json")),
        )

    if _looks_like_risky_tool_name(tool_name):
        result = _add_manual_finding(
            result,
            rule_id="risky_tool_name",
            label="Tool name suggests filesystem, shell, credential, or command execution capability",
            severity="medium",
            category="tool_risk",
            weight=45,
            preview=tool_name,
        )

    result = _apply_capability_assessment(
        result,
        tool_name=tool_name,
        payload=arguments_json,
        add_findings=False,
    )

    return result



def _apply_server_trust(result: dict[str, Any], server_name: ServerNameParam) -> dict[str, Any]:
    trust = get_server_trust(server_name)
    result["server_trust"] = trust

    trust_level = trust.get("trust_level", "untrusted")

    if trust_level == "blocked":
        result = _add_manual_finding(
            result,
            rule_id="blocked_mcp_server",
            label="MCP server is blocked by ShadowGate registry",
            severity="critical",
            category="server_policy",
            weight=100,
            preview=server_name,
        )

    elif trust_level == "untrusted":
        result = _add_manual_finding(
            result,
            rule_id="untrusted_mcp_server",
            label="MCP server is untrusted by default",
            severity="medium",
            category="server_policy",
            weight=40,
            preview=server_name,
        )

    elif trust_level == "monitor":
        result = _add_manual_finding(
            result,
            rule_id="monitored_mcp_server",
            label="MCP server is in monitor list",
            severity="low",
            category="server_policy",
            weight=15,
            preview=server_name,
        )

    return result

def _gateway_from_scan(result: dict[str, Any], *, safe_text_key: str) -> dict[str, Any]:
    decision = result.get("decision", "allow")
    blocked = decision == "block"
    requires_human_approval = bool(result.get("gateway", {}).get("requires_human_approval", False))

    if blocked:
        gateway_action = "block"
    elif requires_human_approval:
        gateway_action = "allow_with_warning"
    elif decision == "redact":
        gateway_action = "allow_redacted"
    else:
        gateway_action = "allow"

    return {
        "allow": not blocked,
        "gateway_action": gateway_action,
        "decision": decision,
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", "none"),
        "reason": result.get("policy", {}).get("reason"),
        "requires_human_approval": requires_human_approval,
        "approval_reason": result.get("gateway", {}).get("approval_reason"),
        safe_text_key: None if blocked else result.get("redacted_text"),
        "blocked_message": "Blocked by ShadowGate policy." if blocked else None,
        "audit_id": result.get("audit", {}).get("event_id"),
        "scan": result,
    }


def _transaction_summary(call_gate: dict[str, Any], response_gate: dict[str, Any]) -> dict[str, Any]:
    call_allowed = bool(call_gate.get("allow_execution"))
    response_allowed = bool(response_gate.get("deliver_to_agent"))

    highest_score = max(
        int(call_gate.get("risk_score", 0)),
        int(response_gate.get("risk_score", 0)),
    )

    needs_approval = bool(call_gate.get("requires_human_approval")) or bool(
        response_gate.get("requires_human_approval")
    )

    if not call_allowed:
        final_decision = "block_call"
        gateway_action = "block"
    elif not response_allowed:
        final_decision = "block_response"
        gateway_action = "block"
    elif needs_approval:
        final_decision = "allow_with_warning"
        gateway_action = "human_review_recommended"
    else:
        final_decision = "allow_transaction"
        gateway_action = "allow"

    return {
        "allow_transaction": call_allowed and response_allowed,
        "final_decision": final_decision,
        "gateway_action": gateway_action,
        "highest_risk_score": highest_score,
        "risk_level": _risk_level(highest_score),
        "requires_human_approval": needs_approval,
        "approval_reasons": [
            reason
            for reason in [
                call_gate.get("approval_reason"),
                response_gate.get("approval_reason"),
            ]
            if reason
        ],
    }


def _client_auth_error_response(auth: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "auth": auth,
        "allowed": False,
        "kind": kind,
        "decision": "auth_failed",
        "blocked_message": auth.get("error", "Authentication failed."),
    }


@mcp.tool()
def health_check() -> dict[str, Any]:
    """Return ShadowGate MCP health, version, and active policy."""
    return {
        "ok": True,
        "name": "ShadowGate MCP",
        "version": VERSION,
        "active_policy": load_policy(),
        "data_paths": _get_data_paths(),
        "security_config": _get_security_config(),
        "server_config": {
            "host": SERVER_HOST,
            "port": SERVER_PORT,
            "mcp_path": "/mcp",
        },
        "tools": [
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
        ],
    }



@mcp.tool()
def scan_text(text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Scan arbitrary text for leaked secrets, prompt injection, risky commands, and sensitive file paths."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "scan_text")

    result = scan(text)
    result["client_auth"] = auth
    result = _finalize("scan_text", result)
    result["auth"] = auth
    return result


@mcp.tool()
def analyze_text(text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """
    Professional public text-analysis tool.

    This merges the practical outputs of:
    - scan_text
    - redact_secrets
    - get_risk_score
    - decide_policy
    - simulate_policy_modes

    Use this as the main public text safety tool.
    """
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "analyze_text")

    result = scan(text)
    result["client_auth"] = auth
    result = _finalize("analyze_text", result)
    result["auth"] = auth

    result["public_api"] = {
        "tool": "analyze_text",
        "replaces": [
            "scan_text",
            "redact_secrets",
            "get_risk_score",
            "decide_policy",
            "simulate_policy_modes"
        ],
        "recommended": True
    }

    result["policy_simulation"] = simulate_modes(scan(text))

    return result


@mcp.tool()
def redact_secrets(text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Return the text with detected secrets and sensitive path snippets redacted."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "redact_secrets")

    return {
        "auth": auth,
        "redacted_text": redact(text),
    }


@mcp.tool()
def get_risk_score(text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Return a 0-100 risk score for a text payload."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "get_risk_score")

    return {
        "auth": auth,
        "risk_score": risk_score(text),
    }


@mcp.tool()
def decide_policy(text: TextParam, strict: bool = True, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Return the policy decision for a payload: allow, redact, or block."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "decide_policy")

    result = policy_decision(text, strict=strict)
    result["client_auth"] = auth
    result = _finalize("decide_policy", result)
    result["auth"] = auth
    return result

@mcp.tool()
def inspect_mcp_response(server_name: ServerNameParam, tool_name: ToolNameParam, response_text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Scan a response returned by another MCP server before the agent trusts it."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "inspect_mcp_response")

    result = scan_mcp_response(server_name, tool_name, response_text)
    result = _apply_server_trust(result, server_name)
    result["client_auth"] = auth

    result = _finalize("inspect_mcp_response", result)
    result["auth"] = auth
    return result

@mcp.tool()
def inspect_mcp_tool_call(server_name: ServerNameParam, tool_name: ToolNameParam, arguments_json: ArgumentsJsonParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Scan an outgoing MCP tool call before execution."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "inspect_mcp_tool_call")

    result = _scan_tool_call(server_name, tool_name, arguments_json)
    result = _apply_server_trust(result, server_name)
    result["client_auth"] = auth

    result = _finalize("inspect_mcp_tool_call", result)
    result["auth"] = auth
    return result

@mcp.tool()
def gate_mcp_tool_call(server_name: ServerNameParam, tool_name: ToolNameParam, arguments_json: ArgumentsJsonParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Gateway decision for an outgoing MCP tool call."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        response = _client_auth_error_response(auth, "gate_mcp_tool_call")
        response["allow_execution"] = False
        response["gateway_action"] = "block_auth"
        return response

    raw = _scan_tool_call(server_name, tool_name, arguments_json)
    raw = _apply_server_trust(raw, server_name)
    raw["client_auth"] = auth

    result = _finalize("gate_mcp_tool_call", raw)

    gateway = _gateway_from_scan(result, safe_text_key="safe_arguments_json")
    gateway["allow_execution"] = gateway.pop("allow")
    gateway["auth"] = auth
    return gateway


@mcp.tool()
def gate_mcp_response(server_name: ServerNameParam, tool_name: ToolNameParam, response_text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Gateway decision for an MCP response."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        response = _client_auth_error_response(auth, "gate_mcp_response")
        response["deliver_to_agent"] = False
        response["gateway_action"] = "block_auth"
        return response

    raw = scan_mcp_response(server_name, tool_name, response_text)
    raw = _apply_server_trust(raw, server_name)
    raw["client_auth"] = auth

    result = _finalize("gate_mcp_response", raw)

    gateway = _gateway_from_scan(result, safe_text_key="safe_response_text")
    gateway["deliver_to_agent"] = gateway.pop("allow")
    gateway["auth"] = auth
    return gateway


@mcp.tool()
def evaluate_mcp_transaction(
    server_name: ServerNameParam,
    tool_name: ToolNameParam,
    arguments_json: ArgumentsJsonParam,
    response_text: TextParam,
    client_key: ClientKeyParam = "",
) -> dict[str, Any]:
    """
    Evaluate both sides of an MCP interaction:
    1. outgoing tool call arguments
    2. incoming MCP response
    """
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        response = _client_auth_error_response(auth, "evaluate_mcp_transaction")
        response["allow_transaction"] = False
        response["final_decision"] = "block_auth"
        response["gateway_action"] = "block_auth"
        return response

    call_gate = gate_mcp_tool_call(
        server_name=server_name,
        tool_name=tool_name,
        arguments_json=arguments_json,
        client_key=client_key,
    )

    response_gate = gate_mcp_response(
        server_name=server_name,
        tool_name=tool_name,
        response_text=response_text,
        client_key=client_key,
    )

    summary = _transaction_summary(call_gate, response_gate)

    return {
        **summary,
        "auth": auth,
        "safe_transaction_summary": {
            "server_name": server_name,
            "tool_name": tool_name,
            "call_audit_id": call_gate.get("audit_id"),
            "response_audit_id": response_gate.get("audit_id"),
            "call_gateway_action": call_gate.get("gateway_action"),
            "response_gateway_action": response_gate.get("gateway_action"),
        },
        "call_gate": call_gate,
        "response_gate": response_gate,
    }


@mcp.tool()
def inspect_tool_schema(server_name: ServerNameParam, tool_name: ToolNameParam, schema_json: SchemaJsonParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Scan an MCP tool schema/description before allowing agents to use it."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "inspect_tool_schema")

    combined = json.dumps(
        {
            "server_name": server_name,
            "tool_name": tool_name,
            "schema": schema_json,
        },
        ensure_ascii=False,
    )

    result = scan(combined)
    result["source"] = {
        "server_name": server_name,
        "tool_name": tool_name,
        "kind": "mcp_tool_schema",
    }

    result = _apply_capability_assessment(
        result,
        tool_name=tool_name,
        payload=schema_json,
    )

    result = _apply_server_trust(result, server_name)

    if _looks_like_risky_tool_name(tool_name):
        result = _add_manual_finding(
            result,
            rule_id="risky_tool_schema_name",
            label="Tool schema name suggests high-risk capability",
            severity="medium",
            category="tool_risk",
            weight=45,
            preview=tool_name,
        )

    result["client_auth"] = auth
    result = _finalize("inspect_tool_schema", result)
    result["auth"] = auth
    return result


@mcp.tool()
def review_mcp_manifest(
    server_name: ServerNameParam,
    manifest_json: ManifestJsonParam,
    client_key: ClientKeyParam = "",
    admin_key: AdminKeyParam = "",
) -> dict[str, Any]:
    """
    Review a simplified MCP server manifest.

    This is now protected by client_key when SHADOWGATE_CLIENT_KEY is set.
    """
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "review_mcp_manifest")

    admin_auth = require_admin_key(admin_key)
    include_previous_details = bool(admin_auth.get("ok"))
    manifest_hash = _manifest_sha256(manifest_json)
    ok, parsed = _safe_json_loads(manifest_json)

    if not ok:
        result = scan(manifest_json)
        result = _add_manual_finding(
            result,
            rule_id="invalid_manifest_json",
            label="MCP manifest is not valid JSON",
            severity="medium",
            category="tool_risk",
            weight=40,
            preview=str(parsed.get("parse_error", "invalid json")),
        )
        result["source"] = {"server_name": server_name, "kind": "mcp_manifest"}
        result = _apply_server_trust(result, server_name)
        result["client_auth"] = auth

        final = _finalize("review_mcp_manifest", result)
        capability_summary = _capability_summary([])
        trust_identity = _trust_identity(
            server_name=server_name,
            manifest_sha256=manifest_hash,
            tool_names=[],
            capability_summary=capability_summary,
        )
        manifest_drift = _manifest_drift(
            server_name=server_name,
            trust_identity=trust_identity,
            include_previous_details=include_previous_details,
        )

        return {
            "auth": auth,
            "server_name": server_name,
            "valid_json": False,
            "manifest_sha256": manifest_hash,
            "admin_auth": admin_auth,
            "overall_decision": final.get("decision"),
            "highest_risk_score": final.get("risk_score"),
            "risk_level": final.get("risk_level"),
            "requires_human_approval": final.get("gateway", {}).get("requires_human_approval"),
            "tool_count": 0,
            "tool_names": [],
            "capability_summary": capability_summary,
            "trust_identity": trust_identity,
            "manifest_drift": manifest_drift,
            "tools": [],
            "manifest_scan": final,
        }

    tools = parsed.get("tools", []) if isinstance(parsed, dict) else []

    reviewed_tools: list[dict[str, Any]] = []
    highest = 0
    decisions: list[str] = []
    needs_approval = False

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        name = str(tool.get("name", "unknown_tool"))
        schema_text = _safe_json_dumps(tool)

        scan_result = inspect_tool_schema(
            server_name=server_name,
            tool_name=name,
            schema_json=schema_text,
            client_key=client_key,
        )

        highest = max(highest, int(scan_result.get("risk_score", 0)))
        decisions.append(str(scan_result.get("decision", "allow")))

        if bool(scan_result.get("gateway", {}).get("requires_human_approval")):
            needs_approval = True

        reviewed_tools.append(
            {
                "tool_name": name,
                "decision": scan_result.get("decision"),
                "risk_score": scan_result.get("risk_score"),
                "risk_level": scan_result.get("risk_level"),
                "requires_human_approval": scan_result.get("gateway", {}).get("requires_human_approval"),
                "approval_reason": scan_result.get("gateway", {}).get("approval_reason"),
                "categories": scan_result.get("categories", []),
                "severities": scan_result.get("severities", []),
                "capability_assessment": scan_result.get("capability_assessment", {}),
                "policy": scan_result.get("policy", {}),
                "server_trust": scan_result.get("server_trust", {}),
                "audit_id": scan_result.get("audit", {}).get("event_id"),
            }
        )

    if "block" in decisions:
        overall = "block"
    elif needs_approval:
        overall = "allow_with_warning"
    elif "redact" in decisions:
        overall = "redact"
    else:
        overall = "allow"

    tool_names = [str(tool.get("tool_name", "unknown_tool")) for tool in reviewed_tools]
    capability_summary = _capability_summary(reviewed_tools)
    trust_identity = _trust_identity(
        server_name=server_name,
        manifest_sha256=manifest_hash,
        tool_names=tool_names,
        capability_summary=capability_summary,
    )
    manifest_drift = _manifest_drift(
        server_name=server_name,
        trust_identity=trust_identity,
        include_previous_details=include_previous_details,
    )

    return {
        "auth": auth,
        "server_name": server_name,
        "valid_json": True,
        "manifest_sha256": manifest_hash,
        "admin_auth": admin_auth,
        "overall_decision": overall,
        "highest_risk_score": highest,
        "risk_level": _risk_level(highest),
        "requires_human_approval": needs_approval,
        "tool_count": len(reviewed_tools),
        "tool_names": tool_names,
        "capability_summary": capability_summary,
        "trust_identity": trust_identity,
        "manifest_drift": manifest_drift,
        "tools": reviewed_tools,
    }


@mcp.tool()
def scan_batch(items: list[str], client_key: ClientKeyParam = "") -> dict[str, Any]:
    """
    Scan multiple text items in one call.

    This is now protected by client_key when SHADOWGATE_CLIENT_KEY is set.
    """
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "scan_batch")

    results: list[dict[str, Any]] = []

    for index, item in enumerate(items):
        result = scan(item)
        result["source"] = {
            "kind": "batch_item",
            "index": index,
        }
        result["client_auth"] = auth
        results.append(_finalize("scan_batch_item", result))

    highest_score = max((r.get("risk_score", 0) for r in results), default=0)
    decisions = [r.get("decision") for r in results]
    approval_needed = any(r.get("gateway", {}).get("requires_human_approval") for r in results)

    if "block" in decisions:
        overall = "block"
    elif approval_needed:
        overall = "allow_with_warning"
    elif "redact" in decisions:
        overall = "redact"
    else:
        overall = "allow"

    return {
        "auth": auth,
        "overall_decision": overall,
        "highest_risk_score": highest_score,
        "risk_level": _risk_level(highest_score),
        "requires_human_approval": approval_needed,
        "count": len(results),
        "results": results,
    }


@mcp.tool()
def simulate_policy_modes(text: TextParam, client_key: ClientKeyParam = "") -> dict[str, Any]:
    """Show how the same text would be handled under monitor, balanced, and strict modes."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "simulate_policy_modes")

    base = scan(text)

    return {
        "auth": auth,
        "active_policy": load_policy(),
        "simulation": simulate_modes(base),
        "base_scan": {
            "risk_score": base.get("risk_score"),
            "risk_level": _risk_level(int(base.get("risk_score", 0))),
            "finding_count": base.get("finding_count"),
            "categories": base.get("categories", []),
            "severities": base.get("severities", []),
            "text_sha256": base.get("text_sha256"),
        },
    }

@mcp.tool()
def get_policy() -> dict[str, Any]:
    """Return the active ShadowGate policy configuration."""
    return load_policy()


@mcp.tool()
def set_policy_mode(mode: PolicyModeParam, admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """Change ShadowGate policy mode: monitor, balanced, or strict."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"updated": False, "auth": auth}
    result = update_policy_mode(mode)
    result["auth"] = auth
    return result


@mcp.tool()
def get_recent_audit_events(limit: LimitParam = 20, admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """Return recent ShadowGate audit events. Raw scanned text is never stored."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth, "events": []}
    return {"auth": auth, "events": read_audit_events(limit=limit)}


@mcp.tool()
def get_audit_summary(admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """Return a summary of ShadowGate audit decisions, actions, categories, and severities."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth}
    summary = summarize_audit_log()
    summary["auth"] = auth
    return summary


def _compact_block_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "action": event.get("action"),
        "score": event.get("risk_score"),
        "level": event.get("risk_level"),
        "categories": event.get("categories", []),
        "event_id": event.get("event_id"),
    }


def _compact_warning_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "action": event.get("action"),
        "score": event.get("risk_score"),
        "level": event.get("risk_level"),
        "approval_reason": event.get("gateway", {}).get("approval_reason"),
        "event_id": event.get("event_id"),
    }


def _risk_overview(summary: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    highest_score = max(
        (_int_value(event.get("risk_score"), 0) for event in events),
        default=0,
    )
    highest_level = _risk_level(highest_score)

    return {
        "total_events": summary.get("total_events", 0),
        "by_decision": summary.get("by_decision", {}),
        "top_categories": summary.get("top_categories", {}),
        "top_severities": summary.get("top_severities", {}),
        "highest_recent_risk_score": highest_score,
        "highest_recent_risk_level": highest_level,
    }


def _server_trust_overview(registry: dict[str, Any]) -> dict[str, Any]:
    servers = registry.get("servers", {})
    if not isinstance(servers, dict):
        servers = {}

    counts = {level: 0 for level in sorted(ALLOWED_TRUST_LEVELS)}
    server_names_by_level = {level: [] for level in sorted(ALLOWED_TRUST_LEVELS)}
    default_trust = registry.get("default_trust", "untrusted")

    for server_name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        trust_level = str(entry.get("trust_level", default_trust)).lower().strip()
        if trust_level not in ALLOWED_TRUST_LEVELS:
            trust_level = "untrusted"
        counts[trust_level] += 1
        server_names_by_level[trust_level].append(str(server_name))

    return {
        "default_trust": default_trust,
        "counts": counts,
        "blocked_servers": sorted(server_names_by_level["blocked"]),
        "monitored_servers": sorted(server_names_by_level["monitor"]),
        "trusted_servers": sorted(server_names_by_level["trusted"]),
    }


def _manifest_identity_overview(registry: dict[str, Any]) -> dict[str, Any]:
    servers = registry.get("servers", {})
    if not isinstance(servers, dict):
        servers = {}

    entries: list[dict[str, Any]] = []

    for server_name, entry in servers.items():
        if not isinstance(entry, dict):
            continue

        identity = entry.get("trust_identity")
        if not isinstance(identity, dict):
            continue

        entries.append(
            {
                "server_name": str(server_name),
                "trust_level": entry.get("trust_level", "untrusted"),
                "manifest_sha256": identity.get("manifest_sha256"),
                "tool_count": identity.get("tool_count", 0),
                "highest_capability_risk_score": identity.get(
                    "highest_capability_risk_score",
                    0,
                ),
                "capability_ids": identity.get("capability_ids", []),
            }
        )

    entries.sort(key=lambda item: item["server_name"])

    return {
        "servers_with_trust_identity": len(entries),
        "servers": entries,
    }


def _capability_risk_overview(
    manifest_identity_overview: dict[str, Any],
) -> dict[str, Any]:
    capability_counts: dict[str, int] = {}
    highest_score = 0
    high_risk_servers: list[dict[str, Any]] = []

    for entry in manifest_identity_overview.get("servers", []):
        score = _int_value(entry.get("highest_capability_risk_score"), 0)
        highest_score = max(highest_score, score)

        for capability_id in _list_value(entry.get("capability_ids", [])):
            capability_counts[capability_id] = capability_counts.get(capability_id, 0) + 1

        if score >= 70:
            high_risk_servers.append(
                {
                    "server_name": entry.get("server_name"),
                    "trust_level": entry.get("trust_level"),
                    "highest_capability_risk_score": score,
                    "capability_ids": entry.get("capability_ids", []),
                }
            )

    high_risk_servers.sort(key=lambda item: str(item.get("server_name", "")))

    return {
        "capability_ids": dict(sorted(capability_counts.items())),
        "highest_capability_risk_score": highest_score,
        "servers_with_high_capability_risk": high_risk_servers,
    }


def _security_report_recommendations(
    *,
    risk_overview: dict[str, Any],
    server_trust_overview: dict[str, Any],
    manifest_identity_overview: dict[str, Any],
    capability_risk_overview: dict[str, Any],
    recent_block_count: int,
) -> list[str]:
    recommendations: list[str] = []

    if server_trust_overview.get("blocked_servers"):
        recommendations.append("Review blocked server list.")

    if manifest_identity_overview.get("servers_with_trust_identity", 0) == 0:
        recommendations.append("Approve baseline identities for trusted MCP servers.")

    if capability_risk_overview.get("servers_with_high_capability_risk"):
        recommendations.append("Require human approval policy for high-capability tools.")

    total_blocks = _int_value(risk_overview.get("by_decision", {}).get("block"), 0)
    if recent_block_count >= 5 or total_blocks >= 5:
        recommendations.append("Investigate recent blocked events.")

    security = _get_security_config()
    if not security.get("admin_auth_enabled") or not security.get("client_auth_enabled"):
        recommendations.append(
            "Set SHADOWGATE_ADMIN_KEY and SHADOWGATE_CLIENT_KEY for hosted use."
        )

    if not recommendations:
        recommendations.append("No immediate security-report actions.")

    return recommendations


def _security_report_sections(
    *,
    summary: dict[str, Any],
    events: list[dict[str, Any]],
    registry: dict[str, Any],
    recent_blocks: list[dict[str, Any]],
    recent_warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    risk_overview = _risk_overview(summary, events)
    server_trust_overview = _server_trust_overview(registry)
    manifest_identity_overview = _manifest_identity_overview(registry)
    capability_risk_overview = _capability_risk_overview(manifest_identity_overview)

    compact_blocks = [_compact_block_event(event) for event in recent_blocks]
    compact_warnings = [_compact_warning_event(event) for event in recent_warnings]

    return {
        "risk_overview": risk_overview,
        "recent_blocks": compact_blocks,
        "recent_human_review_warnings": compact_warnings,
        "server_trust_overview": server_trust_overview,
        "manifest_identity_overview": manifest_identity_overview,
        "capability_risk_overview": capability_risk_overview,
        "production_hardening": _get_security_config(),
        "recommendations": _security_report_recommendations(
            risk_overview=risk_overview,
            server_trust_overview=server_trust_overview,
            manifest_identity_overview=manifest_identity_overview,
            capability_risk_overview=capability_risk_overview,
            recent_block_count=len(recent_blocks),
        ),
    }


def _security_report_markdown(report_sections: dict[str, Any]) -> str:
    risk = report_sections["risk_overview"]
    trust = report_sections["server_trust_overview"]
    identities = report_sections["manifest_identity_overview"]
    capability = report_sections["capability_risk_overview"]

    markdown = [
        "# ShadowGate MCP Security Report",
        "",
        f"Version: {VERSION}",
        "",
        "## Risk overview",
        f"- Total audit events: {risk.get('total_events', 0)}",
        f"- By decision: {risk.get('by_decision', {})}",
        f"- Top categories: {risk.get('top_categories', {})}",
        f"- Top severities: {risk.get('top_severities', {})}",
        f"- Highest recent risk: {risk.get('highest_recent_risk_score')} "
        f"({risk.get('highest_recent_risk_level')})",
        "",
        "## Server trust overview",
        f"- Default trust: {trust.get('default_trust')}",
        f"- Counts: {trust.get('counts', {})}",
        f"- Blocked servers: {trust.get('blocked_servers', [])}",
        f"- Monitored servers: {trust.get('monitored_servers', [])}",
        f"- Trusted servers: {trust.get('trusted_servers', [])}",
        "",
        "## Manifest identity overview",
        f"- Servers with trust identity: {identities.get('servers_with_trust_identity', 0)}",
    ]

    for entry in identities.get("servers", []):
        markdown.append(
            f"- {entry.get('server_name')} | trust={entry.get('trust_level')} | "
            f"tools={entry.get('tool_count')} | "
            f"capability_score={entry.get('highest_capability_risk_score')} | "
            f"capabilities={entry.get('capability_ids', [])}"
        )

    markdown.extend(
        [
            "",
            "## Capability risk overview",
            f"- Capability IDs: {capability.get('capability_ids', {})}",
            f"- Highest capability risk score: "
            f"{capability.get('highest_capability_risk_score', 0)}",
            f"- High-risk servers: "
            f"{capability.get('servers_with_high_capability_risk', [])}",
            "",
            "## Recent blocked events",
        ]
    )

    recent_blocks = report_sections["recent_blocks"]
    if not recent_blocks:
        markdown.append("- No recent blocked events.")
    else:
        for event in recent_blocks:
            markdown.append(
                f"- {event.get('timestamp')} | action={event.get('action')} | "
                f"score={event.get('score')} | level={event.get('level')} | "
                f"categories={event.get('categories')} | event_id={event.get('event_id')}"
            )

    markdown.extend(["", "## Recent human-review warnings"])

    recent_warnings = report_sections["recent_human_review_warnings"]
    if not recent_warnings:
        markdown.append("- No recent human-review warnings.")
    else:
        for event in recent_warnings:
            markdown.append(
                f"- {event.get('timestamp')} | action={event.get('action')} | "
                f"score={event.get('score')} | level={event.get('level')} | "
                f"reason={event.get('approval_reason')} | "
                f"event_id={event.get('event_id')}"
            )

    markdown.extend(["", "## Recommendations"])

    for recommendation in report_sections["recommendations"]:
        markdown.append(f"- {recommendation}")

    return "\n".join(markdown)


@mcp.tool()
def create_security_report(limit: LimitParam = 50, admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """Create a compact security report from recent audit events."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth, "markdown": ""}
    summary = summarize_audit_log()
    events = read_audit_events(limit=limit)

    recent_blocks = [
        event for event in events
        if event.get("decision") == "block"
    ][-10:]

    recent_warnings = [
        event for event in events
        if event.get("gateway", {}).get("requires_human_approval")
    ][-10:]

    report_sections = _security_report_sections(
        summary=summary,
        events=events,
        registry=get_registry(),
        recent_blocks=recent_blocks,
        recent_warnings=recent_warnings,
    )

    return {
        "version": VERSION,
        "summary": summary,
        "recent_block_count": len(recent_blocks),
        "recent_warning_count": len(recent_warnings),
        "markdown": _security_report_markdown(report_sections),
        "auth": auth,
        "report_sections": report_sections,
    }


@mcp.tool()
def get_server_registry(admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """Return the ShadowGate MCP server trust registry."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth}
    registry = get_registry()
    registry["auth"] = auth
    return registry


@mcp.tool()
def get_mcp_server_trust(server_name: ServerNameParam) -> dict[str, Any]:
    """Return trust status for a specific MCP server."""
    return get_server_trust(server_name)


@mcp.tool()
def set_mcp_server_trust(server_name: ServerNameParam, trust_level: str, reason: ReasonParam = "", admin_key: AdminKeyParam = "") -> dict[str, Any]:
    """
    Set trust level for an MCP server.

    Allowed trust levels:
    - trusted
    - untrusted
    - monitor
    - blocked
    """
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"updated": False, "auth": auth}
    result = set_server_trust(server_name, trust_level, reason)
    result["auth"] = auth
    return result


@mcp.tool()
def approve_mcp_manifest_identity(
    server_name: ServerNameParam,
    manifest_json: ManifestJsonParam,
    trust_level: TrustLevelParam = "trusted",
    reason: ReasonParam = "",
    admin_key: AdminKeyParam = "",
) -> dict[str, Any]:
    """Admin tool to approve and persist a manifest trust identity baseline."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"updated": False, "auth": auth}

    clean_level = trust_level.lower().strip()
    if clean_level not in ALLOWED_TRUST_LEVELS:
        return {
            "updated": False,
            "error": f"Invalid trust level: {trust_level}",
            "allowed_trust_levels": sorted(ALLOWED_TRUST_LEVELS),
            "auth": auth,
        }

    ok, parsed = _safe_json_loads(manifest_json)
    if not ok:
        return {
            "updated": False,
            "server_name": server_name,
            "trust_level": clean_level,
            "error": "Invalid manifest JSON.",
            "parse_error": parsed.get("parse_error"),
            "auth": auth,
        }

    manifest_hash = _manifest_sha256(manifest_json)
    identity_parts = _manifest_identity_from_parsed(
        server_name=server_name,
        manifest_sha256=manifest_hash,
        parsed=parsed,
    )
    trust_identity = identity_parts["trust_identity"]
    capability_summary = identity_parts["capability_summary"]

    registry = load_registry()
    servers = registry.setdefault("servers", {})
    existing = servers.get(server_name, {})
    if not isinstance(existing, dict):
        existing = {}

    entry = {
        **existing,
        "trust_level": clean_level,
        "reason": reason,
        "updated_at": _now(),
        "trust_identity": trust_identity,
        "manifest_sha256": trust_identity["manifest_sha256"],
        "tool_names": trust_identity["tool_names"],
        "tool_count": trust_identity["tool_count"],
        "highest_capability_risk_score": trust_identity[
            "highest_capability_risk_score"
        ],
        "capability_ids": trust_identity["capability_ids"],
    }
    servers[server_name] = entry
    save_registry(registry)

    return {
        "updated": True,
        "server_name": server_name,
        "trust_level": clean_level,
        "trust_identity": trust_identity,
        "capability_summary": capability_summary,
        "registry_entry": {
            "trust_level": entry["trust_level"],
            "reason": entry.get("reason", ""),
            "updated_at": entry.get("updated_at"),
            "manifest_sha256": entry["manifest_sha256"],
            "tool_names": entry["tool_names"],
            "tool_count": entry["tool_count"],
            "highest_capability_risk_score": entry[
                "highest_capability_risk_score"
            ],
            "capability_ids": entry["capability_ids"],
        },
        "auth": auth,
    }


@mcp.tool()
def get_data_paths() -> dict[str, Any]:
    """Return ShadowGate data directory paths for policy, registry, and audit logs."""
    return _get_data_paths()


@mcp.tool()
def get_security_config() -> dict[str, Any]:
    """Return ShadowGate admin-auth security configuration without exposing the raw key."""
    return _get_security_config()


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
