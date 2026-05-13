from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .audit import read_audit_events, summarize_audit_log, write_audit_event
from .auth import get_security_config as _get_security_config, require_admin_key, require_client_key
from .policy import apply_policy, load_policy, simulate_policy_modes as simulate_modes, update_policy_mode
from .registry import get_registry, get_server_trust, set_server_trust
from .scanner import policy_decision, redact, risk_score, scan, scan_mcp_response
from .storage import get_data_paths as _get_data_paths

VERSION = "0.3.8-public-surface"

SERVER_HOST = os.environ.get("SHADOWGATE_HOST", os.environ.get("HOST", "127.0.0.1"))
SERVER_PORT = int(os.environ.get("SHADOWGATE_PORT", os.environ.get("PORT", "8000")))

mcp = FastMCP("ShadowGate MCP", json_response=True, host=SERVER_HOST, port=SERVER_PORT)


def _safe_json_loads(value: str) -> tuple[bool, Any]:
    try:
        return True, json.loads(value)
    except Exception as exc:
        return False, {"parse_error": str(exc), "raw": value}


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


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


def _looks_like_risky_tool_name(tool_name: str) -> bool:
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


def _scan_tool_call(server_name: str, tool_name: str, arguments_json: str) -> dict[str, Any]:
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

    return result



def _apply_server_trust(result: dict[str, Any], server_name: str) -> dict[str, Any]:
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
            "get_data_paths",
            "get_security_config",
        ],
    }



@mcp.tool()
def scan_text(text: str, client_key: str = "") -> dict[str, Any]:
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
def analyze_text(text: str, client_key: str = "") -> dict[str, Any]:
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
def redact_secrets(text: str, client_key: str = "") -> dict[str, Any]:
    """Return the text with detected secrets and sensitive path snippets redacted."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "redact_secrets")

    return {
        "auth": auth,
        "redacted_text": redact(text),
    }


@mcp.tool()
def get_risk_score(text: str, client_key: str = "") -> dict[str, Any]:
    """Return a 0-100 risk score for a text payload."""
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "get_risk_score")

    return {
        "auth": auth,
        "risk_score": risk_score(text),
    }


@mcp.tool()
def decide_policy(text: str, strict: bool = True, client_key: str = "") -> dict[str, Any]:
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
def inspect_mcp_response(server_name: str, tool_name: str, response_text: str, client_key: str = "") -> dict[str, Any]:
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
def inspect_mcp_tool_call(server_name: str, tool_name: str, arguments_json: str, client_key: str = "") -> dict[str, Any]:
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
def gate_mcp_tool_call(server_name: str, tool_name: str, arguments_json: str, client_key: str = "") -> dict[str, Any]:
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
def gate_mcp_response(server_name: str, tool_name: str, response_text: str, client_key: str = "") -> dict[str, Any]:
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
    server_name: str,
    tool_name: str,
    arguments_json: str,
    response_text: str,
    client_key: str = "",
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
def inspect_tool_schema(server_name: str, tool_name: str, schema_json: str, client_key: str = "") -> dict[str, Any]:
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
def review_mcp_manifest(server_name: str, manifest_json: str, client_key: str = "") -> dict[str, Any]:
    """
    Review a simplified MCP server manifest.

    This is now protected by client_key when SHADOWGATE_CLIENT_KEY is set.
    """
    auth = require_client_key(client_key)

    if not auth.get("ok"):
        return _client_auth_error_response(auth, "review_mcp_manifest")

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

        return {
            "auth": auth,
            "server_name": server_name,
            "valid_json": False,
            "overall_decision": final.get("decision"),
            "highest_risk_score": final.get("risk_score"),
            "risk_level": final.get("risk_level"),
            "requires_human_approval": final.get("gateway", {}).get("requires_human_approval"),
            "tool_count": 0,
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

    return {
        "auth": auth,
        "server_name": server_name,
        "valid_json": True,
        "overall_decision": overall,
        "highest_risk_score": highest,
        "risk_level": _risk_level(highest),
        "requires_human_approval": needs_approval,
        "tool_count": len(reviewed_tools),
        "tools": reviewed_tools,
    }


@mcp.tool()
def scan_batch(items: list[str], client_key: str = "") -> dict[str, Any]:
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
def simulate_policy_modes(text: str, client_key: str = "") -> dict[str, Any]:
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
def set_policy_mode(mode: str, admin_key: str = "") -> dict[str, Any]:
    """Change ShadowGate policy mode: monitor, balanced, or strict."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"updated": False, "auth": auth}
    result = update_policy_mode(mode)
    result["auth"] = auth
    return result


@mcp.tool()
def get_recent_audit_events(limit: int = 20, admin_key: str = "") -> dict[str, Any]:
    """Return recent ShadowGate audit events. Raw scanned text is never stored."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth, "events": []}
    return {"auth": auth, "events": read_audit_events(limit=limit)}


@mcp.tool()
def get_audit_summary(admin_key: str = "") -> dict[str, Any]:
    """Return a summary of ShadowGate audit decisions, actions, categories, and severities."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth}
    summary = summarize_audit_log()
    summary["auth"] = auth
    return summary


@mcp.tool()
def create_security_report(limit: int = 50, admin_key: str = "") -> dict[str, Any]:
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

    markdown = [
        "# ShadowGate MCP Security Report",
        "",
        f"Version: {VERSION}",
        f"Total audit events: {summary.get('total_events', 0)}",
        f"By decision: {summary.get('by_decision', {})}",
        f"Top categories: {summary.get('top_categories', {})}",
        f"Top severities: {summary.get('top_severities', {})}",
        "",
        "## Recent blocked events",
    ]

    if not recent_blocks:
        markdown.append("- No recent blocked events.")
    else:
        for event in recent_blocks:
            markdown.append(
                f"- {event.get('timestamp')} | action={event.get('action')} | "
                f"score={event.get('risk_score')} | level={event.get('risk_level')} | "
                f"categories={event.get('categories')} | event_id={event.get('event_id')}"
            )

    markdown.extend(["", "## Recent human-review warnings"])

    if not recent_warnings:
        markdown.append("- No recent human-review warnings.")
    else:
        for event in recent_warnings:
            markdown.append(
                f"- {event.get('timestamp')} | action={event.get('action')} | "
                f"score={event.get('risk_score')} | level={event.get('risk_level')} | "
                f"reason={event.get('gateway', {}).get('approval_reason')} | "
                f"event_id={event.get('event_id')}"
            )

    return {
        "version": VERSION,
        "summary": summary,
        "recent_block_count": len(recent_blocks),
        "recent_warning_count": len(recent_warnings),
        "markdown": "\n".join(markdown),
        "auth": auth,
    }


@mcp.tool()
def get_server_registry(admin_key: str = "") -> dict[str, Any]:
    """Return the ShadowGate MCP server trust registry."""
    auth = require_admin_key(admin_key)
    if not auth.get("ok"):
        return {"auth": auth}
    registry = get_registry()
    registry["auth"] = auth
    return registry


@mcp.tool()
def get_mcp_server_trust(server_name: str) -> dict[str, Any]:
    """Return trust status for a specific MCP server."""
    return get_server_trust(server_name)


@mcp.tool()
def set_mcp_server_trust(server_name: str, trust_level: str, reason: str = "", admin_key: str = "") -> dict[str, Any]:
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
def get_data_paths() -> dict[str, Any]:
    """Return ShadowGate data directory paths for policy, registry, and audit logs."""
    return _get_data_paths()


@mcp.tool()
def get_security_config() -> dict[str, Any]:
    """Return ShadowGate admin-auth security configuration without exposing the raw key."""
    return _get_security_config()


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
