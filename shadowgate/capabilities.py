from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class CapabilityRule:
    id: str
    label: str
    severity: str
    category: str
    weight: int
    pattern: re.Pattern[str]


FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


CAPABILITY_RULES: list[CapabilityRule] = [
    CapabilityRule(
        id="shell_execution",
        label="Tool appears able to execute shell or system commands",
        severity="critical",
        category="tool_capability",
        weight=95,
        pattern=re.compile(
            r"\b(run_command|execute_command|shell|terminal|bash|zsh|powershell|cmd\.exe|subprocess|os\.system|exec)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="filesystem_write_delete",
        label="Tool appears able to write, overwrite, or delete files",
        severity="high",
        category="tool_capability",
        weight=80,
        pattern=re.compile(
            r"\b(write_file|writefile|delete_file|remove_file|overwrite|unlink|filesystem_write|rm\s+-rf)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="filesystem_read",
        label="Tool appears able to read local files or sensitive paths",
        severity="high",
        category="tool_capability",
        weight=75,
        pattern=re.compile(
            r"\b(read_file|readfile|file_read|open_file|download_file|cat\s+|/etc/passwd|\.ssh/id_rsa|\.env)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="credential_access",
        label="Tool appears able to access credentials, tokens, cookies, or secrets",
        severity="critical",
        category="tool_capability",
        weight=90,
        pattern=re.compile(
            r"\b(secret|token|api[_-]?key|credential|password|cookie|session|oauth|private[_-]?key)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="network_request",
        label="Tool appears able to make network requests or callbacks",
        severity="medium",
        category="tool_capability",
        weight=55,
        pattern=re.compile(
            r"\b(http_request|web_request|fetch_url|callback_url|webhook|curl|wget|requests\.|post_url)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="browser_control",
        label="Tool appears able to control a browser or web session",
        severity="high",
        category="tool_capability",
        weight=70,
        pattern=re.compile(
            r"\b(browser|playwright|selenium|puppeteer|page\.goto|dom|localstorage|sessionstorage)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="database_access",
        label="Tool appears able to query or modify a database",
        severity="medium",
        category="tool_capability",
        weight=55,
        pattern=re.compile(
            r"\b(sql|query_database|database|postgres|mysql|mongodb|firestore|supabase|select\s+\*)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="email_messaging",
        label="Tool appears able to read or send email/messages",
        severity="medium",
        category="tool_capability",
        weight=50,
        pattern=re.compile(
            r"\b(send_email|read_email|gmail|smtp|inbox|message_send|mailbox)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="calendar_contacts",
        label="Tool appears able to access calendar, contacts, or invitations",
        severity="medium",
        category="tool_capability",
        weight=45,
        pattern=re.compile(
            r"\b(calendar|contacts|attendees|invite|event_create|event_update)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="payments_billing",
        label="Tool appears able to access payments, invoices, billing, or subscriptions",
        severity="high",
        category="tool_capability",
        weight=75,
        pattern=re.compile(
            r"\b(stripe|chargebee|payment|invoice|billing|subscription|refund|payout)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="deployment_ci",
        label="Tool appears able to deploy, modify infrastructure, or run CI/CD actions",
        severity="high",
        category="tool_capability",
        weight=75,
        pattern=re.compile(
            r"\b(deploy|github_actions|ci/cd|docker|kubectl|terraform|railway|render|fly\.io)\b",
            FLAGS,
        ),
    ),
    CapabilityRule(
        id="personal_data_access",
        label="Tool appears able to access personal or sensitive user data",
        severity="high",
        category="tool_capability",
        weight=70,
        pattern=re.compile(
            r"\b(ssn|passport|date_of_birth|dob|pii|personal_data|phone_number|home_address)\b",
            FLAGS,
        ),
    ),
]


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


def assess_mcp_tool_capabilities(tool_name: str, payload: str = "") -> dict[str, Any]:
    """
    Classify risky MCP tool capabilities from tool name, schema, or arguments.

    This does not replace text scanning. It adds a structural risk layer:
    what can this tool probably do?
    """
    combined = f"{tool_name or ''}\n{payload or ''}"

    capabilities: list[dict[str, Any]] = []
    seen: set[str] = set()

    for rule in CAPABILITY_RULES:
        match = rule.pattern.search(combined)
        if not match:
            continue

        if rule.id in seen:
            continue

        seen.add(rule.id)

        item = asdict(rule)
        item.pop("pattern", None)
        item["evidence"] = match.group(0)[:120]
        capabilities.append(item)

    score = min(100, sum(int(item["weight"]) for item in capabilities))
    severities = sorted({item["severity"] for item in capabilities})
    categories = sorted({item["category"] for item in capabilities})

    if any(item["severity"] == "critical" for item in capabilities) or score >= 85:
        recommendation = "block_or_require_explicit_approval"
    elif score >= 45:
        recommendation = "allow_with_human_review"
    else:
        recommendation = "allow"

    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "capability_count": len(capabilities),
        "categories": categories,
        "severities": severities,
        "capabilities": capabilities,
        "recommendation": recommendation,
        "requires_human_approval": score >= 45,
    }
