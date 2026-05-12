from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from .patterns import ALL_RULES, Rule


@dataclass
class Finding:
    rule_id: str
    label: str
    severity: str
    category: str
    weight: int
    start: int
    end: int
    preview: str


def _preview(text: str, start: int, end: int, max_len: int = 96) -> str:
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    if len(snippet) > max_len:
        return snippet[: max_len - 3] + "..."
    return snippet


def _decision(score: int, findings: list[Finding]) -> str:
    if any(f.severity == "critical" for f in findings) or score >= 85:
        return "block"
    if score >= 45:
        return "redact"
    return "allow"


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, int]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.start, finding.end)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def scan(text: str) -> dict[str, Any]:
    """Scan text for leaked secrets, risky commands, and prompt-injection patterns."""
    text = text or ""
    findings: list[Finding] = []

    for rule in ALL_RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    label=rule.label,
                    severity=rule.severity,
                    category=rule.category,
                    weight=rule.weight,
                    start=match.start(),
                    end=match.end(),
                    preview=_preview(text, match.start(), match.end()),
                )
            )

    findings = _dedupe_findings(findings)
    raw_score = sum(f.weight for f in findings)
    score = min(100, raw_score)
    decision = _decision(score, findings)

    categories = sorted({f.category for f in findings})
    severities = sorted({f.severity for f in findings})

    return {
        "decision": decision,
        "risk_score": score,
        "finding_count": len(findings),
        "categories": categories,
        "severities": severities,
        "findings": [asdict(f) for f in findings],
        "redacted_text": redact(text),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def redact(text: str) -> str:
    """Redact known secret values and sensitive path snippets."""
    redacted = text or ""

    for rule in ALL_RULES:
        if not rule.redact:
            continue
        replacement = f"[REDACTED:{rule.id}]"
        redacted = rule.pattern.sub(replacement, redacted)

    return redacted


def risk_score(text: str) -> int:
    return int(scan(text)["risk_score"])


def policy_decision(text: str, strict: bool = True) -> dict[str, Any]:
    result = scan(text)
    if strict and result["decision"] == "redact" and any(
        finding["category"] in {"command", "injection", "network"}
        for finding in result["findings"]
    ):
        result["decision"] = "block"
        result["strict_mode_escalated"] = True
    else:
        result["strict_mode_escalated"] = False

    return result


def scan_mcp_response(server_name: str, tool_name: str, response_text: str) -> dict[str, Any]:
    result = policy_decision(response_text, strict=True)
    result["source"] = {
        "server_name": server_name,
        "tool_name": tool_name,
        "kind": "mcp_response",
    }
    return result
