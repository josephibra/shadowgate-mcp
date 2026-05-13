from __future__ import annotations

import copy
import json
from typing import Any

from .storage import policy_file_path


POLICY_FILE = policy_file_path()

ALLOWED_MODES = {"monitor", "balanced", "strict"}

DEFAULT_POLICY = {
    "mode": "strict",
    "block_score_at": 80,
    "redact_score_at": 30,
    "always_block_categories": ["file_access", "injection", "secret", "secrets"],
    "always_redact": True,
    "audit_enabled": True,
}



def _normalize_block_categories(categories: Any) -> list[str]:
    """
    Normalize policy category aliases.

    Scanner findings use "secret".
    Some older policy configs may use "secrets".
    Keep both aliases so old policy files still behave safely.
    """
    if not isinstance(categories, list):
        categories = DEFAULT_POLICY["always_block_categories"]

    normalized: list[str] = []

    def add(value: str) -> None:
        clean = value.lower().strip()
        if clean and clean not in normalized:
            normalized.append(clean)

    for category in categories:
        clean = str(category).lower().strip()
        if clean == "secrets":
            add("secret")
            add("secrets")
        elif clean == "secret":
            add("secret")
            add("secrets")
        else:
            add(clean)

    return normalized


def load_policy() -> dict[str, Any]:
    if not POLICY_FILE.exists():
        save_policy(DEFAULT_POLICY)
        return DEFAULT_POLICY.copy()

    try:
        loaded = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        merged = {**DEFAULT_POLICY, **loaded}

        mode = str(merged.get("mode", "strict")).lower().strip()
        if mode not in ALLOWED_MODES:
            merged["mode"] = "strict"

        merged["always_block_categories"] = _normalize_block_categories(
            merged.get("always_block_categories", [])
        )

        return merged
    except Exception:
        return DEFAULT_POLICY.copy()


def save_policy(policy: dict[str, Any]) -> dict[str, Any]:
    clean = {**DEFAULT_POLICY, **policy}

    mode = str(clean.get("mode", "strict")).lower().strip()
    if mode not in ALLOWED_MODES:
        mode = "strict"

    clean["mode"] = mode
    clean["always_block_categories"] = _normalize_block_categories(
        clean.get("always_block_categories", [])
    )

    POLICY_FILE.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return clean


def update_policy_mode(mode: str) -> dict[str, Any]:
    clean_mode = mode.lower().strip()

    if clean_mode not in ALLOWED_MODES:
        return {
            "updated": False,
            "error": f"Invalid mode: {mode}",
            "allowed_modes": sorted(ALLOWED_MODES),
            "active_policy": load_policy(),
        }

    policy = load_policy()
    policy["mode"] = clean_mode
    policy = save_policy(policy)

    return {
        "updated": True,
        "mode": clean_mode,
        "active_policy": policy,
    }


def _score_decision(score: int, block_score: int, redact_score: int) -> str:
    if score >= block_score:
        return "block"
    if score >= redact_score:
        return "redact"
    return "allow"


def _apply_policy_object(result: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    mode = str(policy.get("mode", "strict")).lower().strip()
    if mode not in ALLOWED_MODES:
        mode = "strict"

    score = int(result.get("risk_score", 0))
    categories = set(result.get("categories", []))
    severities = set(result.get("severities", []))

    block_score = int(policy.get("block_score_at", 80))
    redact_score = int(policy.get("redact_score_at", 30))
    always_block = set(
        _normalize_block_categories(policy.get("always_block_categories", []))
    )

    matched_block_categories = sorted(categories.intersection(always_block))
    score_decision = _score_decision(score, block_score, redact_score)

    decision = score_decision
    reason = "score_threshold"

    if mode == "monitor":
        decision = "allow"
        reason = "monitor_only"

    elif mode == "balanced":
        if "secrets" in categories or "critical" in severities:
            decision = "block"
            reason = "balanced_critical_or_secret"
        elif score >= block_score:
            decision = "block"
            reason = "balanced_score_block"
        elif score >= redact_score:
            decision = "redact"
            reason = "balanced_score_redact"
        else:
            decision = "allow"
            reason = "balanced_allow"

    elif mode == "strict":
        if matched_block_categories:
            decision = "block"
            reason = "strict_category_block"
        else:
            decision = score_decision
            reason = "strict_score_threshold"

    result["decision"] = decision
    result["policy"] = {
        "mode": mode,
        "reason": reason,
        "block_score_at": block_score,
        "redact_score_at": redact_score,
        "matched_block_categories": matched_block_categories,
        "score_decision": score_decision,
        "policy_file": str(POLICY_FILE),
    }

    return result


def apply_policy(result: dict[str, Any]) -> dict[str, Any]:
    return _apply_policy_object(result, load_policy())


def evaluate_policy_mode(result: dict[str, Any], mode: str) -> dict[str, Any]:
    policy = load_policy()
    policy["mode"] = mode
    return _apply_policy_object(copy.deepcopy(result), policy)


def simulate_policy_modes(result: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}

    for mode in ["monitor", "balanced", "strict"]:
        evaluated = evaluate_policy_mode(result, mode)
        output[mode] = {
            "decision": evaluated.get("decision"),
            "risk_score": evaluated.get("risk_score"),
            "policy": evaluated.get("policy"),
        }

    return output
