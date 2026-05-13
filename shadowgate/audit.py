from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from .storage import audit_file_path


def _audit_file():
    return audit_file_path()


def _make_event_id(record: dict[str, Any]) -> str:
    base = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def _prune_audit_if_needed() -> None:
    try:
        max_events = int(os.environ.get("SHADOWGATE_AUDIT_MAX_EVENTS", "0") or "0")
        retention_days = int(os.environ.get("SHADOWGATE_AUDIT_RETENTION_DAYS", "0") or "0")
    except ValueError:
        return

    if max_events <= 0 and retention_days <= 0:
        return

    audit_file = _audit_file()
    if not audit_file.exists():
        return

    lines = audit_file.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []

    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    original_count = len(events)

    if retention_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        kept: list[dict[str, Any]] = []
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get("timestamp", ""))
                if ts >= cutoff:
                    kept.append(event)
            except (ValueError, TypeError):
                kept.append(event)
        events = kept

    if max_events > 0 and len(events) > max_events:
        events = events[-max_events:]

    if len(events) != original_count:
        content = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
        if content:
            content += "\n"
        audit_file.write_text(content, encoding="utf-8")


def write_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    audit_file = _audit_file()
    audit_file.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    record["event_id"] = _make_event_id(record)

    with audit_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    _prune_audit_if_needed()

    return {
        "written": True,
        "audit_file": str(audit_file),
        "timestamp": record["timestamp"],
        "event_id": record["event_id"],
    }


def read_audit_events(limit: int = 20) -> list[dict[str, Any]]:
    audit_file = _audit_file()

    if not audit_file.exists():
        return []

    safe_limit = max(1, min(int(limit), 500))
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []

    for line in lines[-safe_limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return events


def summarize_audit_log() -> dict[str, Any]:
    audit_file = _audit_file()

    if not audit_file.exists():
        return {
            "audit_file": str(audit_file),
            "total_events": 0,
            "by_decision": {},
            "by_action": {},
            "top_categories": {},
            "top_severities": {},
            "last_timestamp": None,
        }

    lines = audit_file.read_text(encoding="utf-8").splitlines()

    by_decision = Counter()
    by_action = Counter()
    categories = Counter()
    severities = Counter()

    total = 0
    last_timestamp = None

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        total += 1
        by_decision[event.get("decision", "unknown")] += 1
        by_action[event.get("action", "unknown")] += 1
        last_timestamp = event.get("timestamp", last_timestamp)

        for category in event.get("categories", []):
            categories[category] += 1

        for severity in event.get("severities", []):
            severities[severity] += 1

    return {
        "audit_file": str(audit_file),
        "total_events": total,
        "by_decision": dict(by_decision),
        "by_action": dict(by_action),
        "top_categories": dict(categories.most_common(10)),
        "top_severities": dict(severities.most_common(10)),
        "last_timestamp": last_timestamp,
    }
