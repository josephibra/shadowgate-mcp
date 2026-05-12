from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .storage import registry_file_path


ALLOWED_TRUST_LEVELS = {"trusted", "untrusted", "blocked", "monitor"}

DEFAULT_REGISTRY = {
    "default_trust": "untrusted",
    "servers": {},
}


def _registry_file():
    return registry_file_path()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_registry() -> dict[str, Any]:
    registry_file = _registry_file()

    if not registry_file.exists():
        save_registry(DEFAULT_REGISTRY)
        return DEFAULT_REGISTRY.copy()

    try:
        loaded = json.loads(registry_file.read_text(encoding="utf-8"))
        registry = {**DEFAULT_REGISTRY, **loaded}

        if registry.get("default_trust") not in ALLOWED_TRUST_LEVELS:
            registry["default_trust"] = "untrusted"

        if not isinstance(registry.get("servers"), dict):
            registry["servers"] = {}

        return registry
    except Exception:
        return DEFAULT_REGISTRY.copy()


def save_registry(registry: dict[str, Any]) -> dict[str, Any]:
    registry_file = _registry_file()
    registry_file.parent.mkdir(parents=True, exist_ok=True)

    clean = {**DEFAULT_REGISTRY, **registry}

    if clean.get("default_trust") not in ALLOWED_TRUST_LEVELS:
        clean["default_trust"] = "untrusted"

    if not isinstance(clean.get("servers"), dict):
        clean["servers"] = {}

    registry_file.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return clean


def get_server_trust(server_name: str) -> dict[str, Any]:
    registry = load_registry()
    servers = registry.get("servers", {})

    entry = servers.get(server_name)

    if not entry:
        return {
            "server_name": server_name,
            "trust_level": registry.get("default_trust", "untrusted"),
            "source": "default",
            "reason": "No explicit registry entry.",
            "registry_file": str(_registry_file()),
        }

    trust_level = entry.get("trust_level", registry.get("default_trust", "untrusted"))

    if trust_level not in ALLOWED_TRUST_LEVELS:
        trust_level = "untrusted"

    return {
        "server_name": server_name,
        "trust_level": trust_level,
        "source": "registry",
        "reason": entry.get("reason", ""),
        "updated_at": entry.get("updated_at"),
        "registry_file": str(_registry_file()),
    }


def set_server_trust(server_name: str, trust_level: str, reason: str = "") -> dict[str, Any]:
    clean_level = trust_level.lower().strip()

    if clean_level not in ALLOWED_TRUST_LEVELS:
        return {
            "updated": False,
            "error": f"Invalid trust level: {trust_level}",
            "allowed_trust_levels": sorted(ALLOWED_TRUST_LEVELS),
            "registry": load_registry(),
        }

    registry = load_registry()
    registry.setdefault("servers", {})

    registry["servers"][server_name] = {
        "trust_level": clean_level,
        "reason": reason,
        "updated_at": _now(),
    }

    registry = save_registry(registry)

    return {
        "updated": True,
        "server_name": server_name,
        "trust_level": clean_level,
        "reason": reason,
        "registry": registry,
    }


def get_registry() -> dict[str, Any]:
    registry = load_registry()
    return {
        "registry_file": str(_registry_file()),
        "allowed_trust_levels": sorted(ALLOWED_TRUST_LEVELS),
        **registry,
    }
