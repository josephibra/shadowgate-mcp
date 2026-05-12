from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def get_data_dir() -> Path:
    raw = os.environ.get("SHADOWGATE_DATA_DIR", ".").strip()
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def policy_file_path() -> Path:
    return get_data_dir() / "shadowgate_policy.json"


def registry_file_path() -> Path:
    return get_data_dir() / "shadowgate_server_registry.json"


def audit_dir_path() -> Path:
    path = get_data_dir() / "audit_logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def audit_file_path() -> Path:
    return audit_dir_path() / "shadowgate_audit.jsonl"


def get_data_paths() -> dict[str, Any]:
    data_dir = get_data_dir()
    return {
        "data_dir": str(data_dir),
        "policy_file": str(policy_file_path()),
        "registry_file": str(registry_file_path()),
        "audit_dir": str(audit_dir_path()),
        "audit_file": str(audit_file_path()),
        "env_var": "SHADOWGATE_DATA_DIR",
    }
