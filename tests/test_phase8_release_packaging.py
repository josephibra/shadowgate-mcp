import json
import re
import tomllib
from pathlib import Path


RELEASE_VERSION = "0.4.0-hardened"
PACKAGE_VERSION = "0.4.0"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_release_versions_are_consistent_enough():
    pyproject = tomllib.loads(_read("pyproject.toml"))
    assert pyproject["project"]["version"] == PACKAGE_VERSION
    assert f'VERSION = "{RELEASE_VERSION}"' in _read("shadowgate/server.py")
    assert RELEASE_VERSION in _read("README.md")
    assert RELEASE_VERSION in _read("AI_HANDOFF.md")
    assert RELEASE_VERSION in _read("RELEASE_CHECKLIST.md")
    assert RELEASE_VERSION in _read("RELEASE_NOTES.md")

    manifest = json.loads(_read("discovery/shadowgate_manifest.json"))
    assert manifest["version"] == RELEASE_VERSION


def test_release_notes_exists():
    path = Path("RELEASE_NOTES.md")

    assert path.exists()
    assert path.stat().st_size > 0
    assert "Phase 7" in _read("RELEASE_NOTES.md")


def test_readme_includes_public_gateway_terms():
    readme = _read("README.md")

    for term in [
        "ShadowGate MCP",
        "gate_mcp_tool_call",
        "gate_mcp_response",
        "review_mcp_manifest",
        "approve_mcp_manifest_identity",
        "create_security_report",
    ]:
        assert term in readme


def test_release_json_files_parse():
    assert json.loads(_read("examples/client_payloads.json"))
    assert json.loads(_read("discovery/shadowgate_manifest.json"))


def test_client_payload_examples_do_not_contain_real_secret_looking_values():
    text = _read("examples/client_payloads.json")
    forbidden_patterns = [
        r"sk_live_[A-Za-z0-9]{20,}",
        r"\bAKIA[A-Z0-9]{16}\b",
        r"github_pat_[A-Za-z0-9_]{40,}",
        r"\bxoxb-[A-Za-z0-9-]{20,}\b",
    ]

    for pattern in forbidden_patterns:
        assert re.search(pattern, text) is None


def test_package_check_script_is_listed_in_release_check():
    release_check = _read("scripts/release_check.py")

    assert "scripts/package_check.py" in release_check
