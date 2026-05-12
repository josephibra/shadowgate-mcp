from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


OUTPUT = Path("ai_context/SHADOWGATE_AI_CONTEXT.md")

INCLUDE_FILES = [
    "AI_HANDOFF.md",
    "README.md",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "Procfile",
    ".env.example",
    "DEPLOY_RAILWAY.md",
    "RELEASE_CHECKLIST.md",

    "shadowgate/__init__.py",
    "shadowgate/server.py",
    "shadowgate/scanner.py",
    "shadowgate/patterns.py",
    "shadowgate/policy.py",
    "shadowgate/registry.py",
    "shadowgate/auth.py",
    "shadowgate/audit.py",
    "shadowgate/storage.py",
    "shadowgate/cli.py",

    "tests/test_scanner.py",

    "scripts/smoke_check.py",
    "scripts/production_check.py",
    "scripts/validate_discovery.py",
    "scripts/public_api_check.py",
    "scripts/release_check.py",

    "discovery/shadowgate_manifest.json",
    "discovery/client_connection_examples.json",
    "discovery/agent_routing_policy.json",
    "discovery/registry_listing.md",

    "docs/CONNECT.md",
    "docs/CLIENT_CONFIGS.md",
    "docs/AGENT_USAGE.md",
    "docs/SECURITY_MODEL.md",
    "docs/TOOL_SURFACE.md",
]


def language_for(path: str) -> str:
    if path.endswith(".py"):
        return "python"
    if path.endswith(".json"):
        return "json"
    if path.endswith(".toml"):
        return "toml"
    if path.endswith(".md"):
        return "markdown"
    if path.endswith("Dockerfile"):
        return "dockerfile"
    if path.endswith(".example"):
        return "bash"
    return "text"


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []

    lines.append("# ShadowGate MCP — Full AI Context Bundle")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("Purpose: upload this single markdown file to another AI when it needs to inspect the full MCP project without receiving a zip/tar.")
    lines.append("")
    lines.append("Recommended review order:")
    lines.append("")
    lines.append("1. AI_HANDOFF.md")
    lines.append("2. README.md")
    lines.append("3. docs/TOOL_SURFACE.md")
    lines.append("4. docs/SECURITY_MODEL.md")
    lines.append("5. shadowgate/server.py")
    lines.append("6. shadowgate/scanner.py")
    lines.append("7. scripts/public_api_check.py")
    lines.append("8. scripts/release_check.py")
    lines.append("")
    lines.append("## File index")
    lines.append("")

    for file in INCLUDE_FILES:
        exists = Path(file).exists()
        status = "OK" if exists else "MISSING"
        lines.append(f"- [{status}] `{file}`")

    lines.append("")
    lines.append("---")
    lines.append("")

    for file in INCLUDE_FILES:
        path = Path(file)

        lines.append(f"# FILE: {file}")
        lines.append("")

        if not path.exists():
            lines.append("MISSING FILE")
            lines.append("")
            continue

        content = path.read_text(encoding="utf-8", errors="replace")
        lang = language_for(file)

        lines.append(f"```{lang}")
        lines.append(content.rstrip())
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    print(f"created: {OUTPUT}")
    print(f"size_bytes: {OUTPUT.stat().st_size}")


if __name__ == "__main__":
    main()
