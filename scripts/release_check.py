from __future__ import annotations

import subprocess
from pathlib import Path


REQUIRED_FILES = [
    "Dockerfile",
    "Procfile",
    ".env.example",
    ".gitignore",
    ".dockerignore",
    "README.md",
    "DEPLOY_RAILWAY.md",
    "RELEASE_CHECKLIST.md",
    "SECURITY.md",
    "LICENSE",
    "smithery.yaml",
    ".github/workflows/ci.yml",
    "pyproject.toml",
    "requirements.txt",
    "scripts/smoke_check.py",
    "scripts/production_check.py",
    "scripts/validate_discovery.py",
    "scripts/public_api_check.py",
    "scripts/package_check.py",
    "discovery/shadowgate_manifest.json",
    "discovery/client_connection_examples.json",
    "discovery/agent_routing_policy.json",
    "docs/HOSTED_DEMO.md",
    "docs/CONNECT.md",
    "docs/CLIENT_CONFIGS.md",
    "docs/AGENT_USAGE.md",
    "docs/SECURITY_MODEL.md",
    "docs/TOOL_SURFACE.md",
    "docs/PAYMENT_XPAY.md",
    "RELEASE_NOTES.md",
]


def fail(message: str) -> None:
    raise SystemExit(f"RELEASE CHECK FAILED: {message}")


def run(cmd: list[str]) -> None:
    print("running:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        fail("command failed: " + " ".join(cmd))


def main() -> None:
    print("=== ShadowGate Release Check ===")

    for file in REQUIRED_FILES:
        path = Path(file)
        print("checking:", file)
        if not path.exists():
            fail(f"missing file: {file}")
        if path.stat().st_size <= 0:
            fail(f"empty file: {file}")

    run(["python", "-m", "py_compile", "shadowgate/server.py", "shadowgate/cli.py", "shadowgate/auth.py"])
    run(["pytest"])
    run(["python", "scripts/smoke_check.py"])
    run(["python", "scripts/production_check.py"])
    run(["python", "scripts/validate_discovery.py"])
    run(["python", "scripts/public_api_check.py"])
    run(["python", "scripts/package_check.py"])

    print("RELEASE CHECK PASSED")


if __name__ == "__main__":
    main()
