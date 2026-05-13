import subprocess
import sys


def test_agent_to_agent_demo_runs_successfully():
    result = subprocess.run(
        [sys.executable, "examples/agent_to_agent_demo.py"],
        check=True,
        capture_output=True,
        text=True,
    )

    output = result.stdout.lower()

    assert "safe risky call" in output
    assert "allow_with_warning" in output
    assert "dangerous call" in output
    assert "blocked" in output or "block" in output
    assert "malicious response" in output
    assert "manifest review" in output
    assert "trust identity" in output
