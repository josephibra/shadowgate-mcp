# ShadowGate MCP 0.4.0-hardened Release Notes

ShadowGate MCP 0.4.0-hardened is a public-ready defensive MCP gateway for AI agents and MCP hosts.

## Highlights

- Phase 1: policy category and risk scoring hardening.
- Phase 2: normalization and decoding scanner layer for URL, HTML, JSON string, zero-width, and selective base64 bypass detection.
- Phase 3: MCP capability classifier for risky tool capabilities.
- Phase 4: manifest fingerprinting, trust identity, drift detection, and admin approval baselines.
- Phase 5: stronger security report sections and adversarial bypass tests.
- Phase 6: agent-to-agent demo flow, client payload examples, and MCP host integration docs.
- Phase 7: production hardening checks for hosted auth, weak keys, persistent data directory, audit retention config, and rate-limit config hooks.

## Install And Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
python -m shadowgate.server
```

Local MCP endpoint:

```text
http://127.0.0.1:8000/mcp
```

## Demo

```bash
python examples/agent_to_agent_demo.py
```

The demo routes safe risky calls, dangerous calls, malicious responses, manifest review, and manifest approval through ShadowGate.

## Railway Deploy Notes

Set:

```text
SHADOWGATE_HOST=0.0.0.0
SHADOWGATE_DATA_DIR=/data
SHADOWGATE_ADMIN_KEY=<strong-admin-key>
SHADOWGATE_CLIENT_KEY=<strong-client-key>
SHADOWGATE_AUDIT_MAX_EVENTS=10000
SHADOWGATE_AUDIT_RETENTION_DAYS=30
SHADOWGATE_RATE_LIMIT_PER_MINUTE=120
SHADOWGATE_RATE_LIMIT_BURST=20
```

Railway provides `PORT` automatically. Use persistent storage for `/data` when available.

## Release Checks

```bash
pytest -q
python scripts/smoke_check.py
python scripts/production_check.py
python scripts/validate_discovery.py
python scripts/public_api_check.py
python scripts/release_check.py
python examples/agent_to_agent_demo.py
```

## Security Limitations

ShadowGate is not a sandbox. It does not execute external MCP tools itself and does not replace MCP host enforcement, OS isolation, network controls, or platform authorization.

ShadowGate does not prove an MCP server is safe forever. Use manifest approval and drift detection, monitor `create_security_report`, keep keys private, and protect hosted endpoints.
