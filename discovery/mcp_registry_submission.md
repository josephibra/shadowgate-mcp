# ShadowGate MCP — MCP Registry Submission Draft

This file is a draft submission for the official MCP server registry at
https://github.com/modelcontextprotocol/servers

Review and adjust formatting to match the registry's current contribution guidelines
before submitting a pull request.

---

## Server Entry

**Name:** ShadowGate MCP

**Slug:** shadowgate-mcp

**Version:** 0.4.0-hardened

**Description:**
Defensive security gateway and firewall for AI agents using MCP servers.
Scans MCP tool calls, responses, schemas, and server manifests for prompt injection,
leaked secrets, dangerous shell commands, risky capabilities, and untrusted servers.
Supports server trust registry, manifest identity baseline, capability assessment,
and audit-based security reporting.

**Category:** security / agent safety / MCP gateway

**License:** MIT

**Maintainer:** josephibra (https://github.com/josephibra)

**GitHub repository:** https://github.com/josephibra/shadowgate-mcp

**Release tag:** shadowgate-v0.4.0-hardened

---

## Hosted Endpoint

**Transport:** Streamable HTTP

**MCP endpoint:** https://web-production-62b0d.up.railway.app/mcp

**Auth model:**
- `health_check` and `get_security_config` are public — no key required.
- Scan and gateway tools require `client_key` when `SHADOWGATE_CLIENT_KEY` is configured.
- Admin tools (policy, registry, audit, reports) require `admin_key` when `SHADOWGATE_ADMIN_KEY` is configured.
- Without any keys configured, the server runs in open development mode.

---

## Recommended Public Tools

| Tool | Description |
|---|---|
| `health_check` | Server status, version, active policy, production warnings. No key required. |
| `analyze_text` | Primary text safety analysis. Scans for injection, secrets, risky commands. |
| `gate_mcp_tool_call` | Gateway check for an outgoing MCP tool call before execution. |
| `gate_mcp_response` | Gateway check for an MCP response before delivery to the agent. |
| `evaluate_mcp_transaction` | Evaluate both sides of an MCP tool call and response together. |
| `review_mcp_manifest` | Review a new MCP server manifest for risk and identity baseline. |
| `get_mcp_server_trust` | Query the trust level for a known MCP server. |
| `set_mcp_server_trust` | Admin: set trust level for an MCP server. |
| `approve_mcp_manifest_identity` | Admin: approve a reviewed server manifest as baseline. |
| `create_security_report` | Admin: generate a security report from audit events. |
| `get_security_config` | Show security config and production warnings. No raw keys exposed. |

---

## Security Model Summary

ShadowGate MCP is a defensive scanning gateway, not a sandbox.

- Inspects MCP tool calls, responses, schemas, and server manifests for known risk patterns.
- Detects prompt injection, leaked API keys, dangerous shell commands, sensitive file paths,
  risky network callbacks, credential access, and other OWASP-aligned risk categories.
- Normalises and decodes text variants (base64, URL-encoding, HTML entities, zero-width chars)
  to detect obfuscation-based bypass attempts.
- Classifies tool capabilities (shell, filesystem, credentials, payments, deployment, etc.)
  and flags those requiring human approval.
- Maintains a per-server trust registry with trust levels: trusted / untrusted / monitor / blocked.
- Stores audit events as SHA256 hashes — never raw scanned text.
- Does not replace MCP host enforcement, network controls, or OS-level isolation.

---

## Required Environment Variables for Self-Hosting

| Variable | Required | Description |
|---|---|---|
| `SHADOWGATE_HOST` | Yes | Set to `0.0.0.0` for hosted/Docker deployments |
| `PORT` | Yes | Provided automatically by Railway and most platforms |
| `SHADOWGATE_DATA_DIR` | Recommended | Persistent data directory, e.g. `/data` |
| `SHADOWGATE_ADMIN_KEY` | Recommended | Admin key for protected tools. Leave empty for dev mode. |
| `SHADOWGATE_CLIENT_KEY` | Recommended | Client key for scan/gateway tools. Leave empty for dev mode. |
| `SHADOWGATE_AUDIT_MAX_EVENTS` | Optional | Max audit events to retain (e.g. 10000) |
| `SHADOWGATE_AUDIT_RETENTION_DAYS` | Optional | Audit retention window in days (e.g. 30) |
| `SHADOWGATE_RATE_LIMIT_PER_MINUTE` | Optional | In-process rate limit per minute (e.g. 120) |
| `SHADOWGATE_RATE_LIMIT_BURST` | Optional | Burst allowance (e.g. 20) |

---

## Deployment

- **Docker:** Dockerfile included. Builds on Python 3.12-slim.
- **Railway:** Procfile and DEPLOY_RAILWAY.md included. One-click compatible.
- **Local:** `pip install -e .` then `python -m shadowgate.server`

---

## Connection Example

```json
{
  "name": "ShadowGate MCP",
  "transport": "streamable-http",
  "url": "https://web-production-62b0d.up.railway.app/mcp"
}
```

For self-hosted:

```json
{
  "name": "ShadowGate MCP",
  "transport": "streamable-http",
  "url": "https://YOUR_DOMAIN/mcp"
}
```
