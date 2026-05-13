# ShadowGate MCP — Hosted Demo

## Status

| Item | Value |
|---|---|
| Railway deployment | live |
| MCP endpoint | https://web-production-62b0d.up.railway.app/mcp |
| Version | 0.4.0-hardened |
| Auth | client_key / admin_key required for protected tools |
| health_check | public — no key needed |

## Connect

MCP transport: Streamable HTTP

Endpoint:

```
https://web-production-62b0d.up.railway.app/mcp
```

## Verify the server is live

Call `health_check` — no key required:

```json
{}
```

Expected response includes:

```json
{
  "ok": true,
  "version": "0.4.0-hardened",
  "hosted_mode": true
}
```

## Public tools (no key required)

- `health_check` — server status, version, production warnings
- `get_security_config` — security config and warnings (no raw keys exposed)

## Client-key-protected tools

Pass `client_key` to all scan and gateway tools when `SHADOWGATE_CLIENT_KEY` is configured:

- `analyze_text`
- `gate_mcp_tool_call`
- `gate_mcp_response`
- `evaluate_mcp_transaction`
- `review_mcp_manifest`
- `get_mcp_server_trust`
- `scan_text`, `scan_batch`, `redact_secrets`, `get_risk_score`

## Admin-key-protected tools

Pass `admin_key` for registry and audit tools:

- `set_mcp_server_trust`
- `approve_mcp_manifest_identity`
- `get_server_registry`
- `get_audit_summary`
- `get_recent_audit_events`
- `create_security_report`
- `set_policy_mode`

## Auth notes

- Do not share or commit your `client_key` or `admin_key`.
- Keys are passed as tool parameters, not HTTP headers.
- The server never exposes raw key values — only SHA256 fingerprints.

## Running your own instance

Deploy ShadowGate to Railway or any Docker-compatible host. See:

- `DEPLOY_RAILWAY.md` — full deployment guide
- `docs/CLIENT_CONFIGS.md` — client configuration templates
- `.env.example` — all supported environment variables
