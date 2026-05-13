# Deploy ShadowGate MCP to Railway

## Hosted Demo Status

| Item | Value |
|---|---|
| Railway deployment | live |
| MCP endpoint | https://web-production-62b0d.up.railway.app/mcp |
| Auth | client_key / admin_key required for protected tools |
| health_check | public |

## Required environment variables

SHADOWGATE_HOST=0.0.0.0
SHADOWGATE_DATA_DIR=/data
SHADOWGATE_ADMIN_KEY=change-this-admin-key
SHADOWGATE_CLIENT_KEY=change-this-client-key
SHADOWGATE_AUDIT_MAX_EVENTS=10000
SHADOWGATE_AUDIT_RETENTION_DAYS=30
SHADOWGATE_RATE_LIMIT_PER_MINUTE=120
SHADOWGATE_RATE_LIMIT_BURST=20

Railway provides PORT automatically.

Use strong non-placeholder admin and client keys before exposing the endpoint.
If Railway persistent volumes are available, mount one at /data so policy,
registry, and audit files survive deploys.

## Start command

python -m shadowgate.server

## MCP endpoint

Live demo endpoint (Railway):

```
https://web-production-62b0d.up.railway.app/mcp
```

For your own deployment, replace with your Railway app URL:

```
https://YOUR-RAILWAY-APP.up.railway.app/mcp
```

## Test locally before deploy

pytest
python scripts/smoke_check.py
python scripts/production_check.py
python scripts/validate_discovery.py

## Test after deploy

Open the hosted MCP URL in an MCP-compatible client:

```
https://web-production-62b0d.up.railway.app/mcp
```

Or your own deployment URL. Then call:

health_check
scan_text
gate_mcp_tool_call
gate_mcp_response

If SHADOWGATE_CLIENT_KEY is set, pass client_key to scan/gateway tools.

If SHADOWGATE_ADMIN_KEY is set, pass admin_key to admin tools.

## Production hardening

- Keep SHADOWGATE_ADMIN_KEY and SHADOWGATE_CLIENT_KEY private.
- Rotate keys if they are exposed.
- Set SHADOWGATE_DATA_DIR=/data and use persistent storage.
- Do not commit audit logs.
- Keep the MCP endpoint private or protected where possible.
- Call create_security_report periodically.
- Check health_check or get_security_config for production_warnings.

## Recommended public tools

For agents, prefer these tools:

- analyze_text
- gate_mcp_tool_call
- gate_mcp_response
- evaluate_mcp_transaction
- review_mcp_manifest
- get_mcp_server_trust
- create_security_report

Compatibility tools remain available, but analyze_text is preferred over separate scan/score/redact tools.
