# Deploy ShadowGate MCP to Railway

## Required environment variables

SHADOWGATE_HOST=0.0.0.0
SHADOWGATE_DATA_DIR=/data
SHADOWGATE_ADMIN_KEY=change-this-admin-key
SHADOWGATE_CLIENT_KEY=change-this-client-key

Railway provides PORT automatically.

## Start command

python -m shadowgate.server

## MCP endpoint

https://YOUR-RAILWAY-APP.up.railway.app/mcp

## Test locally before deploy

pytest
python scripts/smoke_check.py
python scripts/production_check.py
python scripts/validate_discovery.py

## Test after deploy

Open the hosted MCP URL in an MCP-compatible client:

https://YOUR-RAILWAY-APP.up.railway.app/mcp

Then call:

health_check
scan_text
gate_mcp_tool_call
gate_mcp_response

If SHADOWGATE_CLIENT_KEY is set, pass client_key to scan/gateway tools.

If SHADOWGATE_ADMIN_KEY is set, pass admin_key to admin tools.


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
