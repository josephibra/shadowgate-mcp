# ShadowGate MCP Release Checklist

## Local checks

- pytest -q
- python scripts/smoke_check.py
- python scripts/production_check.py
- python scripts/validate_discovery.py
- python scripts/public_api_check.py
- python scripts/release_check.py
- python examples/agent_to_agent_demo.py
- Dockerfile exists
- Procfile exists
- .env.example exists
- discovery package exists
- docs package exists

## Security checks

- SHADOWGATE_ADMIN_KEY supported
- SHADOWGATE_CLIENT_KEY supported
- SHADOWGATE_DATA_DIR supported
- SHADOWGATE_AUDIT_MAX_EVENTS supported
- SHADOWGATE_AUDIT_RETENTION_DAYS supported
- SHADOWGATE_RATE_LIMIT_PER_MINUTE supported
- SHADOWGATE_RATE_LIMIT_BURST supported
- server binds with SHADOWGATE_HOST=0.0.0.0
- PORT env supported
- audit logs do not store raw scanned text
- health_check reports production warnings without raw keys
- get_security_config does not expose raw keys

## Deployment checks

- Railway env variables prepared
- MCP endpoint is /mcp
- data dir is /data
- persistent volume configured if platform supports it
- endpoint kept private or protected where possible
- create_security_report monitored periodically
- keys rotated if exposed
- hosted URL added to discovery docs after deploy

## Current release

0.3.8-public-surface


## Public surface checks

- analyze_text exists
- recommended public tools are documented
- compatibility tools are documented
- public_api_check passes
- discovery manifest includes recommended_public_tools
- discovery manifest includes compatibility_tools
