# ShadowGate MCP Release Checklist

## Local checks

- pytest passes
- smoke_check passes
- production_check passes
- validate_discovery passes
- Dockerfile exists
- Procfile exists
- .env.example exists
- discovery package exists
- docs package exists

## Security checks

- SHADOWGATE_ADMIN_KEY supported
- SHADOWGATE_CLIENT_KEY supported
- SHADOWGATE_DATA_DIR supported
- server binds with SHADOWGATE_HOST=0.0.0.0
- PORT env supported
- audit logs do not store raw scanned text

## Deployment checks

- Railway env variables prepared
- MCP endpoint is /mcp
- data dir is /data
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
