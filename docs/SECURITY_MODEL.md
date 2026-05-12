# ShadowGate Security Model

ShadowGate is a defensive MCP security gateway.

## What ShadowGate protects

- Prompt injection attempts
- Sensitive file path leakage
- Secret and credential patterns
- Risky command execution patterns
- MCP tool schema risk
- MCP manifest risk
- Unknown or blocked MCP servers
- Unsafe MCP responses before the agent trusts them

## What ShadowGate does not claim

ShadowGate does not prove that a server is safe forever.
ShadowGate does not replace full sandboxing.
ShadowGate does not guarantee detection of every malicious prompt.
ShadowGate does not execute external tools itself.

## Recommended deployment

For hosted/public usage, set:

SHADOWGATE_CLIENT_KEY
SHADOWGATE_ADMIN_KEY
SHADOWGATE_DATA_DIR
SHADOWGATE_HOST=0.0.0.0

## Auth model

Client key:
Used by normal scan and gateway tools.

Admin key:
Used by policy, registry, audit, and reporting tools.

## Trust registry

Server trust levels:

trusted:
Approved, but still scanned.

untrusted:
Default for unknown MCP servers. Should trigger warning.

monitor:
Allowed with monitoring/warning behavior.

blocked:
Should be blocked.
