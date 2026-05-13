# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Reporting a Vulnerability

Report security issues by email to the maintainer listed in `pyproject.toml`. Do not open a public GitHub issue for security vulnerabilities.

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if known

Do not include real API keys, credentials, or production data in your report.

You should receive a response within 7 days. If the issue is confirmed, a patch will be prioritised and released as a new version.

## Security Model Limitations

ShadowGate MCP is a defensive scanning gateway, not a sandbox.

- It inspects MCP tool calls, responses, schemas, and server manifests for known risk patterns.
- It does not prevent an MCP host from executing a tool call it has approved.
- It does not replace network controls, OS-level isolation, or MCP host enforcement.
- Pattern detection can be bypassed by sufficiently novel obfuscation not covered by current rules.
- Rate limiting is in-process and applies per server instance, not globally across replicas.

## Hosted Deployment Requirements

For any public or hosted deployment:

- Set `SHADOWGATE_ADMIN_KEY` to a strong, randomly generated value.
- Set `SHADOWGATE_CLIENT_KEY` to a strong, randomly generated value.
- Mount a persistent volume at `SHADOWGATE_DATA_DIR` (default `/data`) so audit logs survive restarts.
- Do not commit audit logs, policy files, or registry files containing real operational data.
- Rotate keys immediately if they are exposed.
- Call `create_security_report` periodically and review `health_check` for `production_warnings`.
- Keep the MCP endpoint private or behind authentication where possible.

## Audit Log Privacy

Audit logs store SHA256 hashes of scanned text, not the raw text content. This prevents sensitive data from accumulating in log files.
