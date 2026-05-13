# ShadowGate MCP Tool Surface

ShadowGate has two layers:

1. Public agent-facing tools
2. Compatibility and diagnostic tools

The internal code may have many functions, but agents should be guided toward a small, professional tool surface.

## Recommended public tools

These are the main tools agents and MCP hosts should use.

### health_check

Use to verify ShadowGate is alive and to inspect available tools.

### analyze_text

Use for general text safety analysis.

This is the preferred replacement for older separate tools:

- scan_text
- redact_secrets
- get_risk_score
- decide_policy
- simulate_policy_modes

### gate_mcp_tool_call

Use before an agent executes a tool call from another MCP server.

### gate_mcp_response

Use before an agent trusts or shows a response from another MCP server.

### evaluate_mcp_transaction

Use when both the outgoing tool call and incoming response are available.

### review_mcp_manifest

Use before approving or connecting a new MCP server.

### get_mcp_server_trust

Use to check whether an MCP server is trusted, untrusted, monitored, or blocked.

## Admin tools

These tools are mainly for humans, IT admins, or agent-platform administrators.

### set_policy_mode

Change ShadowGate policy mode.

### set_mcp_server_trust

Set a server as trusted, untrusted, monitor, or blocked.

### approve_mcp_manifest_identity

Approve and persist a reviewed MCP manifest identity baseline for drift detection.

### get_server_registry

Read the MCP server trust registry.

### create_security_report

Generate a compact security report from audit logs.

### get_security_config

Check admin/client auth configuration without exposing raw keys.

### get_data_paths

Check storage paths for policy, registry, and audit logs.

## Compatibility tools

These remain available for backward compatibility and testing, but are not the preferred public API.

- scan_text
- redact_secrets
- get_risk_score
- decide_policy
- simulate_policy_modes
- inspect_mcp_tool_call
- inspect_mcp_response
- inspect_tool_schema
- scan_batch

## Recommended agent flow

For normal agent operation:

1. Use gate_mcp_tool_call before executing external MCP tools.
2. Use gate_mcp_response before trusting external MCP responses.
3. Use evaluate_mcp_transaction when reviewing both sides together.
4. Use review_mcp_manifest before onboarding a new MCP server.
5. Use analyze_text for general text safety checks.

## Decision meaning

allow:
The agent can continue.

allow_with_warning:
The agent should continue only if policy allows or a human approves.

redact:
The agent should use only the redacted output.

block:
The agent should stop.

block_auth:
The agent did not provide a valid ShadowGate key.
