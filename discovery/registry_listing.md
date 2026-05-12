# ShadowGate MCP Registry Listing Draft

Name: ShadowGate MCP

Category: Security / MCP Gateway / Agent Firewall

Transport: Streamable HTTP

Endpoint:

https://YOUR_DOMAIN_OR_RAILWAY_URL/mcp

Description:

ShadowGate MCP is a defensive security gateway for AI agents. It scans MCP tool calls, MCP responses, MCP tool schemas, and MCP server manifests before agents trust or execute them. It detects prompt injection, leaked secret paths, risky command execution, suspicious filesystem access, and unknown or blocked MCP servers.

Core tools:

- scan_text
- gate_mcp_tool_call
- gate_mcp_response
- evaluate_mcp_transaction
- inspect_mcp_tool_call
- inspect_mcp_response
- inspect_tool_schema
- review_mcp_manifest
- scan_batch
- get_mcp_server_trust
- set_mcp_server_trust
- create_security_report

Best for:

- IT teams adopting AI agents
- MCP server security review
- Agent tool-call firewalling
- Shadow IT MCP control
- Prompt injection protection
