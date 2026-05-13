# ShadowGate MCP — Pricing Model

This document proposes a starter pricing model for the hosted ShadowGate MCP endpoint once
XPay/x402 payment integration is active.

These are illustrative starting points. Final prices must be calibrated against real usage costs,
Railway hosting costs, and demand after deployment.

---

## Tiers

### Free (Self-Hosted)

Available to anyone running their own instance:

- Local development (`python -m shadowgate.server`)
- Docker deployment
- Personal Railway deployment
- Any private or enterprise self-hosted deployment

The open-source repository is MIT-licensed and will remain freely available at:
https://github.com/josephibra/shadowgate-mcp

### Hosted Free Trial / Beta

During beta, the hosted endpoint may offer:

- Free usage with no payment proxy active.
- Rate-limited access (e.g. 120 calls/minute) without a client key.
- Public `health_check` and `get_security_config` always free.

This allows agents and developers to test integration before committing to paid usage.

### Hosted Paid (via XPay Proxy)

Usage-based per-call pricing. No subscription required.

| Tool | Suggested Price | Tier |
|---|---|---|
| `health_check` | Free | Always public |
| `get_security_config` | Free | Always public |
| `analyze_text` | Low | High-volume lightweight scan |
| `gate_mcp_tool_call` | Low | High-volume gateway check |
| `gate_mcp_response` | Low | High-volume gateway check |
| `evaluate_mcp_transaction` | Medium | Two-sided call + response evaluation |
| `review_mcp_manifest` | Higher | Deep manifest analysis, identity baseline |
| `create_security_report` | Higher | Audit event processing, report generation |
| Admin tools | Included with admin key | Not available via payment proxy |

---

## Pricing Rationale

**Low-priced tools** (`analyze_text`, `gate_mcp_tool_call`, `gate_mcp_response`):
- Called on every MCP interaction in an active agent loop.
- Must be cheap enough that security scanning is not skipped for cost reasons.
- Revenue comes from volume, not per-call margin.

**Medium-priced tools** (`evaluate_mcp_transaction`):
- Combines tool call + response evaluation in a single call.
- Slightly heavier computation than individual gateway checks.

**Higher-priced tools** (`review_mcp_manifest`, `create_security_report`):
- Called infrequently — on new server onboarding or periodic review.
- More complex processing: manifest parsing, identity baseline, audit event aggregation.
- Higher value per call justifies higher per-call price.

---

## Usage-Based Model

Usage-based pricing aligns cost with value and removes friction for low-volume users:

- No monthly minimum.
- Agents pay only for calls they make.
- Easy to model cost against expected call volume before committing.
- Scales naturally as agent usage grows.

---

## Notes for Operators

- Prices listed here are illustrative. Adjust after measuring real Railway compute costs.
- The payment proxy (XPay or x402-compatible) controls actual billing — ShadowGate has no
  knowledge of prices or payment state.
- Admin tools should remain behind `SHADOWGATE_ADMIN_KEY`, not exposed via the payment proxy.
- `health_check` must remain public regardless of pricing configuration.
