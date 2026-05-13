# Payment Integration — XPay / x402

This document describes the intended future payment integration for hosted ShadowGate MCP deployments.

## Status

Not yet implemented. This is a planned optional feature for monetising access to a hosted ShadowGate MCP endpoint.

No wallet addresses, payment keys, or real credentials are included here.

---

## Monetization Flow

```
User or AI Agent
    |
    v
XPay / x402 Paid Proxy  <-- payment check happens here
    |
    v  (on successful payment or valid payment session token)
ShadowGate MCP (Railway hosted endpoint)
    |
    v
MCP tool response returned to agent
```

The payment proxy sits in front of the Railway-hosted MCP endpoint. Users or agents must satisfy the
payment requirement (via x402 or XPay session) before the proxy forwards the request to ShadowGate.

**Current live MCP URL (direct, no payment proxy yet):**

```
https://web-production-62b0d.up.railway.app/mcp
```

**Future paid proxy URL (once XPay is configured):**

```
https://<your-xpay-proxy>/mcp
```

The raw Railway URL becomes an internal backend URL once a payment proxy is placed in front.
Do not expose the raw Railway URL as the public endpoint once payment proxy is active.

---

## Why a Proxy, Not In-Process Payment

ShadowGate's MCP server handles security scanning, not payment processing. A separate proxy keeps
payment enforcement decoupled from the scanning logic and allows:

- Swapping payment providers without changing ShadowGate code.
- Running ShadowGate free and self-hosted while optionally monetising a hosted instance.
- Per-tool or per-call pricing configured entirely in the proxy layer.

---

## x402 Protocol Notes

x402 is an HTTP payment protocol using the HTTP 402 Payment Required status code. Agents that
support x402 can handle payment flows automatically.

When integrated:
- The public endpoint returns HTTP 402 with payment details if no valid payment is present.
- After payment, the proxy adds an authorisation header or token and forwards the request.
- ShadowGate's `SHADOWGATE_CLIENT_KEY` should be set to a proxy-generated token so the raw
  Railway endpoint cannot be reached without going through the proxy.

---

## Conceptual Per-Tool Pricing

Pricing is configured in the proxy layer, not in ShadowGate. Example conceptual tiers:

| Tool | Pricing tier | Reason |
|---|---|---|
| `health_check` | Free (no key required) | Discovery / status only |
| `analyze_text` | Low per-call | High-volume lightweight scan |
| `gate_mcp_tool_call` | Low per-call | High-volume gateway check |
| `gate_mcp_response` | Low per-call | High-volume gateway check |
| `evaluate_mcp_transaction` | Medium per-call | Two-sided evaluation |
| `review_mcp_manifest` | Higher per-call | Deep manifest analysis |
| `create_security_report` | Higher per-call | Audit-heavy, report generation |

Final prices must be calibrated against real usage after deployment.

---

## Free and Self-Hosted Option

Payment integration is optional and only applies to the hosted endpoint:

- Self-hosted instances (local, Docker, Railway private) remain completely free.
- The open-source repository stays publicly available at:
  https://github.com/josephibra/shadowgate-mcp
- `health_check` stays public and key-free on the hosted endpoint regardless of payment proxy.

---

## Configuration Steps (future)

1. Set `SHADOWGATE_CLIENT_KEY` on Railway to a strong value known only to the payment proxy.
2. Configure the XPay/x402 proxy to forward authenticated requests to:
   `https://web-production-62b0d.up.railway.app/mcp`
3. Expose the proxy URL (not the Railway URL) as the public MCP endpoint.
4. Update `discovery/shadowgate_manifest.json` `production_url` to the proxy URL.
5. Update `smithery.yaml` `hostedEndpoint` to the proxy URL if listing on Smithery.

---

## Security Warning for Publishers

- Do not commit real wallet addresses, payment credentials, or API keys to this repository.
- Do not expose `SHADOWGATE_ADMIN_KEY` or `SHADOWGATE_CLIENT_KEY` in any doc or config file.
- Once a payment proxy is active, treat the raw Railway URL as an internal secret.
- The `health_check` tool is designed to be public regardless of payment or auth configuration.
