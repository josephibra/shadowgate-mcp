# Payment Integration — XPay / x402

This document describes the intended future payment integration for hosted ShadowGate MCP deployments.

## Status

Not yet implemented. This is a planned optional feature for monetising access to a hosted ShadowGate MCP endpoint.

No wallet addresses, payment keys, or real credentials are included here.

## Intended Flow

```
User or Agent
    |
    v
XPay / x402 Payment Proxy  <-- payment check happens here
    |
    v  (on successful payment or valid session token)
ShadowGate MCP (Railway hosted URL)
    |
    v
MCP tool response
```

The payment proxy sits in front of the Railway-hosted MCP URL. Users or agents must satisfy the payment requirement before the proxy forwards their request to ShadowGate.

## Prerequisites

1. Deploy ShadowGate to Railway and note the Railway URL:
   ```
   https://YOUR-APP.up.railway.app/mcp
   ```
   See `DEPLOY_RAILWAY.md` for deployment instructions.

2. Sign up for an XPay or x402-compatible payment proxy service.

3. Configure the proxy to forward authenticated requests to your Railway MCP URL.

4. Publish the payment proxy URL (not the raw Railway URL) as the public MCP endpoint.

## x402 Protocol Notes

x402 is an HTTP payment protocol that allows servers to request payment for API access using the HTTP 402 Payment Required status code. Agents that support x402 can automatically handle payment flows.

When integrated:
- Public endpoint returns HTTP 402 with payment details if no valid payment is present.
- After payment, the proxy adds an authorisation header or token forwarded to ShadowGate.
- ShadowGate's `SHADOWGATE_CLIENT_KEY` can be set to a proxy-generated token for additional security.

## Configuration Steps (future)

1. Set `SHADOWGATE_CLIENT_KEY` on Railway to a value known only to the payment proxy.
2. Point the payment proxy target to `https://YOUR-APP.up.railway.app/mcp`.
3. Expose the proxy URL in `discovery/shadowgate_manifest.json` as `production_url`.
4. Update `smithery.yaml` with the payment proxy URL if listing on Smithery.

## No Secrets in This File

Do not commit real wallet addresses, API keys, or payment credentials to this file or any file in this repository.
