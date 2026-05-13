# ShadowGate MCP — Passive Discovery and Monetization Platforms

This document lists platforms where ShadowGate MCP can be passively listed or distributed
to reach AI developers, MCP users, and security-conscious agent builders.

Passive means: listed once, then surfaces organically through search and browsing.
No active campaign or ongoing effort required after initial setup.

---

## Essential Platforms

### GitHub

**URL:** https://github.com/josephibra/shadowgate-mcp

**Role:** Source of truth, credibility, and discoverability.

- Public repo is required for Smithery and MCP Registry listings.
- GitHub search indexes README keywords — AI, MCP, security, gateway, firewall, agent.
- Stars and watchers signal legitimacy to other developers.
- Issues and PRs provide a public feedback channel.

**Status:** Live.

---

### Railway

**URL:** https://web-production-62b0d.up.railway.app/mcp

**Role:** Hosted MCP endpoint — makes ShadowGate usable without self-hosting.

- Provides a live `health_check` URL for listings that require a working demo.
- `DEPLOY_RAILWAY.md` makes it easy for others to deploy their own instance.
- Persistent volume at `/data` ensures audit logs and registry survive restarts.

**Status:** Live.

---

### Smithery

**URL:** https://smithery.ai

**Role:** Primary MCP server registry and discovery platform.

- MCP-specific directory — directly reaches the target audience.
- Requires `smithery.yaml` in the repository root (already present).
- Lists tools, transport type, auth model, and hosted endpoint.
- See `smithery.yaml` and `docs/PUBLISHING.md` for submission checklist.

**Status:** Not yet submitted. Ready to submit — see docs/PUBLISHING.md.

---

### MCP Registry (modelcontextprotocol/servers)

**URL:** https://github.com/modelcontextprotocol/servers

**Role:** Official MCP server list maintained by the MCP project.

- High credibility — the canonical list from the protocol maintainers.
- Submission is a pull request to the registry repository.
- Draft submission ready: `discovery/mcp_registry_submission.md`.

**Status:** Not yet submitted. Draft ready — see discovery/mcp_registry_submission.md.

---

### XPay

**URL:** https://x.com/XPayOfficial (or current official XPay/x402 docs)

**Role:** Optional payment proxy for monetising the hosted endpoint.

- Places a payment gate in front of the Railway MCP endpoint.
- Enables per-call usage-based billing for hosted tool access.
- Does not affect free/self-hosted usage.
- See `docs/PAYMENT_XPAY.md` and `docs/PRICING_MODEL.md` for integration plan.

**Status:** Not yet integrated. Planned future feature.

---

## Optional Platforms

### XPack

**Role:** Optional MCP tool storefront / marketplace.

- If XPack lists individual MCP tools, ShadowGate's security-focused tools may appeal to
  enterprise agent builders.
- Listing would require a working hosted endpoint and documented tool surface.
- See `docs/TOOL_SURFACE.md` for the full tool list.

**Status:** Optional. Evaluate once core listings (Smithery, MCP Registry) are live.

---

### Product Hunt

**Role:** Launch platform for developer tools.

- A launch post reaches developers who follow AI tooling.
- One-time launch event, not a persistent listing.
- Best timed after Smithery and MCP Registry listings are live so there is a working
  endpoint and multiple discovery points to link.

**Status:** Optional. Not yet launched.

---

### Devpost

**Role:** Hackathon and project portfolio platform.

- Lists open-source projects and links to GitHub.
- Security / AI safety angle may resonate with hackathon audiences.
- Low effort to maintain once listed.

**Status:** Optional. Low priority relative to core MCP registries.

---

### Hacker News / Show HN

**Role:** Developer community discovery.

- A "Show HN" post reaches senior developers and security engineers.
- Works best when there is a live demo, working hosted endpoint, and clear value proposition.
- One-time post; organic upvotes drive traffic to the GitHub repo.

**Status:** Optional. Best timed after hosted endpoint is stable and listing is in Smithery.

---

### Reddit

**Relevant communities:**

- r/MachineLearning
- r/artificial
- r/LocalLLaMA
- r/programming
- r/netsec

**Role:** Community-driven discovery.

- Posts about open-source AI security tools reach active communities.
- Links to GitHub repo and hosted demo.
- Comments and upvotes provide organic distribution.

**Status:** Optional. Timing and community fit should be evaluated before posting.

---

## Platform Priority

| Platform | Priority | Status |
|---|---|---|
| GitHub | Essential | Live |
| Railway | Essential | Live |
| Smithery | Essential | Ready to submit |
| MCP Registry | Essential | Draft ready |
| XPay | Essential (future) | Planned |
| XPack | Optional | Evaluate later |
| Product Hunt | Optional | Post after core listings |
| Devpost | Optional | Low priority |
| Hacker News | Optional | Post after stable |
| Reddit | Optional | Post after stable |
