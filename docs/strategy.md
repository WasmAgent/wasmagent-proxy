# Strategy

## Market context (2026)

MCP gateways are a crowded category. Kong, TrueFoundry, Lunar.dev (MCPX), Lasso
Security, and Composio all ship production MCP gateway products with:
- Identity-aware routing and tool-level RBAC
- Real-time PII redaction
- Tool reputation scoring

Competing on general gateway features is not viable. wasmagent-proxy must occupy
a specific gap these products don't fill.

## MCP 2026-07-28: the protocol shift that creates our window

The MCP final spec (2026-07-28) introduces two features that commercial gateways
treat as routing infrastructure — and that we should treat as a security
inspection surface:

**MCP-Method** and **MCP-Name** headers: Akamai has specifically warned that
developers may accidentally map secrets or PII into these headers (using them as
generic metadata), creating a class of credential/PII leakage that standard API
gateways are not looking for.

This is a concrete, named, industry-acknowledged risk that commercial gateways
are NOT solving as of this writing. `classify_mcp_headers()` is our answer —
it is implemented, tested (20+ unit tests), and surfaced in the AEP evidence
record via the `McpHeaderRisk` struct.

The same spec shift also moves from stateful sessions to a stateless/handle
model. For wasmagent-proxy this is largely neutral: `x-b3-traceid` and
`x-agent-id` remain valid per-request correlation headers; the semantics of
"conversation-scoped evidence" just shifts to caller-supplied `x-agent-id`.
See `docs/mcp-protocol-compatibility.md` for the full mapping.

## Positioning: audit layer, not auth layer

**We are not competing with OAuth 2.1 + audience-bound token + PKCE gateways.**
Microsoft's official MCP security guidance mandates this identity layer. We
complement it: the identity layer decides "is this caller authorized?" — we
record "what did this caller do, signed and verifiable post-hoc?"

This should be made explicit in architecture documentation. Users who deploy
wasmagent-proxy alongside an identity-aware gateway get defense in depth.
Users who replace their identity layer with wasmagent-proxy are misusing it.

## Capability boundary (must be stated, not hidden)

wasmagent-proxy is a network-layer tool. It cannot observe:
- Endpoint-local MCP servers (running on a developer's machine)
- Traffic that bypasses the proxy
- Content inside TLS unless TLS termination is at this proxy

This is not a weakness to hide — it is a clear boundary that builds trust.
Users who understand the boundary can use the tool correctly. The complementary
endpoint-layer evidence tool is `@wasmagent/aep` in wasmagent-js.

## Priority order
1. Fix EvidenceFilter classification bug (issue #23) — credibility prerequisite
2. Adequate test coverage for recording.rs, prov.rs, filter.rs — no enterprise
   will evaluate an Ed25519 signing module with zero tests
3. `classify_mcp_headers()` — MCP-Method/MCP-Name leakage detection (implemented
   with 20+ unit tests; continue hardening as first-class API)
4. Document capability boundary and relationship to auth layers explicitly
   (completed: `docs/architecture.md` and `docs/deployment-model.md` cover this)
5. Phase 5 production hardening (serialization, Prometheus, ring buffer)
