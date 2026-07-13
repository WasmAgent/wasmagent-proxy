# MCP Protocol Compatibility

## Scope

wasmagent-proxy is a Proxy-Wasm HTTP filter that records AEP evidence for MCP traffic.
This document describes what the filter assumes about the MCP protocol, what changed
in the MCP 2026-07-28 specification, and how the filter handles each change.

## Protocol assumptions

| Assumption | Pre-2026-07-28 | MCP 2026-07-28+ | Filter status |
|---|---|---|---|
| Session tracking | Stateful session via x-b3-traceid | Stateless; portable 'handle' per request | Trace ID still usable per-request; session-spanning correlation is now client-side |
| Request identification | x-b3-traceid / x-agent-id headers | Same headers still valid; handle is transport-level | No change required |
| MCP operation type | Inferred from HTTP method + path | MCP-Method header explicitly names the operation | **Extended**: filter now reads MCP-Method and classifies accordingly |
| Tool call vs. list | Not distinguishable from HTTP method alone | MCP-Method = tools/call vs. tools/list | **Extended**: tools/call → MutateExternal; tools/list → Read |
| Header leakage risk | N/A | MCP-Method / MCP-Name may contain leaked secrets | **New**: classify_mcp_headers() detects credential/PII leakage |

## x-b3-traceid under the stateless model

Under MCP 2026-07-28, the protocol no longer maintains long-lived sessions.
Each request carries an independent context. x-b3-traceid remains useful for
per-request evidence correlation but no longer represents a conversation scope.

**Impact**: AEP EvidenceBundle records associated via trace_id now represent
single-request evidence, not conversation evidence. Multi-request conversation
evidence requires the caller to supply a stable x-agent-id across requests.

**Action taken**: No code change; documented above. The filter continues to
read both x-b3-traceid and x-agent-id and includes them in evidence records.

## MCP-Method header (new in 2026-07-28)

The spec introduces MCP-Method (e.g. tools/call, tools/list, resources/read).

The filter reads this header and uses it in infer_side_effect_class_with_mcp():

| MCP-Method value | SideEffectClass |
|---|---|
| tools/call | MutateExternal (tool invocation can have external effects) |
| tools/list | Read |
| resources/list, resources/read | Read |
| prompts/list, prompts/get | Read |
| completion/complete | Read |
| (other / unknown) | Unknown |

When MCP-Method is absent (pre-2026-07-28 traffic), the HTTP method + path
heuristic is used as before.

## MCP-Name header leakage detection (new in 2026-07-28)

Akamai identified that developers may accidentally map secrets or PII into
MCP-Method or MCP-Name headers (e.g. using them as generic metadata headers).

The filter calls classify_mcp_headers() on every request and, if a risk is
detected, sets x-aep-mcp-header-risk: critical|high on the response.

Detection patterns:
- Credential prefixes: ghp_, sk-, Bearer, token, api_ (case-insensitive)
- High-entropy strings: longest alphanumeric run >= 32 chars
- PII: email address pattern in MCP-Name (contains @ and .)

## Capability boundary

wasmagent-proxy can only inspect traffic that passes through it as a Proxy-Wasm
filter. It cannot observe:

- Endpoint-local MCP servers (running on a developer machine)
- Traffic that bypasses the proxy (direct MCP server connections)
- Content inside TLS-encrypted payloads if TLS termination is upstream

For endpoint-layer evidence, see agent-trust-infra's @wasmagent/aep package.
