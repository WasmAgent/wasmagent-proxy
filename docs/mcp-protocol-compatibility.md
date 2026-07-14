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
| Header leakage risk | N/A | MCP-Method / MCP-Name may contain leaked secrets | **New**: `classify_mcp_headers()` detects credential/PII leakage |

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
The filter calls [`classify_mcp_headers()`](../crates/proxy-wasm-evidence/src/recorder.rs)
on every request and, if a risk is detected, sets
`x-aep-mcp-header-risk` to a JSON representation of the `McpHeaderRisk` struct
on the response.

### Detection heuristics

`classify_mcp_headers()` checks MCP-Method first, then MCP-Name, and returns
the first detected risk. Each header value is examined for:

| Pattern | Detection logic | Example trigger |
|---|---|---|
| Credential prefix | Value starts with `ghp_`, `sk-`, or `Bearer ` (case-insensitive, after trimming) | `ghp_abc123`, `sk-proj-xxx`, `Bearer eyJ...` |
| High-entropy string | Value length > 32 characters | A 40-character JWT or API token |
| Email-like pattern | Value matches `local@domain.tld` structure (characters before `@`, a `.` in the domain part) | `user@example.com` |

### Response header format

When a risk is detected, the filter sets:

```
x-aep-mcp-header-risk: {"has_credential_prefix":true,"is_high_entropy":false,"is_email_like":false,"source_header":"MCP-Method","value_snippet":"ghp_abc123..."}
```

The `value_snippet` field contains the first 40 characters of the risky value
(enough for forensics without exposing the full secret across intermediary hops).

### No risk

When both MCP-Method and MCP-Name values appear benign (or are absent), no
`x-aep-mcp-header-risk` header is set. The filter produces a normal AEP
evidence record without the `mcp_header_risk` field populated.

## Capability boundary

wasmagent-proxy can only inspect traffic that passes through it as a Proxy-Wasm
filter. It cannot observe:

- Endpoint-local MCP servers (running on a developer machine)
- Traffic that bypasses the proxy (direct MCP server connections)
- Content inside TLS-encrypted payloads if TLS termination is upstream

For endpoint-layer evidence, see [agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra).
