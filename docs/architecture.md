# Architecture

## System diagram

```
                         HTTP request
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Envoy / Istio / Kong  (Proxy-Wasm host)                     │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  proxy-wasm-evidence.wasm                              │  │
│  │                                                        │  │
│  │  1. EvidenceFilter (HTTP context)                      │  │
│  │     ├── Reads :method, :path from request headers     │  │
│  │     ├── Extracts x-b3-traceid, x-agent-id headers      │  │
│  │     ├── Calls infer_side_effect_class(method, path)    │  │
│  │     ├── Builds RiskContext → compile_recording_policy   │  │
│  │     ├── Produces ActionEvidence with recording_mode    │  │
│  │     └── Sets x-aep-recording-mode response header      │  │
│  │                                                        │  │
│  │  2. aep-core (shared types & logic)                     │  │
│  │     ├── RecordingMode (validation / delta / full)      │  │
│  │     ├── SideEffectClass classification enum             │  │
│  │     ├── compile_recording_policy (risk → mode mapping) │  │
│  │     ├── ActionEvidence, AepRecord, ProvGraph           │  │
│  │     └── BundleSigner (Ed25519 DSSE envelope)          │  │
│  └────────────────────────────────────────────────────────┘  │
│                              │                               │
│                              ▼                               │
│                   HTTP response (with AEP headers)            │
└──────────────────────────────────────────────────────────────┘
         ↕ x-b3-traceid / x-agent-id headers link both layers
┌──────────────────────────────────────────────────────────────┐
│  wasmagent-js process-internal firewall                       │
│  (@wasmagent/mcp-firewall)                                   │
│  → shared trace_id joins gateway evidence to tool-call       │
│    evidence for full causal chain                             │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
              open-agent-audit (full causal graph assembly)
```

## Component responsibilities

### `proxy-wasm-evidence` crate — Wasm HTTP filter

The deployable Wasm module. It implements the Proxy-Wasm `HttpContext` trait
via `EvidenceFilter` and is loaded by the gateway host.

Key responsibilities:

- **Request interception** — reads HTTP method, path, trace ID, and agent ID
  from incoming request headers via `on_http_request_headers`.
- **Response decoration** — during `on_http_response_headers`, classifies the
  request's side-effects, builds an `ActionEvidence` record, and sets the
  `x-aep-recording-mode` response header so downstream services can observe
  the evidence policy decision.
- **Evidence construction** — delegates classification logic to `aep-core`
  and produces `ActionEvidence` structs with the computed recording mode.

### `aep-core` crate — shared evidence types and logic

A pure-Rust library with no Proxy-Wasm dependency. Contains the data model
and policy engine used by `proxy-wasm-evidence` and any future consumers.

Key types:

| Type | Purpose |
|---|---|
| `RecordingMode` | Enum: `validation`, `delta`, `full` — how much evidence to capture |
| `SideEffectClass` | Enum: `read`, `mutate_local`, `mutate_external`, `network_egress`, `unknown` |
| `RiskContext` | Struct: `was_vetted`, `has_consent_anomaly`, `taint_chain_length`, `side_effect_class` |
| `RecordingPolicy` | Output of `compile_recording_policy` — a `mode` + human-readable `reason` |
| `ActionEvidence` | Single action's evidence: action ID, tool name, state-changing flag, digests, recording mode |
| `AepRecord` | Top-level record: schema version, run/trace/session IDs, list of actions, optional signature |
| `AepSignature` | Ed25519 signature envelope: algorithm, key ID, hex-encoded signature |
| `ProvGraph` | PROV-DM causal graph: activities, entities, agents with ancestry traversal |

## AEP recording flow

```
1. HTTP request arrives at gateway
       │
2. EvidenceFilter.on_http_request_headers()
   ├── Extract method, path, trace_id, agent_id
       │
3. EvidenceFilter.on_http_response_headers()
   ├── infer_side_effect_class(method, path)
   │     GET/HEAD/OPTIONS        → Read
   │     POST/PUT/PATCH/DELETE
   │       path contains /network/ or /webhook → NetworkEgress
   │       otherwise                     → MutateExternal
   │     other methods                   → Unknown
   │
   ├── Build RiskContext {
   │     was_vetted: false,
   │     has_consent_anomaly: false,
   │     taint_chain_length: 0,
   │     side_effect_class: <above>
   │   }
   │
   ├── compile_recording_policy(risk_ctx)
   │     Priority chain (first match wins):
   │       1. was_vetted            → Full   "tool flagged by vetting"
   │       2. has_consent_anomaly   → Full   "consent anomaly recorded"
   │       3. tainted + non-read    → Full   "tainted input reaching state-changing call"
   │       4. Unknown class         → Full   "unknown side-effect class"
   │       5. MutateExternal        → Full   "external mutation"
   │       6. NetworkEgress         → Full   "external mutation"
   │       7. MutateLocal          → Delta  "local mutation, low risk"
   │       8. Read                 → Validation "read-only, no anomaly"
   │
   ├── build_evidence(action_id, tool_name, risk_ctx, timestamp, digest)
   │     → ActionEvidence { recording_mode, state_changing, ... }
   │
   └── set response header x-aep-recording-mode: "<RecordingMode>"
```

## Ed25519 signing

`aep-core::signing` wraps evidence records in an Ed25519 DSSE-style envelope:

1. **Canonicalize** — serialize the `AepRecord` to JSON (including the `signature: null`
   field, which is then excluded during verification).
2. **Hash** — SHA-256 of the canonical JSON bytes.
3. **Sign** — Ed25519 signature over the hash using `ed25519_dalek`.
4. **Attach** — `AepSignature { alg: "ed25519", key_id, sig: "<hex>" }` is set on the record.

Verification reverses the process: clone the record, strip the signature field,
re-canonicalize, hash, and verify against the Ed25519 public key.
The signing key is injected at deploy time (see [deployment.md](deployment.md)) and
never hard-coded in the Wasm module.

## Relationship to wasmagent-js

wasmagent-proxy implements the **network-boundary layer** of the wasmagent
evidence model. The process-internal layer lives in
[`@wasmagent/mcp-firewall`](https://github.com/WasmAgent/wasmagent-js/tree/main/packages/mcp-firewall).

| Layer | Repo | What it observes |
|---|---|---|
| Gateway (network boundary) | `wasmagent-proxy` (this repo) | HTTP ingress/egress, side-effect classification, response headers |
| Process-internal | `wasmagent-js` / `@wasmagent/mcp-firewall` | MCP tool calls, agent decisions, capability enforcement |

Both layers share the same `trace_id` (carried in the `x-b3-traceid` header) and
the same AEP record schema. Combining their evidence produces a full causal graph
from gateway ingress through to individual agent tool calls, consumed by
[open-agent-audit](https://github.com/WasmAgent/open-agent-audit).

## Boundary with identity and authorization layers

For a focused reference on the deployment model, capability boundary, and
complementary layers, see [deployment-model.md](deployment-model.md).

### What wasmagent-proxy is and is not

wasmagent-proxy is an **evidence and audit layer**. It observes traffic,
classifies side-effects, and emits signed AEP records. It does **not** perform
authorization decisions, token validation, or RBAC enforcement. Those concerns
belong upstream in an identity-aware gateway.

### Deployment model

The recommended deployment stacks an identity-aware gateway in front of
wasmagent-proxy. The identity gateway handles OAuth 2.0 token validation,
tool-level RBAC, and policy-based routing; wasmagent-proxy captures evidence
on all traffic that passes through:

```
 ┌──────────┐     ┌─────────────────────────────────────┐     ┌───────────┐
 │ MCP      │────▶│ Identity-aware gateway              │────▶│ wasmagent │
 │ Client   │     │                                     │     │ -proxy    │
 │          │     │  • OAuth 2.0 token validation       │     │           │────▶ MCP Server
 └──────────┘     │  • Tool-level RBAC                  │     │  • AEP    │
                  │  • Policy-based routing              │     │    evidence│
                  │                                     │     │    capture│
                  │  (Kong AI Gateway, TrueFoundry,     │     │  • DSSE   │
                  │   MCPX, Istio AuthorizationPolicy)  │     │    signing │
                  └─────────────────────────────────────┘     └───────────┘
```

The identity gateway and wasmagent-proxy may coexist inside the same host
(e.g., Envoy filter chain with an OAuth filter before the Wasm evidence filter)
or run as separate proxies in sequence.

### Capability boundary

wasmagent-proxy can only observe traffic that passes through the gateway
it is loaded into:

- **In scope** — any HTTP request routed through the proxy host: MCP tool
  calls, agent-to-server communication, A2A messages.
- **Out of scope** — endpoint-local MCP servers that communicate
  directly with their agent process without traversing the gateway. These
  servers are invisible to wasmagent-proxy's evidence capture.

Evidence completeness depends on traffic topology. Deploy wasmagent-proxy at
a choke point that covers the paths you need to audit.

### Complementary layers

The wasmagent ecosystem provides evidence at multiple layers. The table below
shows where wasmagent-proxy fits and which projects complement it:

| Layer | Project | Role |
|---|---|---|
| Identity / Authorization | Kong AI Gateway, TrueFoundry, MCPX, Istio AuthorizationPolicy | OAuth token validation, RBAC, routing |
| **Gateway evidence** | **wasmagent-proxy (this repo)** | **AEP evidence capture, side-effect classification, DSSE signing** |
| Process-internal evidence | [wasmagent-js](https://github.com/WasmAgent/wasmagent-js) / `@wasmagent/mcp-firewall` | MCP tool-call evidence, capability enforcement |
| Endpoint trust posture | [agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra) | AgentBOM, MCP posture assessment, trust passport |

wasmagent-proxy does not replace the identity layer or the endpoint layer — it
adds an auditable evidence record of the traffic flowing between them.
