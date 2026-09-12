# wasmagent-proxy

| | |
|---|---|
| **Status** | Experimental |
| **Contract stability** | Evolving |
| **Recommended for** | Gateway-level AEP evidence; Envoy/Istio/Kong sidecar |
| **Not recommended for** | Endpoint-local MCP servers; general gateway RBAC/routing |


> Proxy-Wasm evidence engine — request classification and AEP evidence capture for Agent/MCP/A2A traffic

A Wasm module that plugs into any [Proxy-Wasm](https://github.com/proxy-wasm/spec)-compatible
gateway (Envoy, Istio, Kong, Consul) and records wasmagent-level evidence for every
request — without replacing your existing gateway.

## What it does

- Intercepts HTTP requests and responses at the gateway
- Classifies side-effects (read / mutate-local / mutate-external / network-egress);
  the MCP-Method header is untrusted metadata and can raise but never lower the verdict
- Applies `validation → delta → full` recording policy from
  [@wasmagent/capability-compiler](https://github.com/WasmAgent/wasmagent-js/tree/main/packages/capability-compiler)
- Captures PROV-DM-structured `AEPRecord` evidence inputs (aep/v0.5) into a per-context evidence buffer
- Sets `x-aep-recording-mode` response header for downstream observability

> **Honest status (evidence emission):** the gateway data plane currently
> *captures and classifies* evidence; it does not yet assemble, sign, or export
> complete `AEPRecord`s to a durable sink from the Wasm data plane. The signing
> primitives (`sign_record_dsse`, Ed25519) live in `crates/aep-core` and are
> exercised by the central conformance corpus; wiring the data plane to a
> signed export pipeline is in progress. Treat "signed gateway evidence" as a
> roadmap item until then.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Envoy / Istio / Kong  (Proxy-Wasm host)        │
│  ┌───────────────────────────────────────────┐  │
│  │  proxy-wasm-evidence.wasm                 │  │
│  │  ├── aep-core (RecordingPolicy, ProvGraph)│  │
│  │  ├── EvidenceFilter (HTTP context)        │  │
│  │  └── BundleSigner (Ed25519)               │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
         ↕ x-b3-traceid / x-agent-id headers
┌─────────────────────────────────────────────────┐
│  wasmagent-js process-internal firewall         │
│  (@wasmagent/mcp-firewall)                      │
│  → shared trace_id joins both graphs            │
└─────────────────────────────────────────────────┘
```

## Documentation

Detailed guides live under [`docs/`](docs/):

| Guide | What it covers |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System diagram, component responsibilities, AEP recording flow, Ed25519 signing |
| [`docs/deployment.md`](docs/deployment.md) | Envoy quickstart, Istio WasmPlugin, K8s signing-key secret injection |
| [`docs/configuration.md`](docs/configuration.md) | Every config field with type, default, and example |
| [`docs/aep-evidence-format.md`](docs/aep-evidence-format.md) | AEP record structure, side-effect classification, DSSE envelope |

## Quick start

```bash
# Build the native library (tests)
cargo build --workspace

# Build the Wasm module
make wasm

# Run tests
make test
```

### Istio

```bash
kubectl apply -f deploy/istio/wasmplugin.yaml
```

### Envoy (local)

```bash
envoy -c deploy/envoy/envoy.yaml
```

## Configuration

| Field | Default | Description |
|---|---|---|
| `default_mode` | `validation` | Recording mode when no risk signals present |
| `key_id` | `default` | Key ID embedded in AEP signature envelopes |
| `signing_key_hex` | — | Ed25519 private key hex — inject via env/secret |
| `trace_id_header` | `x-b3-traceid` | Header to use as AEP `trace_id` |
| `agent_id_header` | `x-agent-id` | Header to use as AEP `agent_id` |

## Relationship to wasmagent-js

This repo implements the **network-boundary layer** of the wasmagent evidence model.
The process-internal layer lives in
[@wasmagent/mcp-firewall](https://github.com/WasmAgent/wasmagent-js/tree/main/packages/mcp-firewall).
Both layers share the same AEP schema and `trace_id` — combining them gives a full
causal graph from gateway ingress to Agent tool call.

## License

Apache-2.0

Part of the [WasmAgent](https://github.com/WasmAgent) ecosystem.
