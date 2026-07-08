# wasmagent-proxy

> Proxy-Wasm evidence engine — cryptographic AEP audit layer for Agent/MCP/A2A traffic

A Wasm module that plugs into any [Proxy-Wasm](https://github.com/proxy-wasm/spec)-compatible
gateway (Envoy, Istio, Kong, Consul) and adds wasmagent-level evidence recording to every
request — without replacing your existing gateway.

## What it does

- Intercepts HTTP requests and responses at the gateway
- Classifies side-effects (read / mutate-local / mutate-external / network-egress)
- Applies `validation → delta → full` recording policy from
  [@wasmagent/capability-compiler](https://github.com/WasmAgent/wasmagent-js/tree/main/packages/capability-compiler)
- Emits PROV-DM-structured `AEPRecord` evidence, signed with Ed25519 (DSSE envelope)
- Sets `x-aep-recording-mode` response header for downstream observability

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
