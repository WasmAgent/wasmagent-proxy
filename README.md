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

## WasmAgent Ecosystem

| Repository | Role |
|---|---|
| [.github](https://github.com/WasmAgent/.github) | Org hub — org portal, roadmap, claims registry, release ledger, project index |
| [wasmagent-js](https://github.com/WasmAgent/wasmagent-js) | Runtime — embedded agent runtime (WASM kernels, MCP gateway, AEP emitter, capability manifests; A2A/AG-UI/Claude Agent SDK adapters) |
| wasmagent-py | Runtime (planned) — Python agent runtime; shares AEP schema, Criterion/ConstraintIR, symkernel adapter |
| [wasmagent-proxy](https://github.com/WasmAgent/wasmagent-proxy) | Gateway 🚧 — Proxy-Wasm evidence engine for Envoy/Istio/Kong; Ed25519-signed AEP records |
| [symkernel](https://github.com/WasmAgent/symkernel) | Verification 🚧 — Go symbolic verification backend; cel-go rules, wazero sandbox, Z3 SMT proofs |
| [bscode](https://github.com/WasmAgent/bscode) | Workload — coding-agent workload on Cloudflare Workers; AEP evidence, deny capabilities, RolloutProvenance |
| [fresharena](https://github.com/WasmAgent/fresharena) | Evaluation — dynamic adversarial evaluation protocol; FAEP schema, submit-then-test, Public Immunity Pool |
| [trace-pipeline](https://github.com/WasmAgent/trace-pipeline) | Evidence pipeline — trace-to-training backend; AgentTrustScore, training-data admission gate |
| [wasmagent-train-replay](https://github.com/WasmAgent/wasmagent-train-replay) | Evidence pipeline 🚧 — causal evidence for distributed GPU training; cross-rank PROV-DM graph, signed EpochEvidenceBundles |
| [agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra) | Trust artifacts — AgentBOM, MCP Posture, Trust Passport spec + CLI; EU AI Act Annex IV mapping |
| [open-agent-audit](https://github.com/WasmAgent/open-agent-audit) | Audit — enterprise audit product with AEP v0.3 adapter; deployed at trustavo.com |
