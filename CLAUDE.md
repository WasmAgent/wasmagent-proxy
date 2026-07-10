# wasmagent-proxy — CLAUDE.md

## Project overview
Rust Proxy-Wasm module that adds cryptographic AEP (Agent Evidence Protocol) evidence
recording to any Proxy-Wasm compatible gateway (Envoy, Istio, Kong). Intercepts HTTP
traffic, classifies side-effects, and emits signed PROV-DM structured evidence.

## Relationship to WasmAgent ecosystem
```
Agent/MCP traffic → Envoy/Istio/Kong gateway
    ↓ Proxy-Wasm plugin
wasmagent-proxy (this repo) — classifies side-effects, emits AEP records
    ↓ x-b3-traceid header links gateway evidence to process evidence
wasmagent-js MCP firewall — process-internal evidence
    ↓
open-agent-audit — full causal chain: gateway ingress → agent tool call
```

## Tech stack
- Rust 2021 edition, Cargo workspace
- Crates: `proxy-wasm-evidence` (main Wasm filter), `aep-core` (shared logic)
- Target: `wasm32-wasip1` (formerly wasm32-wasi — do not use deprecated target)
- Tests: `cargo test --workspace --lib`
- Lint: `cargo clippy --workspace -- -D warnings`
- Benchmarks: `cargo bench`

## Build and verify
```bash
# Unit tests (doc-tests disabled — rustdoc path issue)
PATH=/root/.cargo/bin:$PATH cargo test --workspace --lib

# Wasm module
make wasm
# or: PATH=/root/.cargo/bin:$PATH cargo build --target wasm32-wasip1 --release

# Clippy
PATH=/root/.cargo/bin:$PATH cargo clippy --workspace -- -D warnings
```

## Important constraints
- `[lib] doctest = false` in `crates/aep-core/Cargo.toml` — rustdoc not reliably in PATH
- Always use `PATH=/root/.cargo/bin:$PATH` when running cargo commands on VPS
- `wasm32-wasip1` is the correct target (not the deprecated `wasm32-wasi`)
- No OS-specific dependencies — all code must compile to Wasm

## Bot instructions
- Run `PATH=/root/.cargo/bin:$PATH cargo test --workspace --lib` to verify
- Run `cargo clippy --workspace -- -D warnings` for lint (no warnings allowed)
- All new code must have unit tests
- Do not use doc-tests — they fail due to rustdoc PATH issue on VPS


## Key references

Detailed documentation lives under `docs/` (see issue #14):

| Reference | What it covers |
|-----------|---------------|
| `README.md` | Architecture, Proxy-Wasm design, configuration fields |
| `docs/architecture.md` | System diagram, component responsibilities, AEP recording flow, Ed25519 signing |
| `docs/deployment.md` | Envoy/Istio quickstart, K8s secret injection walkthrough |
| `docs/configuration.md` | All config fields with types, defaults, and examples |
| `docs/aep-evidence-format.md` | AEP record structure, side-effect classification, DSSE envelope |
| `crates/aep-core/src/lib.rs` | RecordingMode, ActionEvidence types — the core contract |
| `crates/proxy-wasm-evidence/src/filter.rs` | EvidenceFilter — the Wasm HTTP context |
| `crates/proxy-wasm-evidence/src/recorder.rs` | Recording policy implementation |
| `deploy/envoy/envoy.yaml` | Envoy filter chain config reference |
| `deploy/istio/wasmplugin.yaml` | Istio WasmPlugin config reference |

Read README.md first, then `docs/` for the relevant area, then the
specific crate source for the component you are modifying. Tests are
co-located with source (lib.rs #[cfg(test)]).

## Current status

### Completed ✅
- `aep-core`: RecordingMode, ActionEvidence, PROV-DM types, BundleSigner (Ed25519)
- `proxy-wasm-evidence`: EvidenceFilter HTTP context, request/response classification
- Recording policy: read/mutate-local/mutate-external/network-egress classification
- 6 unit tests passing
- Deploy configs: `deploy/envoy/envoy.yaml`, `deploy/istio/wasmplugin.yaml`, `deploy/k8s/signing-secret.yaml`
- Benchmark skeleton: `benchmarks/latency_bench.rs`

### In-progress ⚠️
- Issue #12: `x-aep-recording-mode` response header not yet set
- Issue #13: integration test (full request/response cycle)

### Open PRs
- None (all PRs merged or closed)

## Roadmap

Bot: implement issues in order. When an issue closes, open the next unchecked item.

### Phase 2: Complete core functionality (issues #12-#13)
- [ ] #12 feat: set `x-aep-recording-mode` response header in EvidenceFilter
- [ ] #13 test: integration test — EvidenceFilter full request/response cycle
- [ ] feat: `x-b3-traceid` and `x-agent-id` header extraction and injection into AEP records
- [ ] test: BundleSigner produces valid DSSE envelope with verifiable Ed25519 signature
- [ ] feat: `signing_key_hex` config read from Proxy-Wasm root context

### Phase 3: Wasm deployment validation
- [ ] feat: `make wasm` produces `proxy-wasm-evidence.wasm` without errors (fix any wasm32-wasip1 compat issues)
- [ ] docs: `deploy/envoy/README.md` — quickstart: load wasm, send test request, see AEP header
- [ ] test: `benchmarks/latency_bench.rs` — measure added latency (target: <1ms per request)
- [ ] feat: `deploy/k8s/signing-secret.yaml` — document how to inject Ed25519 key as K8s secret

### Phase 4: Integration with wasmagent-js
- [ ] feat: AEP records from proxy match FAEP v0.1 schema (`@wasmagent/faep-schema`)
- [ ] feat: shared `trace_id` header (`x-b3-traceid`) passed through to wasmagent-js MCP firewall
- [ ] feat: `x-aep-bundle-id` response header — unique ID for the signed evidence bundle
- [ ] docs: architecture diagram showing proxy + wasmagent-js evidence joining via trace_id

### Phase 5: Production readiness
- [ ] feat: configurable route-level recording policy (per-path overrides)
- [ ] feat: `aep-core` — AEP record serialization to JSON for downstream consumers
- [ ] feat: metrics endpoint (Prometheus) — evidence volume, latency overhead, signing errors
- [ ] perf: ring buffer for evidence accumulation (avoid per-request heap allocation)

## How patrol sweep drives progress
Patrol reads this CLAUDE.md. Unchecked checkboxes → patrol opens issues with `claude` label.
Bot implements → merged → patrol ticks checkbox → opens next issue.
