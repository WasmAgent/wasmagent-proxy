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

## Strategic positioning

**Read `docs/strategy.md` before opening new issues or designing new features.**

This project is NOT a general MCP gateway. Its defensible niche is:

**"MCP-protocol-aware evidence and audit layer"** — a thin Proxy-Wasm plugin that sits
alongside any existing gateway and produces cryptographically signed, post-incident
auditable evidence records. It complements identity/auth layers (OAuth 2.1,
audience-bound tokens), it does NOT compete with commercial MCP gateways (Kong,
TrueFoundry, Lunar.dev) on routing, RBAC, or PII redaction.

Key differentiation:
1. **MCP-Method/MCP-Name header leakage detection** — credential/PII leak pattern
   specific to the MCP 2026-07-28 spec that commercial gateways do not check.
2. **PROV-DM signed evidence** — audit-grade tamper-evident records linking gateway
   ingress to agent tool-call layer via shared `trace_id`.
3. **Gateway-agnostic** — sidecar alongside any Proxy-Wasm host.

**Capability boundary**: wasmagent-proxy only sees traffic that passes through it.
It cannot observe endpoint-local MCP servers. Document this clearly.

## Key references

| Reference | What it covers |
|-----------|---------------|
| `README.md` | Architecture, Proxy-Wasm design, configuration fields |
| `docs/strategy.md` | **Strategic positioning, competitive landscape, differentiation** |
| `docs/architecture.md` | System diagram, component responsibilities, AEP recording flow, Ed25519 signing |
| `docs/mcp-protocol-compatibility.md` | MCP 2026-07-28 compatibility: stateless model, MCP-Method/MCP-Name headers, leakage detection |
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
- MCP 2026-07-28 compatibility: stateless model documented (`docs/mcp-protocol-compatibility.md`),
  MCP-Method classification, header leakage detection (`classify_mcp_headers`)

### In-progress ⚠️
- Issue #12: `x-aep-recording-mode` response header not yet set
- Issue #13: integration test (full request/response cycle)
- Issue #23: EvidenceFilter HTTP side-effect classification bug (PRs #26, #27 open)
- Issue #24: recording.rs / prov.rs / filter.rs unit tests (PR #28 open)
- Issue #29: MCP-Method/MCP-Name leakage detection (PR #38 open)
- Issue #30: architecture boundary docs (open)
- Issue #31: MCP compat validation (PRs #35, #39 open)

### Open PRs
- PR #26, #27: Fix #23 — EvidenceFilter side-effect classification
- PR #28: Fix #24 — unit tests for recording.rs/prov.rs/filter.rs
- PR #35, #39: Fix #31 — MCP 2026-07-28 compat
- PR #38: Fix #29 — MCP header leakage detection

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

### Phase 6: MCP-aware security evidence layer
- [ ] #23 fix: EvidenceFilter HTTP side-effect classification bug (PRs #26/#27 — pick one and land it)
- [ ] #24 test: unit tests for recording.rs, prov.rs, filter.rs (PR #28)
- [ ] #29 feat: `classify_mcp_headers()` — MCP-Method/MCP-Name leakage detection (PR #38)
- [ ] #31 docs/test: MCP 2026-07-28 compat — validate trace correlation model (PRs #35/#39)
- [ ] #30 docs: `docs/capability-boundary.md` — explicit statement of observable vs unobservable traffic
- [ ] docs: expand architecture.md — relationship to OAuth 2.1/identity layers

## How patrol sweep drives progress
Patrol reads this CLAUDE.md. Unchecked checkboxes → patrol opens issues with `claude` label.
Bot implements → merged → patrol ticks checkbox → opens next issue.
