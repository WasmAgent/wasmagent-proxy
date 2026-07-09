# wasmagent-proxy

## Project overview
Rust Proxy-Wasm module that adds cryptographic AEP (Agent Evidence Protocol) evidence
recording to any Proxy-Wasm compatible gateway (Envoy, Istio, Kong). Intercepts HTTP
traffic, classifies side-effects, and emits signed PROV-DM structured evidence.

## Key concepts
- **Proxy-Wasm**: WebAssembly plugin spec for gateways (Envoy/Istio/Kong)
- **AEP evidence**: Agent Evidence Protocol records, Ed25519 signed (DSSE envelope)
- **Recording policy**: validation → delta → full, configured per route
- **PROV-DM**: W3C provenance model for structured evidence

## Tech stack
- Rust 2021 edition, Cargo workspace
- Crates: `proxy-wasm-evidence` (main Wasm filter), `aep-core` (shared logic)
- Tests: `cargo test --workspace`
- Lint/format: `cargo clippy`, `cargo fmt`

## Build and test
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Wasm build
```bash
cargo build --target wasm32-wasip1 --release
```

## Code structure
```
crates/
  proxy-wasm-evidence/  — Wasm filter (EvidenceFilter, HTTP context)
  aep-core/             — RecordingPolicy, ProvGraph, BundleSigner
deploy/                 — Envoy/Istio configuration examples
benchmarks/             — performance benchmarks
```

## Bot instructions
- All new code must have unit tests
- Use `cargo clippy` clean (no warnings)
- Do not add unsafe code without a documented safety comment
- WASM target is wasm32-wasip1 — avoid OS-specific dependencies
- The verify command is: `cargo test --workspace`
