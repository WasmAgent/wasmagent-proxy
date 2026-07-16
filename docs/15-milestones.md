# Milestones

## Milestone 1 — Classification Bug Fix and Test Coverage

- [ ] Fix `crates/proxy-wasm-evidence/src/filter.rs` `on_http_response_headers()`: read `mcp_method` and `mcp_name` fields (already captured in struct) and pass them to `infer_side_effect_class_with_mcp()` and `classify_mcp_headers()` instead of using the HTTP-method-only `infer_side_effect_class()` overload
- [ ] Fix `crates/proxy-wasm-evidence/src/filter.rs` `on_http_request_headers()`: capture `mcp_method` from `x-mcp-method` (or `MCP-Method`) header and `mcp_name` from `MCP-Name` header, store in struct fields
- [ ] Add unit tests in `crates/proxy-wasm-evidence/src/recorder.rs` `tests` module: cover `infer_side_effect_class_with_mcp()` for all MCP operation variants including unknown ops
- [ ] Add unit tests in `crates/aep-core/src/recording.rs` `tests` module: cover all six `SideEffectClass` branches of `compile_recording_policy()` including `was_vetted=true` and `has_consent_anomaly=true` paths
- [ ] Add unit tests in `crates/aep-core/src/signing.rs` `tests` module: round-trip sign and verify an `AepRecord`; verify that a tampered payload returns `Err`
- [ ] Run `cargo test --workspace` and confirm all new tests pass; update `docs/architecture.md` to document the MCP header capture flow

## Milestone 2 — MCP Header Leakage API

- [ ] Promote `classify_mcp_headers()` from `crates/proxy-wasm-evidence/src/recorder.rs` to `crates/aep-core/src/lib.rs` public API: add `pub use mcp_headers::{classify_mcp_headers, McpHeaderRisk};` re-export from a new `crates/aep-core/src/mcp_headers.rs` module
- [ ] Extend `ActionEvidence` in `crates/aep-core/src/evidence.rs`: add `mcp_header_risk: Option<String>` field (serialized as snake_case) carrying the `McpHeaderRisk` variant name when leakage is detected
- [ ] Update `build_evidence()` in `crates/proxy-wasm-evidence/src/recorder.rs`: accept `mcp_header_risk: Option<McpHeaderRisk>` parameter and set `evidence.mcp_header_risk`
- [ ] Update `on_http_response_headers()` in `crates/proxy-wasm-evidence/src/filter.rs`: call `classify_mcp_headers()`, pass result to `build_evidence()`, and emit `x-aep-mcp-header-risk` response header when non-None
- [ ] Add `tests/test_mcp_headers.rs` integration test (or extend existing recorder tests): inject a request with `MCP-Method: ghp_faketoken` and assert that the response carries `x-aep-mcp-header-risk: credential_leak`
- [ ] Update `docs/aep-evidence-format.md`: add "MCP Header Risk" section documenting the `mcp_header_risk` field values and when each is emitted

## Milestone 3 — Capability Boundary Documentation and Serialization

- [ ] Add `crates/aep-core/src/evidence.rs` `AepRecord` serialization round-trip test: serialize to JSON via `serde_json`, deserialize, assert field equality including `recording_mode` snake_case form
- [ ] Add `crates/aep-core/src/prov.rs` unit tests: add at least one node and one edge to `ProvGraph`, assert `ancestors_of()` returns expected IDs
- [ ] Add `docs/capability-boundary.md`: explicit statement that wasmagent-proxy cannot observe endpoint-local MCP servers, traffic bypassing the proxy, or content inside TLS unless TLS terminates here; include architecture diagram showing the boundary
- [ ] Update `docs/architecture.md`: add "Relationship to Identity Layers" section explaining that wasmagent-proxy complements OAuth 2.1 gateways (records what callers do) and does not replace them (does not decide who is authorized)
- [ ] Add `deploy/k8s/configmap.yaml` example with all `docs/configuration.md` fields as commented-out keys with their defaults, so operators have a ready-to-fork template
- [ ] Update `docs/deployment.md`: add "Capability Boundary" callout box referencing `docs/capability-boundary.md` so operators see the scope limits before deploying

## Milestone 4 — Production Hardening

- [ ] Add `crates/aep-core/src/recording.rs` `RiskContext` builder: `RiskContext::builder()` returning a `RiskContextBuilder` with `was_vetted()`, `has_consent_anomaly()`, `taint_chain_length()`, `side_effect_class()` setters and `.build()` — eliminates struct literal spread at all call sites
- [ ] Add `crates/proxy-wasm-evidence/src/recorder.rs` bounded ring-buffer for in-flight evidence: `EvidenceBuffer` struct holding at most `N` (configurable, default 1024) `ActionEvidence` entries; evict oldest on overflow rather than allocating unboundedly
- [ ] Add `crates/proxy-wasm-evidence/src/config.rs` `Config::max_evidence_buffer` field (default 1024, type `usize`) read from filter config JSON
- [ ] Add `benchmarks/latency_bench.rs` criterion benchmark for `compile_recording_policy()` covering all six code paths; assert median latency under 1 microsecond in CI via `cargo bench --bench latency_bench`
- [ ] Add `crates/proxy-wasm-evidence/src/filter.rs` Prometheus counter increments: emit `aep_evidence_recorded_total{mode="validation|delta|full"}` via `proxy_wasm::hostcalls::increment_metric` for each recorded evidence entry
- [ ] Update `docs/deployment.md`: add "Observability" section documenting the three Prometheus counters, their labels, and a sample Grafana panel JSON that visualizes recording mode distribution over time
