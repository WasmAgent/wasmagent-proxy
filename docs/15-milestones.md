# Milestones

## Milestone 1 — Proxy-Wasm module skeleton & HTTP context

- [ ] Proxy-Wasm plugin entrypoint compiles to `dist/proxy-wasm-evidence.wasm` via `make build` with exit code 0
- [ ] `plugin/` implements `VMContext` → `PluginContext` → `HttpContext` and loads in a Proxy-Wasm host with no startup errors
- [ ] On `onHttpRequestHeaders` / `onHttpResponseHeaders`, capture method, path, and selected headers into an `EvidenceFilter` HTTP-context struct
- [ ] Set `x-aep-recording-mode: off` response header on every response as the baseline observable signal
- [ ] Plugin reads host config (recording mode, signing key ref, sink endpoint) via `getPluginConfig` and fails closed on parse error
- [ ] `make test` passes: `plugin/context_test` asserts headers are captured and the baseline header is echoed back

## Milestone 2 — Side-effect classification & recording policy

- [ ] `classify/` module maps each request to read / mutate-local / mutate-external / network-egress using method, path, and header heuristics
- [ ] `classify/classify_test` passes a decision table of (method, path, headers) → expected effect covering all four categories
- [ ] `aep-core/RecordingPolicy` selects validation → delta → full from a capability manifest emitted by `@wasmagent/capability-compiler`
- [ ] `EvidenceFilter` binds the HTTP context to the per-request recording mode chosen by `RecordingPolicy`
- [ ] `x-aep-recording-mode` header now reflects the resolved mode (validation / delta / full) instead of the `off` baseline
- [ ] Integration test feeds a sample capability manifest JSON and asserts the correct mode is selected per route

## Milestone 3 — PROV-DM evidence records & Ed25519 signing

- [ ] `aep-core/ProvGraph` builds a PROV-DM graph (entity / activity / agent) for each intercepted exchange
- [ ] `evidence/AEPRecord` serializes the graph to the AEPRecord JSON schema; `evidence/aeprecord_test` validates output against the schema fixture
- [ ] `signing/BundleSigner` wraps the AEPRecord in a DSSE envelope signed with Ed25519
- [ ] Signing key loaded from host config or Wasm-sealed store; `signing/ed25519_test` verifies a signature round-trips with a known keypair
- [ ] Signed bundles emitted to a configured sink (host `logCrit` or HTTP callout) and observable in a test run
- [ ] Tamper test: flipping one byte of the payload causes `BundleSigner.verify` to fail

## Milestone 4 — Gateway integration, E2E tests & release

- [ ] Envoy harness: `make run-envoy` loads `proxy-wasm-evidence.wasm` and proxies a sample request end-to-end
- [ ] E2E test issues one read and one mutate request and asserts two signed AEPRecords are produced with the correct recording modes
- [ ] Same `.wasm` artifact runs against at least one of Istio / Kong / Consul without host errors
- [ ] `curl` against the proxied endpoint returns the `x-aep-recording-mode` header downstream
- [ ] `docs/` updated with a per-gateway integration guide and a signing-key setup walkthrough
- [ ] Tagged `v0.1.0` release with the built `proxy-wasm-evidence.wasm` attached as an artifact