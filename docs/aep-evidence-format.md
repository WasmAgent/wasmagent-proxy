# AEP Evidence Format

## What an AEP record looks like

The top-level evidence structure produced by wasmagent-proxy is `AepRecord`.
Optional fields are **omitted** when absent (never serialized as `null`), so
every emitted record validates against the canonical schema (see
[Schema conformance](#schema-conformance)):

```json
{
  "schema_version": "aep/v0.5",
  "run_id": "run-abc123",
  "trace_id": "abc123def456",
  "actions": [
    {
      "action_id": "ctx-42",
      "tool_name": "POST /api/payments",
      "state_changing": true,
      "timestamp_ms": 1700000000000,
      "recording_mode": "full",
      "mcp_header_risk": "credential_leak"
    }
  ],
  "created_at_ms": 1700000000000,
  "signature": {
    "alg": "ed25519",
    "key_id": "wasmagent-prod-key",
    "sig": "a1b2c3d4...hex_encoded_64_bytes"
  }
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `schema_version` | `string` | Schema identifier for format compatibility (`"aep/v0.5"` — within the canonical enum `aep/v0.1`–`aep/v0.5`) |
| `run_id` | `string` | Unique identifier for the agent run/session |
| `trace_id` | `string` (omitted when absent) | Distributed trace ID extracted from `x-b3-traceid` header |
| `session_id` | `string` (omitted when absent) | Optional session identifier for multi-turn conversations |
| `actions` | `array<ActionEvidence>` | List of recorded actions in this request (see below) |
| `created_at_ms` | `u64` | Unix timestamp in milliseconds when the record was created |
| `signature` | `AepSignature` (omitted when absent) | Ed25519 signature envelope (omitted if signing key not configured) |

### ActionEvidence fields

| Field | Type | Description |
|---|---|---|
| `action_id` | `string` | Unique identifier for this action (e.g., `"ctx-42"` derived from Proxy-Wasm context ID) |
| `tool_name` | `string` | Human-readable label — `"<METHOD> <path>"` (e.g., `"POST /api/payments"`) |
| `state_changing` | `bool` | `true` if the action modifies external state |
| `precondition_digest` | `string` (omitted when absent) | Hash of pre-action state (for `delta`/`full` modes) |
| `result_digest` | `string` (omitted when absent) | Hash of post-action state (for `full` mode) |
| `timestamp_ms` | `u64` | Unix timestamp in milliseconds |
| `parent_action_id` | `string` (omitted when absent) | ID of the parent action in a causal chain |
| `causal_chain_id` | `string` (omitted when absent) | Groups related actions into a causal chain |
| `recording_mode` | `string` | One of `"validation"`, `"delta"`, `"full"` |
| `capability_decision` | `CapabilityDecision` (omitted when absent) | Optional capability policy decision |
| `mcp_header_risk` | `string` (omitted when absent) | MCP 2026-07-28 header-leak risk: `"credential_leak"`, `"high_entropy_value"`, or `"pii_leak"` |

## Schema conformance

The AEP record schema has **one canonical source**:
[`WasmAgent/wasmagent-protocol`](https://github.com/WasmAgent/wasmagent-protocol),
published as `@wasmagent/protocol` (npm) / `wasmagent-protocol` (PyPI). The
schema JSON is never vendored, inlined, or hand-copied into this repo.

- **Emitted `schema_version`**: `aep/v0.5` (constant `aep_core::AEP_SCHEMA_VERSION`),
  within the canonical schema's enum (`aep/v0.1`–`aep/v0.5`; additive fields only, so v0.1 records stay valid).
- **v0.5 attribution fields**: the record struct carries `user_id`, `authorized_by`,
  `authority_origin`, `identity_source`, `attribution_backing`,
  `run_attribution_backing_floor` and `run_attribution_backing_observed` as optional
  fields (canonical snake_case values). The gateway populates the ones it can
  observe (e.g. an authenticated principal header); absent fields are omitted,
  never null. Per-action `side_effect_class` uses the canonical hyphenated
  vocabulary (`read`, `mutate-local`, `mutate-external`, `network-egress`, `unknown`).
- **CI check**: the `AEP schema conformance` job emits representative records
  (`cargo run -p aep-core --example emit_aep_samples`), fetches the canonical
  `aep-record` schema from the npm release pinned by exact version + sha256
  (`ci/fetch_aep_schema.sh`), and validates every sample against it
  (`ci/validate_aep_records.py`, JSON Schema draft 2020-12).
- **Serialization rule**: optional Rust fields serialize as *omitted*, not
  `null`, because the canonical schema types them as `string`/`object` — a
  JSON `null` would fail validation.
- **Need a schema change?** Open it against `wasmagent-protocol` following its
  [CONTRACT-CHANGE-PROCESS](https://github.com/WasmAgent/wasmagent-protocol/blob/main/docs/CONTRACT-CHANGE-PROCESS.md);
  do not fork or relax the schema locally.

## Side-effect classification rules

wasmagent-proxy classifies each HTTP request by its side-effect class, which
determines the recording policy applied.

### Classification heuristic

The proxy uses HTTP method and path to infer the side-effect class:

| HTTP Method(s) | Path condition | Side-effect class |
|---|---|---|
| `GET`, `HEAD`, `OPTIONS` | *(any)* | `Read` |
| `POST`, `PUT`, `PATCH`, `DELETE` | contains `/network/` or `/webhook` | `NetworkEgress` |
| `POST`, `PUT`, `PATCH`, `DELETE` | *(other paths)* | `MutateExternal` |
| *(any other method)* | *(any)* | `Unknown` |

### From side-effect class to recording mode

The `compile_recording_policy` function maps `RiskContext` (which includes
`side_effect_class` plus risk signals) to a `RecordingMode`:

| Side-effect class | Risk signals | Recording mode | Reason |
|---|---|---|---|
| *(any)* | `was_vetted = true` | `Full` | Tool flagged by vetting |
| *(any)* | `has_consent_anomaly = true` | `Full` | Consent anomaly recorded |
| non-`Read` | `taint_chain_length > 0` | `Full` | Tainted input reaching state-changing call |
| `Unknown` | *(none)* | `Full` | Unknown side-effect class |
| `MutateExternal` | *(none)* | `Full` | External mutation |
| `NetworkEgress` | *(none)* | `Full` | External mutation |
| `MutateLocal` | *(none)* | `Delta` | Local mutation, low risk |
| `Read` | *(none)* | `Validation` | Read-only, no anomaly |

Priority: first matching rule wins (evaluated top-to-bottom).

### Recording mode semantics

| Mode | What is recorded | Overhead |
|---|---|---|
| `validation` | Action metadata (method, path, mode) only | Minimal — response header only |
| `delta` | Metadata + state change digests (before/after) | Moderate — hash computation |
| `full` | Complete evidence with all digests and full provenance | Higher — signing + full capture |

## DSSE envelope structure

When evidence signing is enabled (`signing_key_hex` is configured), each
`AepRecord` carries an `AepSignature`:

```json
{
  "alg": "ed25519",
  "key_id": "wasmagent-prod-key",
  "sig": "<64-char hex of 64-byte Ed25519 signature>"
}
```

### Signing process

1. The `AepRecord` (with `signature: null`) is serialized to canonical JSON.
2. The canonical JSON is hashed with SHA-256.
3. The SHA-256 digest is signed with the Ed25519 private key.
4. The resulting 64-byte signature is hex-encoded and stored in `AepSignature.sig`.

### Verification

1. Clone the record and strip the `signature` field.
2. Re-canonicalize to JSON and hash with SHA-256.
3. Decode the hex signature back to 64 bytes.
4. Verify with the Ed25519 public key corresponding to `key_id`.

## How proxy evidence joins with wasmagent-js

### Shared trace ID

Both wasmagent-proxy (gateway layer) and `@wasmagent/mcp-firewall`
(process-internal layer) use the same `trace_id` from the `x-b3-traceid`
header. This links their evidence into a single causal chain.

### Complementary observations

```
Gateway (wasmagent-proxy):          Process-internal (wasmagent-js):
  POST /api/payments                 tool_call: "charge_card"
  x-aep-recording-mode: full         capability_decision: allow
  side_effect_class: MutateExternal  precondition: {amount: 100}
                                     result: {tx_id: "xyz"}
```

### Full causal chain

[open-agent-audit](https://github.com/WasmAgent/open-agent-audit) assembles
evidence from both layers into a complete causal graph:

```
Gateway ingress → Agent receives request → Agent calls tools → Agent responds
  (proxy)            (trace_id link)        (firewall)         (proxy)
```

The `x-b3-traceid` header flows from the gateway through to the agent process,
ensuring every layer's evidence can be correlated.
