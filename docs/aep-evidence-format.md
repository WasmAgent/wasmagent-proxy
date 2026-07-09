# AEP Evidence Format

## What an AEP record looks like

The top-level evidence structure produced by wasmagent-proxy is `AepRecord`:

```json
{
  "schema_version": "aep/v0.1",
  "run_id": "run-abc123",
  "trace_id": "abc123def456",
  "session_id": null,
  "actions": [
    {
      "action_id": "ctx-42",
      "tool_name": "POST /api/payments",
      "state_changing": true,
      "precondition_digest": null,
      "result_digest": null,
      "timestamp_ms": 1700000000000,
      "parent_action_id": null,
      "causal_chain_id": null,
      "recording_mode": "full",
      "capability_decision": null
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
| `schema_version` | `string` | Schema identifier for format compatibility (`"aep/v0.1"`) |
| `run_id` | `string` | Unique identifier for the agent run/session |
| `trace_id` | `string \| null` | Distributed trace ID extracted from `x-b3-traceid` header |
| `session_id` | `string \| null` | Optional session identifier for multi-turn conversations |
| `actions` | `array<ActionEvidence>` | List of recorded actions in this request (see below) |
| `created_at_ms` | `u64` | Unix timestamp in milliseconds when the record was created |
| `signature` | `AepSignature \| null` | Ed25519 signature envelope (null if signing key not configured) |

### ActionEvidence fields

| Field | Type | Description |
|---|---|---|
| `action_id` | `string` | Unique identifier for this action (e.g., `"ctx-42"` derived from Proxy-Wasm context ID) |
| `tool_name` | `string` | Human-readable label — `"<METHOD> <path>"` (e.g., `"POST /api/payments"`) |
| `state_changing` | `bool` | `true` if the action modifies external state |
| `precondition_digest` | `string \| null` | Hash of pre-action state (for `delta`/`full` modes) |
| `result_digest` | `string \| null` | Hash of post-action state (for `full` mode) |
| `timestamp_ms` | `u64` | Unix timestamp in milliseconds |
| `parent_action_id` | `string \| null` | ID of the parent action in a causal chain |
| `causal_chain_id` | `string \| null` | Groups related actions into a causal chain |
| `recording_mode` | `string` | One of `"validation"`, `"delta"`, `"full"` |
| `capability_decision` | `CapabilityDecision \| null` | Optional capability policy decision |

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
  x-aep-recording-mode: Full         capability_decision: allow
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
