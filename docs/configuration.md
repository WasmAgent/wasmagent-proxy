# Configuration

All configuration is passed to the Wasm module as a JSON object through the
gateway's Proxy-Wasm configuration mechanism. The fields are read from the
Proxy-Wasm root context at module initialization.

## Configuration fields

| Field | Type | Default | Description |
|---|---|---|---|
| `default_mode` | `string` | `"validation"` | Fallback recording mode when no risk signals are present. One of: `"validation"`, `"delta"`, `"full"`. |
| `key_id` | `string` | `"default"` | Key identifier embedded in the Ed25519 signature envelope. Used by downstream consumers to look up the corresponding public key. |
| `signing_key_hex` | `string` | *(none)* | Ed25519 private key as a 64-character hex string (32 bytes). Required for evidence signing. Inject via environment variable or K8s secret — never hard-code. |
| `trace_id_header` | `string` | `"x-b3-traceid"` | HTTP request header name used to extract the distributed trace ID. This value becomes the `trace_id` field in AEP records. |
| `agent_id_header` | `string` | `"x-agent-id"` | HTTP request header name used to extract the agent identifier. This value becomes the `agent_id` field in AEP records. |

## Field details

### `default_mode`

Controls the minimum evidence recording level. The actual mode for each request
is determined by `compile_recording_policy`, but `default_mode` serves as a
baseline when no risk context is available.

| Value | Behavior |
|---|---|
| `"validation"` | Lowest overhead — records metadata only, no full payloads |
| `"delta"` | Captures changes (deltas) to state for local mutations |
| `"full"` | Complete evidence capture including full request/response bodies |

### `key_id`

A human-readable identifier for the signing key. Downstream verification
services use this to select the correct public key from a key registry.
In production, use a unique key ID per deployment environment:

- `wasmagent-dev-key` — development
- `wasmagent-staging-key` — staging
- `wasmagent-prod-key-2024-01` — production (rotate with date)

### `signing_key_hex`

The 32-byte Ed25519 private key encoded as 64 hex characters. This key signs
all evidence records produced by the filter.

**Security notes:**

- Always inject via environment variable or K8s Secret — never commit to source control.
- Rotate keys periodically. Each key should have a unique `key_id`.
- The corresponding public key must be distributed to verification consumers.

See [deployment.md — K8s secret injection](deployment.md#k8s-secret-injection) for
how to generate and inject this key.

### `trace_id_header`

Defaults to `x-b3-traceid` for compatibility with Zipkin/B3 distributed tracing.
If your infrastructure uses a different header (e.g., `x-trace-id`, `traceparent`),
change this field accordingly.

The extracted trace ID links gateway-level evidence (this proxy) with
process-internal evidence ([wasmagent-js](https://github.com/WasmAgent/wasmagent-js)).

### `agent_id_header`

Defaults to `x-agent-id`. The value identifies which agent instance made the
request. If your system uses a different header for agent identification, update
this field.

## Examples

### Envoy (static config)

```yaml
configuration:
  "@type": type.googleapis.com/google.protobuf.StringValue
  value: |
    {
      "default_mode": "validation",
      "key_id": "wasmagent-dev-key",
      "signing_key_hex": "",
      "trace_id_header": "x-b3-traceid",
      "agent_id_header": "x-agent-id"
    }
```

### Istio WasmPlugin

```yaml
spec:
  pluginConfig:
    default_mode: validation
    key_id: wasmagent-prod-key
    signing_key_hex: ""  # injected via Secret reference
    trace_id_header: x-b3-traceid
    agent_id_header: x-agent-id
```

### Minimal development config

```json
{
  "default_mode": "validation",
  "key_id": "dev"
}
```

All other fields use their defaults. Evidence signing is skipped when
`signing_key_hex` is empty.
