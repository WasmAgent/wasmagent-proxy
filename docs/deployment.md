# Deployment

## Prerequisites

- Rust toolchain with `wasm32-wasip1` target installed
- Ed25519 signing key (see [K8s secret injection](#k8s-secret-injection))

```bash
# Install Wasm target
rustup target add wasm32-wasip1

# Generate Ed25519 key pair
openssl genpkey -algorithm ed25519 | xxd -p -c 64
# Output: 64-char hex string (32 bytes) — use as signing_key_hex
```

## Build the Wasm module

```bash
# From repo root
make wasm
# or equivalently:
cargo build --target wasm32-wasip1 --release

# Output:
# target/wasm32-wasip1/release/proxy_wasm_evidence.wasm
```

## Envoy quickstart

### 1. Place the Wasm module

```bash
sudo mkdir -p /etc/envoy/wasm
sudo cp target/wasm32-wasip1/release/proxy_wasm_evidence.wasm /etc/envoy/wasm/
```

### 2. Configure Envoy

Use the provided config as a starting point (see `deploy/envoy/envoy.yaml`):

```yaml
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                http_filters:
                  - name: envoy.filters.http.wasm
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
                      config:
                        name: wasmagent_proxy_evidence
                        root_id: wasmagent_evidence_root
                        configuration:
                          "@type": type.googleapis.com/google.protobuf.StringValue
                          value: |
                            {
                              "default_mode": "validation",
                              "key_id": "wasmagent-dev-key",
                              "trace_id_header": "x-b3-traceid",
                              "agent_id_header": "x-agent-id"
                            }
                        vm_config:
                          runtime: envoy.wasm.runtime.v8
                          code:
                            local:
                              filename: /etc/envoy/wasm/proxy_wasm_evidence.wasm
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

### 3. Start Envoy

```bash
envoy -c deploy/envoy/envoy.yaml
```

### 4. Verify the AEP header

```bash
# Read request → should get "validation" mode
curl -v http://localhost:8080/api/data

# Look for the response header:
#   < x-aep-recording-mode: Validation

# Mutation request → should get "full" mode
curl -v -X POST http://localhost:8080/api/users

# Look for:
#   < x-aep-recording-mode: Full
```

## Istio WasmPlugin

### Deploy with kubectl

```bash
kubectl apply -f deploy/istio/wasmplugin.yaml
```

The plugin config in `deploy/istio/wasmplugin.yaml`:

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: wasmagent-proxy-evidence
  namespace: default
spec:
  selector:
    matchLabels:
      app: your-agent-app
  url: oci://ghcr.io/wasmAgent/wasmagent-proxy:latest
  phase: AUTHN
  pluginConfig:
    default_mode: validation
    key_id: wasmagent-prod-key
    trace_id_header: x-b3-traceid
    agent_id_header: x-agent-id
```

Key fields:

| Field | Description |
|---|---|
| `selector.matchLabels.app` | Set to your workload's label so the plugin attaches to the correct pods |
| `url` | OCI image registry reference for the Wasm module |
| `phase` | `AUTHN` runs the filter in the authentication phase (before routing) |
| `pluginConfig` | Passes configuration to the Wasm module at runtime (see [configuration.md](configuration.md)) |

### Verify in Istio

```bash
# Port-forward to a pod in the mesh
kubectl port-forward svc/your-agent-app 8080:80

# Send test request
curl -v http://localhost:8080/health

# Check for x-aep-recording-mode in response headers
```

## K8s secret injection

The Ed25519 signing key must be injected securely — never hard-coded in the
Wasm module or Envoy config.

### 1. Generate a key pair

```bash
# Generate private key and extract hex
openssl genpkey -algorithm ed25519 -out /tmp/signing.key
xxd -p -c 64 /tmp/signing.key | tr -d '\n'
# Save the output — this is your WASMAGENT_SIGNING_KEY_HEX value

# Extract public key for verification
openssl pkey -pubout -outform DER /tmp/signing.key | \
  tail -c 32 | xxd -p -c 32 | tr -d '\n'
# Save this for downstream consumers to verify signatures
```

### 2. Create the K8s Secret

Edit `deploy/k8s/signing-secret.yaml` with your generated key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: wasmagent-signing-key
  namespace: default
type: Opaque
stringData:
  WASMAGENT_SIGNING_KEY_HEX: "<your-64-char-hex-key>"
```

Apply it:

```bash
kubectl apply -f deploy/k8s/signing-secret.yaml
```

### 3. Mount in Envoy/Istio

The signing key is injected into the gateway via environment variable or
volume mount, then passed to the Wasm module through the Proxy-Wasm
`signing_key_hex` configuration field (see [configuration.md](configuration.md)).

For Istio, mount the secret as an environment variable on the gateway proxy
or use the WasmPlugin's `pluginConfig` to pass it directly.
