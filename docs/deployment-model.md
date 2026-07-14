# Deployment Model

## Architectural boundary

wasmagent-proxy is an **evidence and audit layer**, not an identity gateway or
authorization proxy. It observes HTTP traffic, classifies side-effects, and emits
signed AEP evidence records. Authorization decisions — OAuth 2.0 token validation,
tool-level RBAC, policy-based routing — belong upstream in a dedicated
identity-aware gateway.

The recommended deployment stacks an identity-aware gateway in front of
wasmagent-proxy. The identity gateway handles authentication and authorization;
wasmagent-proxy captures evidence on all traffic that passes through.

For the full architecture description and component responsibilities, see
[docs/architecture.md](architecture.md).

## Reference architecture

```
 ┌──────────┐     ┌─────────────────────────────────────┐     ┌───────────┐
 │ MCP      │────▶│ Identity-aware gateway              │────▶│ wasmagent │
 │ Client   │     │                                     │     │ -proxy    │
 │          │     │  • OAuth 2.0 token validation       │     │           │────▶ MCP Server
 └──────────┘     │  • Tool-level RBAC                  │     │  • AEP    │
                  │  • Policy-based routing              │     │    evidence│
                  │                                     │     │    capture│
                  │  (Kong AI Gateway, TrueFoundry,     │     │  • DSSE   │
                  │   MCPX, Istio AuthorizationPolicy)  │     │    signing │
                  └─────────────────────────────────────┘     └───────────┘
```

The identity gateway and wasmagent-proxy may coexist inside the same host
(e.g., Envoy filter chain with an OAuth filter before the Wasm evidence filter)
or run as separate proxies in sequence.

## Capability boundary

wasmagent-proxy can only observe traffic that passes through the gateway
it is loaded into:

- **In scope** — any HTTP request routed through the proxy host: MCP tool
  calls, agent-to-server communication, A2A messages.
- **Out of scope** — endpoint-local MCP servers that communicate
  directly with their agent process without traversing the gateway. These
  servers are invisible to wasmagent-proxy's evidence capture.

Evidence completeness depends on traffic topology. Deploy wasmagent-proxy at
a choke point that covers the paths you need to audit.

## Complementary layers

The wasmagent ecosystem provides evidence at multiple layers. wasmagent-proxy
fills the gateway-evidence layer; endpoint-layer trust posture is addressed by
[agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra) (AgentBOM,
MCP posture assessment, trust passport).

| Layer | Project | Role |
|---|---|---|
| Identity / Authorization | Kong AI Gateway, TrueFoundry, MCPX, Istio AuthorizationPolicy | OAuth token validation, RBAC, routing |
| **Gateway evidence** | **wasmagent-proxy (this repo)** | **AEP evidence capture, side-effect classification, DSSE signing** |
| Process-internal evidence | [wasmagent-js](https://github.com/WasmAgent/wasmagent-js) / `@wasmagent/mcp-firewall` | MCP tool-call evidence, capability enforcement |
| Endpoint trust posture | [agent-trust-infra](https://github.com/WasmAgent/agent-trust-infra) | AgentBOM, MCP posture assessment, trust passport |

wasmagent-proxy does not replace the identity layer or the endpoint layer — it
adds an auditable evidence record of the traffic flowing between them.

## See also

- [Architecture overview](architecture.md) — full system diagram, component responsibilities, AEP recording flow
- [MCP protocol compatibility](mcp-protocol-compatibility.md) — capability boundary for MCP traffic
- [Deployment guide](deployment.md) — Envoy/Istio quickstart and K8s secret injection
- [Configuration reference](configuration.md) — all config fields with types and defaults
- [AEP evidence format](aep-evidence-format.md) — record structure, side-effect classification, DSSE envelope
