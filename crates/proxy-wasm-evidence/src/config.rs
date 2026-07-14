use aep_core::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Configuration loaded from the Wasm plugin's root context (e.g. Istio WasmPlugin spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Default recording mode when no risk signals are present.
    pub default_mode: RecordingMode,
    /// Key ID used in AEP signature envelopes.
    pub key_id: String,
    /// Hex-encoded Ed25519 signing key (32 bytes). In production, inject via
    /// a Kubernetes Secret mounted as an environment variable — never hardcode.
    pub signing_key_hex: Option<String>,
    /// Trace/session header to propagate as AEP trace_id.
    pub trace_id_header: String,
    /// Agent identity header (e.g. x-agent-id).
    pub agent_id_header: String,
    /// Optional trust token for the `x-aep-side-effect-class` override header.
    ///
    /// If set, the `x-aep-side-effect-class` request header is only honored when
    /// the request also carries an `x-aep-override-token` header whose value
    /// matches this token. This prevents untrusted downstream clients from
    /// downgrading the evidence recording mode.
    ///
    /// When `None` (the default), the override header is ignored entirely —
    /// the side-effect class is always determined by the method/path heuristic.
    /// Set this to a shared secret to enable the override feature in deployments
    /// where an upstream proxy can inject the matching token header.
    pub override_trust_token: Option<String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            default_mode: RecordingMode::Validation,
            key_id: "default".into(),
            signing_key_hex: None,
            trace_id_header: "x-b3-traceid".into(),
            agent_id_header: "x-agent-id".into(),
            override_trust_token: None,
        }
    }
}
