use aep_core::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Configuration loaded from the Wasm plugin's root context (e.g. Istio WasmPlugin spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
    /// Maximum number of evidence records to buffer before flushing.
    pub max_evidence_buffer: usize,
}

pub type Config = PluginConfig;

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            default_mode: RecordingMode::Validation,
            key_id: "default".into(),
            signing_key_hex: None,
            trace_id_header: "x-b3-traceid".into(),
            agent_id_header: "x-agent-id".into(),
            max_evidence_buffer: 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_max_evidence_buffer_to_1024() {
        let config = Config::default();

        assert_eq!(config.max_evidence_buffer, 1024);
    }

    #[test]
    fn reads_max_evidence_buffer_from_json() {
        let config: Config = serde_json::from_str(
            r#"{
                "default_mode": "delta",
                "key_id": "gateway-key",
                "trace_id_header": "x-trace-id",
                "agent_id_header": "x-agent",
                "max_evidence_buffer": 64
            }"#,
        )
        .expect("deserialize plugin config");

        assert_eq!(config.max_evidence_buffer, 64);
    }

    #[test]
    fn defaults_max_evidence_buffer_when_json_omits_it() {
        let config: Config = serde_json::from_str(
            r#"{
                "default_mode": "full",
                "key_id": "gateway-key",
                "trace_id_header": "x-trace-id",
                "agent_id_header": "x-agent"
            }"#,
        )
        .expect("deserialize plugin config");

        assert_eq!(config.max_evidence_buffer, 1024);
    }
}
