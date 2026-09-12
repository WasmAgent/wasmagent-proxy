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

impl PluginConfig {
    /// Validate cross-field invariants that serde's type checks cannot express.
    ///
    /// Called from the root context's `on_configure` so a misconfigured plugin
    /// fails to load instead of silently degrading at request time. For an
    /// evidence-recording filter, a malformed signing key must be fatal: it
    /// would otherwise produce unsigned (i.e. unauditable) evidence with no
    /// signal to the operator.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_evidence_buffer == 0 {
            return Err("max_evidence_buffer must be greater than 0".into());
        }
        if let Some(key_hex) = &self.signing_key_hex {
            let decoded = hex::decode(key_hex)
                .map_err(|err| format!("signing_key_hex is not valid hex: {err}"))?;
            if decoded.len() != 32 {
                return Err(format!(
                    "signing_key_hex must decode to 32 bytes (Ed25519 seed), got {}",
                    decoded.len()
                ));
            }
        }
        Ok(())
    }
}

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

    #[test]
    fn validate_accepts_default_config() {
        Config::default()
            .validate()
            .expect("default config is valid");
    }

    #[test]
    fn validate_rejects_zero_evidence_buffer() {
        let config = Config {
            max_evidence_buffer: 0,
            ..Config::default()
        };
        let err = config.validate().expect_err("zero buffer must be rejected");
        assert!(err.contains("max_evidence_buffer"), "got: {err}");
    }

    #[test]
    fn validate_accepts_32_byte_hex_signing_key() {
        let config = Config {
            signing_key_hex: Some("00".repeat(32)),
            ..Config::default()
        };
        config.validate().expect("32-byte hex key is valid");
    }

    #[test]
    fn validate_rejects_non_hex_signing_key() {
        let config = Config {
            signing_key_hex: Some("<inject-at-deploy-time>".into()),
            ..Config::default()
        };
        let err = config.validate().expect_err("non-hex key must be rejected");
        assert!(err.contains("not valid hex"), "got: {err}");
    }

    #[test]
    fn validate_rejects_wrong_length_signing_key() {
        let config = Config {
            signing_key_hex: Some("00".repeat(31)),
            ..Config::default()
        };
        let err = config.validate().expect_err("31-byte key must be rejected");
        assert!(err.contains("32 bytes"), "got: {err}");
    }
}
