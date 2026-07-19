use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Risk level detected in MCP-specific headers (MCP 2026-07-28+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpHeaderRisk {
    /// Credential-like pattern detected (e.g. ghp_, sk-, Bearer prefix).
    CredentialLeak,
    /// High-entropy string > 32 chars detected (potential API key).
    HighEntropyValue,
    /// Email-like pattern detected in MCP-Name header.
    PiiLeak,
}

impl McpHeaderRisk {
    /// Returns the snake_case name of this variant for use in `ActionEvidence::mcp_header_risk`.
    pub fn as_snake_case(&self) -> &'static str {
        match self {
            Self::CredentialLeak => "credential_leak",
            Self::HighEntropyValue => "high_entropy_value",
            Self::PiiLeak => "pii_leak",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDecision {
    pub capability: String,
    pub subject: String,
    pub resource: String,
    pub decision: String,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvidence {
    pub action_id: String,
    pub tool_name: String,
    pub state_changing: bool,
    pub precondition_digest: Option<String>,
    pub result_digest: Option<String>,
    pub timestamp_ms: u64,
    pub parent_action_id: Option<String>,
    pub causal_chain_id: Option<String>,
    pub recording_mode: RecordingMode,
    pub capability_decision: Option<CapabilityDecision>,
    /// Snake-case variant name of [`McpHeaderRisk`] when leakage is detected (e.g. `"credential_leak"`).
    pub mcp_header_risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepRecord {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub actions: Vec<ActionEvidence>,
    pub created_at_ms: u64,
    pub signature: Option<AepSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_evidence() -> ActionEvidence {
        ActionEvidence {
            action_id: "act-1".into(),
            tool_name: "test_tool".into(),
            state_changing: false,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1_700_000_000_000,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Validation,
            capability_decision: None,
            mcp_header_risk: None,
        }
    }

    #[test]
    fn mcp_header_risk_none_serializes_absent_or_null() {
        let ev = minimal_evidence();
        let json = serde_json::to_string(&ev).unwrap();
        // When None, serde serializes Option<String> as null
        assert!(json.contains("\"mcp_header_risk\":null"));
    }

    #[test]
    fn mcp_header_risk_some_serializes_snake_case() {
        let mut ev = minimal_evidence();
        ev.mcp_header_risk = Some("credential_leak".to_string());
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"mcp_header_risk\":\"credential_leak\""));
    }

    #[test]
    fn mcp_header_risk_roundtrips_all_variants() {
        for (name, snake) in [
            ("CredentialLeak", "credential_leak"),
            ("HighEntropyValue", "high_entropy_value"),
            ("PiiLeak", "pii_leak"),
        ] {
            let mut ev = minimal_evidence();
            ev.mcp_header_risk = Some(snake.to_string());
            let json = serde_json::to_string(&ev).unwrap();
            let back: ActionEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(
                back.mcp_header_risk,
                Some(snake.to_string()),
                "roundtrip failed for {}",
                name
            );
        }
    }

    #[test]
    fn mcp_header_risk_as_snake_case_matches_variant_names() {
        assert_eq!(
            McpHeaderRisk::CredentialLeak.as_snake_case(),
            "credential_leak"
        );
        assert_eq!(
            McpHeaderRisk::HighEntropyValue.as_snake_case(),
            "high_entropy_value"
        );
        assert_eq!(McpHeaderRisk::PiiLeak.as_snake_case(), "pii_leak");
    }
}
