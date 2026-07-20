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
    /// Return the variant name in `snake_case` form.
    ///
    /// This is the canonical string carried by
    /// [`ActionEvidence::mcp_header_risk`] when leakage is detected, so that
    /// the serialized AEP record uses stable lowercase identifiers (e.g.
    /// `credential_leak`) rather than the Rust PascalCase variant names.
    pub fn as_str(&self) -> &'static str {
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
    /// `McpHeaderRisk` variant name in `snake_case` when MCP header leakage is
    /// detected, else `None`. Stored as a plain string so downstream consumers
    /// (and the FAEP schema) need no Rust enum definition to read the value.
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

    #[test]
    fn mcp_header_risk_as_str_returns_snake_case_variant_name() {
        assert_eq!(McpHeaderRisk::CredentialLeak.as_str(), "credential_leak");
        assert_eq!(
            McpHeaderRisk::HighEntropyValue.as_str(),
            "high_entropy_value"
        );
        assert_eq!(McpHeaderRisk::PiiLeak.as_str(), "pii_leak");
    }

    #[test]
    fn action_evidence_serializes_mcp_header_risk_as_snake_case_string() {
        let evidence = ActionEvidence {
            action_id: "action-1".into(),
            tool_name: "POST /mcp".into(),
            state_changing: true,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1_700_000_000_000,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Full,
            capability_decision: None,
            mcp_header_risk: Some(McpHeaderRisk::CredentialLeak.as_str().to_owned()),
        };

        let value = serde_json::to_value(evidence).expect("serialize ActionEvidence");

        assert_eq!(value["mcp_header_risk"], "credential_leak");
    }
}
