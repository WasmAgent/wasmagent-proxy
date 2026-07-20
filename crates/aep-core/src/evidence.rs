use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Risk level detected in MCP-specific headers (MCP 2026-07-28+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// `McpHeaderRisk` variant name in `snake_case` (e.g. `credential_leak`)
    /// when MCP header leakage is detected, else `None`. Stored as a plain
    /// `String` so the serialized AEP record uses stable lowercase identifiers
    /// and downstream consumers need no Rust enum definition to read it.
    /// Producers convert from the enum via [`McpHeaderRisk::as_str`].
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
            mcp_header_risk: Some("credential_leak".into()),
        };

        let value = serde_json::to_value(evidence).expect("serialize ActionEvidence");

        assert_eq!(value["mcp_header_risk"], "credential_leak");
    }

    #[test]
    fn action_evidence_mcp_header_risk_round_trips_as_plain_string() {
        // The field is `Option<String>` carrying the snake_case variant name:
        // prove it survives a serialize→deserialize round trip as a plain
        // string (not an enum), so downstream consumers need no Rust enum
        // definition to read it. Exercises the HighEntropyValue variant, which
        // the serialize-only test above does not cover.
        let original = ActionEvidence {
            action_id: "action-rt".into(),
            tool_name: "POST /mcp".into(),
            state_changing: true,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1_700_000_000_001,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Validation,
            capability_decision: None,
            mcp_header_risk: Some(McpHeaderRisk::HighEntropyValue.as_str().into()),
        };

        let json = serde_json::to_string(&original).expect("serialize ActionEvidence");
        assert!(
            json.contains("\"mcp_header_risk\":\"high_entropy_value\""),
            "expected snake_case variant name in JSON, got: {json}"
        );

        let decoded: ActionEvidence =
            serde_json::from_str(&json).expect("deserialize ActionEvidence");
        assert_eq!(
            decoded.mcp_header_risk.as_deref(),
            Some(McpHeaderRisk::HighEntropyValue.as_str())
        );
    }
}
