use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Risk level detected in MCP-specific headers (MCP 2026-07-28+).
///
/// Serialized as the snake_case variant name on the wire (e.g. `"credential_leak"`)
/// via `#[serde(rename_all = "snake_case")]`, matching the AEP evidence JSON contract.
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
    /// Returns the canonical snake_case wire name of this variant.
    ///
    /// This mirrors the `#[serde(rename_all = "snake_case")]` serialization, exposed
    /// as a helper for non-serde contexts such as forming the `x-aep-mcp-header-risk`
    /// HTTP header value.
    pub fn as_snake_case(&self) -> &'static str {
        match self {
            Self::CredentialLeak => "credential_leak",
            Self::HighEntropyValue => "high_entropy_value",
            Self::PiiLeak => "pii_leak",
        }
    }

    /// Parses a snake_case wire name back into the typed [`McpHeaderRisk`] variant.
    ///
    /// Returns the matching variant, or `None` if the string is not a recognized
    /// `McpHeaderRisk` snake_case name (e.g. typos like `"CredientialLeak"` or
    /// bogus values like `"invalid_risk"`). Useful when consuming a raw risk
    /// string sourced outside serde (e.g. the `x-aep-mcp-header-risk` HTTP header
    /// or hand-rolled JSON), so an unrecognized value cannot be mistaken for a
    /// real variant.
    pub fn from_snake_case(s: &str) -> Option<McpHeaderRisk> {
        Some(match s {
            "credential_leak" => McpHeaderRisk::CredentialLeak,
            "high_entropy_value" => McpHeaderRisk::HighEntropyValue,
            "pii_leak" => McpHeaderRisk::PiiLeak,
            _ => return None,
        })
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
    /// Detected MCP header leakage risk as the snake_case `McpHeaderRisk` variant
    /// name (e.g. `"credential_leak"`). `None` when no leakage is detected.
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
        ev.mcp_header_risk = Some(McpHeaderRisk::CredentialLeak.as_snake_case().into());
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"mcp_header_risk\":\"credential_leak\""));
    }

    #[test]
    fn mcp_header_risk_roundtrips_all_variants() {
        for (variant, snake) in [
            (McpHeaderRisk::CredentialLeak, "credential_leak"),
            (McpHeaderRisk::HighEntropyValue, "high_entropy_value"),
            (McpHeaderRisk::PiiLeak, "pii_leak"),
        ] {
            let mut ev = minimal_evidence();
            ev.mcp_header_risk = Some(variant.as_snake_case().into());
            let json = serde_json::to_string(&ev).unwrap();
            assert!(
                json.contains(&format!("\"mcp_header_risk\":\"{snake}\"")),
                "{:?} should serialize as \"{snake}\"",
                variant
            );
            let back: ActionEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(
                back.mcp_header_risk.as_deref(),
                Some(snake),
                "roundtrip failed for \"{snake}\""
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

    #[test]
    fn mcp_header_risk_from_snake_case_validates_known_and_rejects_unknown() {
        // Known snake_case names round-trip back into the typed enum.
        for (snake, variant) in [
            ("credential_leak", McpHeaderRisk::CredentialLeak),
            ("high_entropy_value", McpHeaderRisk::HighEntropyValue),
            ("pii_leak", McpHeaderRisk::PiiLeak),
        ] {
            assert_eq!(
                McpHeaderRisk::from_snake_case(snake),
                Some(variant),
                "from_snake_case({}) should recover the variant",
                snake
            );
        }

        // Invalid / typo strings are rejected (None), so an unrecognized wire name
        // cannot be mistaken for a real McpHeaderRisk variant.
        for invalid in [
            "invalid_risk",
            "CredientialLeak",
            "credentialLeak",
            "credential-leak",
            "",
        ] {
            assert_eq!(
                McpHeaderRisk::from_snake_case(invalid),
                None,
                "from_snake_case({}) should be None for a non-variant string",
                invalid
            );
        }
    }

    #[test]
    fn as_snake_case_matches_serde_wire_name() {
        // Guards against as_snake_case() drifting from the
        // #[serde(rename_all = "snake_case")] wire name.
        for variant in [
            McpHeaderRisk::CredentialLeak,
            McpHeaderRisk::HighEntropyValue,
            McpHeaderRisk::PiiLeak,
        ] {
            let serde_str = serde_json::to_string(&variant).unwrap();
            let expected = format!("\"{}\"", variant.as_snake_case());
            assert_eq!(
                serde_str, expected,
                "serde wire name drifted from as_snake_case() for {:?}",
                variant
            );
        }
    }
}
