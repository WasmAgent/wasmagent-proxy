use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// The `schema_version` value this proxy emits in serialized `AepRecord`s.
///
/// Must stay within the `schema_version` enum declared by the canonical
/// `aep-record` schema owned by `WasmAgent/wasmagent-protocol`
/// (`aep/v0.1` … `aep/v0.3`); schema changes go through that repo's
/// CONTRACT-CHANGE-PROCESS, never through a local fork of the schema.
pub const AEP_SCHEMA_VERSION: &str = "aep/v0.1";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvidence {
    pub action_id: String,
    pub tool_name: String,
    pub state_changing: bool,
    // Optional fields are omitted (never serialized as null) so records
    // validate against the canonical aep-record schema, which types these
    // fields as `string`/`object` — a JSON null would fail validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precondition_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    pub timestamp_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causal_chain_id: Option<String>,
    pub recording_mode: RecordingMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_decision: Option<CapabilityDecision>,
    /// `McpHeaderRisk` variant name in `snake_case` (e.g. `credential_leak`)
    /// when MCP header leakage is detected, else `None`. Stored as a plain
    /// `String` so the serialized AEP record uses stable lowercase identifiers
    /// and downstream consumers need no Rust enum definition to read it.
    /// Producers convert from the enum via [`McpHeaderRisk::as_str`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_header_risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepRecord {
    pub schema_version: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub actions: Vec<ActionEvidence>,
    pub created_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    fn schema_version_constant_is_in_canonical_enum() {
        // The canonical aep-record schema (wasmagent-protocol) declares
        // schema_version as an enum; "aep/v0.1" is its first entry. The value
        // must carry the "v" — "aep/0.1" fails schema validation.
        assert_eq!(AEP_SCHEMA_VERSION, "aep/v0.1");
    }

    #[test]
    fn absent_optional_fields_are_omitted_not_null() {
        // The canonical schema types trace_id/signature and the optional
        // ActionEvidence fields as string/object; a serialized null would
        // fail validation against it.
        let record = AepRecord {
            schema_version: AEP_SCHEMA_VERSION.into(),
            run_id: "run-1".into(),
            trace_id: None,
            session_id: None,
            actions: vec![ActionEvidence {
                action_id: "act-1".into(),
                tool_name: "GET /x".into(),
                state_changing: false,
                precondition_digest: None,
                result_digest: None,
                timestamp_ms: 1_700_000_000_000,
                parent_action_id: None,
                causal_chain_id: None,
                recording_mode: RecordingMode::Validation,
                capability_decision: None,
                mcp_header_risk: None,
            }],
            created_at_ms: 1_700_000_000_000,
            signature: None,
        };

        let json = serde_json::to_string(&record).expect("serialize AepRecord");
        for absent in [
            "\"trace_id\"",
            "\"session_id\"",
            "\"signature\"",
            "\"precondition_digest\"",
            "\"result_digest\"",
            "\"parent_action_id\"",
            "\"causal_chain_id\"",
            "\"capability_decision\"",
            "\"mcp_header_risk\"",
            "null",
        ] {
            assert!(!json.contains(absent), "expected no {absent} in: {json}");
        }
    }

    #[test]
    fn present_optional_fields_round_trip_after_omission_change() {
        let record = AepRecord {
            schema_version: AEP_SCHEMA_VERSION.into(),
            run_id: "run-2".into(),
            trace_id: Some("trace-xyz".into()),
            session_id: None,
            actions: vec![ActionEvidence {
                action_id: "act-2".into(),
                tool_name: "POST /mcp".into(),
                state_changing: true,
                precondition_digest: Some("sha256:pre".into()),
                result_digest: Some("sha256:post".into()),
                timestamp_ms: 1_700_000_000_001,
                parent_action_id: None,
                causal_chain_id: Some("chain-1".into()),
                recording_mode: RecordingMode::Full,
                capability_decision: None,
                mcp_header_risk: Some(McpHeaderRisk::PiiLeak.as_str().into()),
            }],
            created_at_ms: 1_700_000_000_001,
            signature: None,
        };

        let json = serde_json::to_string(&record).expect("serialize AepRecord");
        assert!(json.contains("\"trace_id\":\"trace-xyz\""), "got: {json}");
        assert!(
            json.contains("\"causal_chain_id\":\"chain-1\""),
            "got: {json}"
        );

        let decoded: AepRecord = serde_json::from_str(&json).expect("deserialize AepRecord");
        assert_eq!(decoded.trace_id.as_deref(), Some("trace-xyz"));
        assert_eq!(
            decoded.actions[0].precondition_digest.as_deref(),
            Some("sha256:pre")
        );
        assert_eq!(
            decoded.actions[0].mcp_header_risk.as_deref(),
            Some("pii_leak")
        );
    }

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
