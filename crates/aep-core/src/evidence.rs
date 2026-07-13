use serde::{Deserialize, Serialize};
use crate::recording::RecordingMode;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepRecord {
    pub schema_version: String,
    pub run_id: String,
    /// Distributed trace ID (e.g. from x-b3-traceid). Under MCP 2026-07-28
    /// stateless architecture this may not span a full conversation context;
    /// prefer `handle_id` for correlating evidence across independent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional handle ID for stateless request tracking under MCP 2026-07-28.
    /// Under the stateless/handle-based architecture, protocol-level sessions no
    /// longer exist. Each request is independent, and a handle ID (threaded by
    /// the model between tool calls as arguments) provides the correlation key.
    /// When present, `handle_id` takes precedence over `session_id` and
    /// `trace_id` for linking evidence records across a logical workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<String>,
    /// Optional session identifier for multi-turn conversations.
    /// Under MCP 2026-07-28 stateless architecture this field SHOULD be empty
    /// because session-level state no longer exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// MCP protocol version header (e.g. `2026-07-28`). Present when the
    /// request carried the MCP-Protocol-Version header, indicating that the
    /// caller is using the MCP protocol and the evidence should be correlated
    /// using MCP-specific fields (`handle_id`, `mcp_method`, `mcp_name`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_protocol_version: Option<String>,
    /// MCP JSON-RPC method name (e.g. `tools/call`, `resources/read`).
    /// Provides higher-signal correlation key under the stateless/handle-based
    /// model when the trace_id alone is insufficient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_method: Option<String>,
    /// MCP tool or resource name (e.g. `search`). Provides additional
    /// correlation context under the stateless/handle-based model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_name: Option<String>,
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
    use crate::recording::RecordingMode;

    #[test]
    fn aep_record_serialization_includes_new_fields() {
        let record = AepRecord {
            schema_version: "aep/v0.1".into(),
            run_id: "run-123".into(),
            trace_id: Some("abc123".into()),
            handle_id: Some("hdl-42".into()),
            session_id: None,
            mcp_protocol_version: Some("2026-07-28".into()),
            mcp_method: Some("tools/call".into()),
            mcp_name: Some("search".into()),
            actions: vec![],
            created_at_ms: 1700000000000,
            signature: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"mcp_protocol_version\":\"2026-07-28\""));
        assert!(json.contains("\"mcp_method\":\"tools/call\""));
        assert!(json.contains("\"mcp_name\":\"search\""));
        assert!(json.contains("\"handle_id\":\"hdl-42\""));
        assert!(json.contains("\"trace_id\":\"abc123\""));
    }

    #[test]
    fn aep_record_skips_empty_mcp_fields() {
        let record = AepRecord {
            schema_version: "aep/v0.1".into(),
            run_id: "run-456".into(),
            trace_id: None,
            handle_id: None,
            session_id: None,
            mcp_protocol_version: None,
            mcp_method: None,
            mcp_name: None,
            actions: vec![],
            created_at_ms: 1700000000001,
            signature: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        // When absent, the fields should not appear in serialized output.
        assert!(!json.contains("mcp_protocol_version"), "{}", json);
        assert!(!json.contains("mcp_method"), "{}", json);
        assert!(!json.contains("mcp_name"), "{}", json);
        assert!(!json.contains("handle_id"), "{}", json);
        assert!(!json.contains("trace_id"), "{}", json);
        assert!(!json.contains("session_id"), "{}", json);
    }

    #[test]
    fn aep_record_deserialization_roundtrip() {
        let json = r#"{
            "schema_version": "aep/v0.1",
            "run_id": "run-789",
            "trace_id": "trace-xyz",
            "handle_id": "hdl-99",
            "session_id": null,
            "mcp_protocol_version": "2026-07-28",
            "mcp_method": "resources/read",
            "mcp_name": "documents",
            "actions": [],
            "created_at_ms": 1700000000002,
            "signature": null
        }"#;
        let record: AepRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.schema_version, "aep/v0.1");
        assert_eq!(record.run_id, "run-789");
        assert_eq!(record.trace_id.as_deref(), Some("trace-xyz"));
        assert_eq!(record.handle_id.as_deref(), Some("hdl-99"));
        assert_eq!(record.mcp_protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(record.mcp_method.as_deref(), Some("resources/read"));
        assert_eq!(record.mcp_name.as_deref(), Some("documents"));
        assert!(record.session_id.is_none());
        assert!(record.signature.is_none());
    }
}
