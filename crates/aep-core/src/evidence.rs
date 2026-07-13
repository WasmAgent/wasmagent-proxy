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
    /// Risk label from MCP header analysis (e.g. `"credential_prefix:ghp_"`).
    /// `None` when MCP-Method / MCP-Name headers are absent or benign.
    pub mcp_header_risk: Option<String>,
    /// MCP trace correlation — trace ID from the MCP 2026-07-28 stateless
    /// trace model.  Populated from the `mcp-trace-id` request header (falling
    /// back to the configurable `trace_id_header` / `x-b3-traceid`).
    /// `None` when no trace header is present.
    #[serde(default)]
    pub trace_id: Option<String>,
    /// MCP trace correlation — session ID for grouping related actions.
    /// Populated from the `mcp-session-id` request header (falling back to the
    /// configurable `agent_id_header` / `x-agent-id`).
    /// `None` when no session header is present.
    #[serde(default)]
    pub session_id: Option<String>,
}

impl ActionEvidence {
    /// Create a new `ActionEvidence` with all mandatory fields and sensible
    /// defaults for the optional fields (all `None`, `state_changing = false`,
    /// `timestamp_ms = 0`).
    ///
    /// Callers can mutate the returned struct to set `trace_id`, `session_id`,
    /// `parent_action_id`, etc.
    pub fn new(
        action_id: String,
        tool_name: String,
        recording_mode: RecordingMode,
        state_changing: bool,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            action_id,
            tool_name,
            state_changing,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode,
            capability_decision: None,
            mcp_header_risk: None,
            trace_id: None,
            session_id: None,
        }
    }
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
    use crate::recording::RecordingMode;

    #[test]
    fn action_evidence_new_creates_default_optional_fields() {
        let ev = ActionEvidence::new(
            "test-action".into(),
            "GET /test".into(),
            RecordingMode::Validation,
            false,
            1_700_000_000_000,
        );
        assert_eq!(ev.action_id, "test-action");
        assert_eq!(ev.tool_name, "GET /test");
        assert_eq!(ev.recording_mode, RecordingMode::Validation);
        assert!(!ev.state_changing);
        assert_eq!(ev.timestamp_ms, 1_700_000_000_000);
        assert!(ev.precondition_digest.is_none());
        assert!(ev.result_digest.is_none());
        assert!(ev.parent_action_id.is_none());
        assert!(ev.causal_chain_id.is_none());
        assert!(ev.capability_decision.is_none());
        assert!(ev.mcp_header_risk.is_none());
        assert!(ev.trace_id.is_none());
        assert!(ev.session_id.is_none());
    }

    #[test]
    fn action_evidence_serializes_trace_id_and_session_id() {
        let mut ev = ActionEvidence::new(
            "ctx-1".into(),
            "POST /api/data".into(),
            RecordingMode::Full,
            true,
            42,
        );
        ev.trace_id = Some("mcp-trace-abc".into());
        ev.session_id = Some("session-xyz".into());

        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"trace_id\":\"mcp-trace-abc\""));
        assert!(json.contains("\"session_id\":\"session-xyz\""));
    }

    #[test]
    fn action_evidence_deserializes_missing_trace_fields_as_none() {
        let json = r#"{
            \"action_id\": \"a\",
            \"tool_name\": \"t\",
            \"state_changing\": false,
            \"timestamp_ms\": 0,
            \"recording_mode\": \"validation\"
        }"#;
        let ev: ActionEvidence = serde_json::from_str(json).unwrap();
        assert!(ev.trace_id.is_none());
        assert!(ev.session_id.is_none());
    }

    #[test]
    fn aep_record_round_trip() {
        let record = AepRecord {
            schema_version: "aep/v0.1".into(),
            run_id: "run-1".into(),
            trace_id: Some("abc".into()),
            session_id: None,
            actions: vec![],
            created_at_ms: 42,
            signature: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        let deser: AepRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.schema_version, "aep/v0.1");
        assert_eq!(deser.trace_id.as_deref(), Some("abc"));
        assert!(deser.session_id.is_none());
        assert!(deser.actions.is_empty());
        assert!(deser.signature.is_none());
    }
}
