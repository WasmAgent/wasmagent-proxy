use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

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

/// MCP 2026-07-28 stateless/handle-based trace-correlation fields.
///
/// Bundles the correlation signals threaded through an intercepted request so
/// that [`AepRecord::build_evidence_record`] stays below clippy's
/// `too_many_arguments` threshold while keeping the stateless correlation model
/// explicit. This is the validated trace-correlation model for the MCP
/// 2026-07-28 stateless/handle-based spec.
///
/// # Field precedence (MCP 2026-07-28 stateless model)
///
/// - `handle_id` is the primary cross-request correlation key (threaded by the
///   model between tool calls); prefer it over `trace_id`.
/// - `mcp_protocol_version`, when present, indicates MCP traffic and forces the
///   record's `session_id` to `None` (protocol-level sessions no longer exist).
/// - `trace_id` (e.g. `x-b3-traceid`) is implementation-specific and may not
///   span a full conversation context under the stateless model.
#[derive(Debug, Clone, Default)]
pub struct TraceCorrelation {
    /// Zipkin/OpenTelemetry trace ID (implementation-specific; NOT part of MCP).
    pub trace_id: Option<String>,
    /// MCP handle ID — primary cross-request correlation key under the
    /// stateless/handle-based model.
    pub handle_id: Option<String>,
    /// MCP protocol version header (e.g. `2026-07-28`).
    pub mcp_protocol_version: Option<String>,
    /// MCP JSON-RPC method name (e.g. `tools/call`, `resources/read`).
    pub mcp_method: Option<String>,
    /// MCP tool or resource name (e.g. `search`).
    pub mcp_name: Option<String>,
}

impl TraceCorrelation {
    /// Validates the trace correlation against the MCP 2026-07-28 stateless
    /// model invariants.
    ///
    /// # Invariants checked
    ///
    /// - If `mcp_protocol_version` is `Some`, it must equal `"2026-07-28"`.
    ///   This is the only protocol version supported by the stateless model.
    /// - Under the stateless model, `handle_id` is the primary correlation key;
    ///   a warning is issued via `log::warn!` when `trace_id` is present
    ///   without `handle_id` while MCP protocol is declared.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the correlation fields are consistent with the stateless
    ///   model.
    /// - `Err(String)` with a description of the first invariant violation.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref ver) = self.mcp_protocol_version {
            if ver != "2026-07-28" {
                return Err(format!(
                    "unsupported MCP protocol version: {}, expected 2026-07-28",
                    ver
                ));
            }
            // Under the stateless model, handle_id is the primary correlation
            // key. Issue a warning when trace_id is present without handle_id.
            if self.trace_id.is_some() && self.handle_id.is_none() {
                log::warn!(
                    "trace_id present without handle_id under MCP {}; \
                     handle_id is the preferred correlation key under the \
                     stateless/handle-based model",
                    ver
                );
            }
        }
        Ok(())
    }

    /// Creates a new `TraceCorrelation` from MCP 2026-07-28 stateless/handle-based
    /// correlation header values.
    ///
    /// This is a convenience constructor that calls `validate()` internally.
    /// Prefer this over direct struct construction when the values originate
    /// from external headers.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the MCP protocol version is present but unsupported
    /// (see [`validate`](Self::validate)).
    pub fn from_headers(
        trace_id: Option<String>,
        handle_id: Option<String>,
        mcp_protocol_version: Option<String>,
        mcp_method: Option<String>,
        mcp_name: Option<String>,
    ) -> Result<Self, String> {
        let correlation = TraceCorrelation {
            trace_id,
            handle_id,
            mcp_protocol_version,
            mcp_method,
            mcp_name,
        };
        correlation.validate()?;
        Ok(correlation)
    }
}

impl AepRecord {
    /// The schema version constant used by the AEP evidence format.
    pub const SCHEMA_VERSION: &'static str = "aep/v0.1";

    /// Build a new AEP record from an action evidence and MCP 2026-07-28
    /// stateless/handle-based correlation fields.
    ///
    /// Under the MCP 2026-07-28 stateless architecture:
    ///
    /// - Each request is independent; protocol-level sessions no longer exist.
    ///   Consequently `session_id` is always `None` when MCP protocol version
    ///   is declared.
    /// - `handle_id` is the primary correlation key, taking precedence over
    ///   `trace_id` for linking evidence records across independent requests.
    /// - MCP-specific fields (`mcp_method`, `mcp_name`) provide higher-signal
    ///   correlation context under the stateless model.
    ///
    /// # Validation enforced
    ///
    /// - When `mcp_protocol_version` is `Some`, `session_id` is forced to
    ///   `None` because the stateless model explicitly deprecates session-level
    ///   state.
    pub fn build_evidence_record(
        action: ActionEvidence,
        correlation: TraceCorrelation,
        run_id: String,
        created_at_ms: u64,
    ) -> Self {
        // Under the MCP 2026-07-28 stateless model, protocol-level session
        // state no longer exists, so `session_id` is always `None`; the handle
        // ID in `correlation` is the primary cross-request correlation key.
        AepRecord {
            schema_version: Self::SCHEMA_VERSION.into(),
            run_id,
            trace_id: correlation.trace_id,
            handle_id: correlation.handle_id,
            session_id: None,
            mcp_protocol_version: correlation.mcp_protocol_version,
            mcp_method: correlation.mcp_method,
            mcp_name: correlation.mcp_name,
            actions: vec![action],
            created_at_ms,
            signature: None,
        }
    }
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

    #[test]
    fn build_evidence_record_with_mcp_fields() {
        let action = ActionEvidence {
            action_id: "act-1".into(),
            tool_name: "search".into(),
            state_changing: true,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1700000000003,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Full,
            capability_decision: None,
        };

        let record = AepRecord::build_evidence_record(
            action.clone(),
            TraceCorrelation {
                trace_id: Some("trace-abc".into()),
                handle_id: Some("hdl-42".into()),
                mcp_protocol_version: Some("2026-07-28".into()),
                mcp_method: Some("tools/call".into()),
                mcp_name: Some("search".into()),
            },
            "run-999".into(),
            1700000000004,
        );

        assert_eq!(record.schema_version, "aep/v0.1");
        assert_eq!(record.run_id, "run-999");
        assert_eq!(record.trace_id.as_deref(), Some("trace-abc"));
        assert_eq!(record.handle_id.as_deref(), Some("hdl-42"));
        assert_eq!(record.mcp_protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(record.mcp_method.as_deref(), Some("tools/call"));
        assert_eq!(record.mcp_name.as_deref(), Some("search"));
        // Under MCP 2026-07-28 stateless model, session_id is None
        assert!(record.session_id.is_none());
        assert_eq!(record.actions.len(), 1);
        assert_eq!(record.actions[0].action_id, "act-1");
        assert_eq!(record.actions[0].tool_name, "search");
        assert_eq!(record.created_at_ms, 1700000000004);
        assert!(record.signature.is_none());
    }

    #[test]
    fn build_evidence_record_without_mcp_headers() {
        let action = ActionEvidence {
            action_id: "act-2".into(),
            tool_name: "GET /data".into(),
            state_changing: false,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1700000000005,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Validation,
            capability_decision: None,
        };

        let record = AepRecord::build_evidence_record(
            action.clone(),
            TraceCorrelation {
                trace_id: Some("trace-xyz".into()),
                ..Default::default()
            },
            "run-888".into(),
            1700000000006,
        );

        assert_eq!(record.schema_version, "aep/v0.1");
        assert_eq!(record.run_id, "run-888");
        assert_eq!(record.trace_id.as_deref(), Some("trace-xyz"));
        assert!(record.handle_id.is_none());
        assert!(record.mcp_protocol_version.is_none());
        assert!(record.mcp_method.is_none());
        assert!(record.mcp_name.is_none());
        assert!(record.session_id.is_none());
        assert_eq!(record.actions.len(), 1);
        assert_eq!(record.actions[0].action_id, "act-2");
        assert_eq!(record.created_at_ms, 1700000000006);
    }

    #[test]
    fn trace_correlation_validate_ok() {
        let tc = TraceCorrelation {
            trace_id: Some("abc".into()),
            handle_id: Some("hdl-1".into()),
            mcp_protocol_version: Some("2026-07-28".into()),
            mcp_method: Some("tools/call".into()),
            mcp_name: Some("search".into()),
        };
        assert!(tc.validate().is_ok());
    }

    #[test]
    fn trace_correlation_validate_rejects_unsupported_version() {
        let tc = TraceCorrelation {
            mcp_protocol_version: Some("2026-03-15".into()),
            ..Default::default()
        };
        let err = tc.validate().unwrap_err();
        assert!(err.contains("unsupported"), "got: {}", err);
    }

    #[test]
    fn trace_correlation_validate_accepts_no_version() {
        let tc = TraceCorrelation {
            trace_id: Some("xyz".into()),
            ..Default::default()
        };
        assert!(tc.validate().is_ok());
    }

    #[test]
    fn trace_correlation_validate_warns_on_trace_id_without_handle_id() {
        // When MCP version is declared and trace_id is present without
        // handle_id, validate() should succeed (the warning is informational).
        let tc = TraceCorrelation {
            trace_id: Some("abc".into()),
            handle_id: None,
            mcp_protocol_version: Some("2026-07-28".into()),
            ..Default::default()
        };
        assert!(tc.validate().is_ok());
    }

    #[test]
    fn trace_correlation_from_headers_ok() {
        let tc = TraceCorrelation::from_headers(
            Some("trace-1".into()),
            Some("hdl-99".into()),
            Some("2026-07-28".into()),
            Some("resources/read".into()),
            Some("documents".into()),
        )
        .unwrap();
        assert_eq!(tc.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(tc.handle_id.as_deref(), Some("hdl-99"));
        assert_eq!(tc.mcp_protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(tc.mcp_method.as_deref(), Some("resources/read"));
        assert_eq!(tc.mcp_name.as_deref(), Some("documents"));
    }

    #[test]
    fn trace_correlation_from_headers_rejects_bad_version() {
        let err = TraceCorrelation::from_headers(
            None,
            None,
            Some("bad-version".into()),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("unsupported"), "got: {}", err);
    }

    #[test]
    fn trace_correlation_from_headers_accepts_missing_version() {
        let tc = TraceCorrelation::from_headers(
            Some("t".into()),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(tc.trace_id.as_deref(), Some("t"));
        assert!(tc.handle_id.is_none());
        assert!(tc.mcp_protocol_version.is_none());
    }
}
