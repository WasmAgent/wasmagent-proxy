use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

/// Infer SideEffectClass from HTTP method + path heuristics, with optional
/// MCP method override for higher-signal classification.
///
/// When `mcp_method` is provided (MCP 2026-07-28 stateless/handle-based
/// requests), it takes precedence over HTTP-level heuristics for known MCP
/// method patterns:
///
/// - `tools/call` → `MutateExternal` (tool invocations are external side-effects)
/// - `resources/read` → `Read` (resource reads are non-mutating)
/// - `resources/subscribe` → `Read` (subscriptions are observational)
/// - `prompts/get` → `Read`
///
/// Falls back to HTTP method + path heuristics when `mcp_method` is absent or
/// unrecognized. In a real deployment, callers can set
/// `x-aep-side-effect-class` header to override.
pub fn infer_side_effect_class(
    method: &str,
    path: &str,
    mcp_method: Option<&str>,
) -> SideEffectClass {
    // Prefer MCP method-based classification when available.
    if let Some(mcp) = mcp_method {
        match mcp {
            "tools/call" => return SideEffectClass::MutateExternal,
            "resources/read" | "resources/subscribe" | "prompts/get" => {
                return SideEffectClass::Read;
            }
            _ => {} // Fall through to HTTP heuristics for unrecognized methods.
        }
    }
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => SideEffectClass::Read,
        "POST" | "PUT" | "PATCH" | "DELETE" => {
            if path.contains("/network/") || path.contains("/webhook") {
                SideEffectClass::NetworkEgress
            } else {
                SideEffectClass::MutateExternal
            }
        }
        _ => SideEffectClass::Unknown,
    }
}

pub fn build_evidence(
    action_id: String,
    tool_name: String,
    risk_ctx: &RiskContext,
    timestamp_ms: u64,
    precondition_digest: Option<String>,
) -> ActionEvidence {
    let policy = compile_recording_policy(risk_ctx);
    ActionEvidence {
        action_id,
        tool_name,
        state_changing: !matches!(risk_ctx.side_effect_class, SideEffectClass::Read),
        precondition_digest,
        result_digest: None,
        timestamp_ms,
        parent_action_id: None,
        causal_chain_id: None,
        recording_mode: policy.mode,
        capability_decision: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aep_core::recording::RecordingMode;

    fn risk(side_effect_class: SideEffectClass) -> RiskContext {
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        }
    }

    #[test]
    fn classifies_read_methods() {
        for method in ["GET", "head", "OpTiOnS"] {
            assert_eq!(
                infer_side_effect_class(method, "/anything", None),
                SideEffectClass::Read
            );
        }
    }

    #[test]
    fn classifies_external_mutations() {
        assert_eq!(
            infer_side_effect_class("POST", "/users", None),
            SideEffectClass::MutateExternal
        );
        assert_eq!(
            infer_side_effect_class("DELETE", "/users/42", None),
            SideEffectClass::MutateExternal
        );
    }

    #[test]
    fn classifies_network_egress_by_path() {
        assert_eq!(
            infer_side_effect_class("POST", "/network/peers", None),
            SideEffectClass::NetworkEgress
        );
        assert_eq!(
            infer_side_effect_class("PUT", "/v1/webhook/xyz", None),
            SideEffectClass::NetworkEgress
        );
    }

    #[test]
    fn classifies_unknown_methods() {
        assert_eq!(
            infer_side_effect_class("PROPFIND", "/", None),
            SideEffectClass::Unknown
        );
        assert_eq!(
            infer_side_effect_class("", "", None),
            SideEffectClass::Unknown
        );
    }

    #[test]
    fn mcp_tools_call_classifies_as_mutate_external() {
        assert_eq!(
            infer_side_effect_class("POST", "/mcp", Some("tools/call")),
            SideEffectClass::MutateExternal,
        );
        // MCP method takes precedence over HTTP method/path heuristics.
        assert_eq!(
            infer_side_effect_class("GET", "/mcp", Some("tools/call")),
            SideEffectClass::MutateExternal,
        );
    }

    #[test]
    fn mcp_resources_read_classifies_as_read() {
        assert_eq!(
            infer_side_effect_class("POST", "/mcp", Some("resources/read")),
            SideEffectClass::Read,
        );
        assert_eq!(
            infer_side_effect_class("POST", "/mcp", Some("resources/subscribe")),
            SideEffectClass::Read,
        );
        assert_eq!(
            infer_side_effect_class("POST", "/mcp", Some("prompts/get")),
            SideEffectClass::Read,
        );
    }

    #[test]
    fn unrecognized_mcp_method_falls_through_to_http_heuristics() {
        assert_eq!(
            infer_side_effect_class("GET", "/data", Some("custom/method")),
            SideEffectClass::Read,
        );
        assert_eq!(
            infer_side_effect_class("DELETE", "/data", Some("custom/method")),
            SideEffectClass::MutateExternal,
        );
    }

    #[test]
    fn mcp_method_none_falls_through_to_http_heuristics() {
        assert_eq!(
            infer_side_effect_class("GET", "/data", None),
            SideEffectClass::Read,
        );
    }

    #[test]
    fn build_evidence_marks_reads_as_non_state_changing() {
        let ev = build_evidence(
            "ctx-1".into(),
            "GET /x".into(),
            &risk(SideEffectClass::Read),
            1_700_000_000_000,
            None,
        );
        assert!(!ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Validation);
        assert_eq!(ev.action_id, "ctx-1");
        assert_eq!(ev.tool_name, "GET /x");
        assert_eq!(ev.timestamp_ms, 1_700_000_000_000);
        assert!(ev.precondition_digest.is_none());
        assert!(ev.result_digest.is_none());
        assert!(ev.capability_decision.is_none());
    }

    #[test]
    fn build_evidence_marks_external_mutation_as_state_changing_and_full() {
        let digest = "sha256:abc".to_string();
        let ev = build_evidence(
            "ctx-2".into(),
            "POST /payments".into(),
            &risk(SideEffectClass::MutateExternal),
            42,
            Some(digest.clone()),
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
        assert_eq!(ev.precondition_digest.as_deref(), Some(digest.as_str()));
    }
}
