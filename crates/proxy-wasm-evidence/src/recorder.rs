use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

/// Infer [`SideEffectClass`] from HTTP method + path heuristics.
///
/// This is the gateway-level default classifier. In a real deployment, callers can
/// override via the `x-aep-side-effect-class` request header.
///
/// # Design rationale (issue #23)
///
/// The previous implementation mapped every mutation method (POST/PUT/PATCH/DELETE) to
/// [`SideEffectClass::MutateExternal`], which unconditionally produced
/// [`RecordingMode::Full`] (full request/response capture). This was overly
/// conservative for the common case: a gateway proxy intercepting standard CRUD
/// traffic where the mutation target is the service's own data store — a **local**
/// state change from the gateway's perspective.
///
/// By classifying normal-path POST/PUT/PATCH as [`SideEffectClass::MutateLocal`] we
/// get [`RecordingMode::Delta`] (state-diff evidence), which is sufficient for
/// auditability while avoiding the storage and latency cost of full capture on every
/// write. [`MutateExternal`] → Full is reserved for genuinely destructive operations
/// (DELETE) and confirmed external calls (network/webhook paths).
///
/// # Classification rules
///
/// | Method                         | Path              | Class            | Recording |
/// |--------------------------------|-------------------|------------------|-----------|
/// | GET / HEAD / OPTIONS          | any               | `Read`           | Validation |
/// | POST / PUT / PATCH            | normal            | `MutateLocal`    | Delta     |
/// | DELETE                         | normal            | `MutateExternal` | Full      |
/// | any mutation (POST/PUT/PATCH/DELETE) | `/network/…` or `…/webhook…` | `NetworkEgress` | Full      |
/// | other                          | any               | `Unknown`        | Full      |
pub fn infer_side_effect_class(method: &str, path: &str) -> SideEffectClass {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => SideEffectClass::Read,
        "DELETE" => {
            if path.contains("/network/") || path.contains("/webhook") {
                SideEffectClass::NetworkEgress
            } else {
                SideEffectClass::MutateExternal
            }
        }
        "POST" | "PUT" | "PATCH" => {
            if path.contains("/network/") || path.contains("/webhook") {
                SideEffectClass::NetworkEgress
            } else {
                SideEffectClass::MutateLocal
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
                infer_side_effect_class(method, "/anything"),
                SideEffectClass::Read
            );
        }
    }

    #[test]
    fn classifies_mutate_local_for_post_put_patch() {
        // POST/PUT/PATCH on normal paths → MutateLocal (not MutateExternal)
        assert_eq!(
            infer_side_effect_class("POST", "/users"),
            SideEffectClass::MutateLocal
        );
        assert_eq!(
            infer_side_effect_class("PUT", "/users/42"),
            SideEffectClass::MutateLocal
        );
        assert_eq!(
            infer_side_effect_class("PATCH", "/settings/profile"),
            SideEffectClass::MutateLocal
        );
    }

    #[test]
    fn classifies_delete_as_mutate_external() {
        // DELETE is destructive → MutateExternal
        assert_eq!(
            infer_side_effect_class("DELETE", "/users/42"),
            SideEffectClass::MutateExternal
        );
    }

    #[test]
    fn classifies_network_egress_from_mutation_paths() {
        // Both mutation and delete to network/webhook paths → NetworkEgress
        assert_eq!(
            infer_side_effect_class("POST", "/network/peers"),
            SideEffectClass::NetworkEgress
        );
        assert_eq!(
            infer_side_effect_class("PUT", "/v1/webhook/xyz"),
            SideEffectClass::NetworkEgress
        );
        assert_eq!(
            infer_side_effect_class("DELETE", "/network/peers/42"),
            SideEffectClass::NetworkEgress
        );
    }

    #[test]
    fn classifies_unknown_methods() {
        assert_eq!(
            infer_side_effect_class("PROPFIND", "/"),
            SideEffectClass::Unknown
        );
        assert_eq!(infer_side_effect_class("", ""), SideEffectClass::Unknown);
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
            "DELETE /users/42".into(),
            &risk(SideEffectClass::MutateExternal),
            42,
            Some(digest.clone()),
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
        assert_eq!(ev.precondition_digest.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn post_to_normal_path_yields_mutate_local_then_delta() {
        // End-to-end: POST /users classifies as MutateLocal → build_evidence records Delta
        let class = infer_side_effect_class("POST", "/users");
        assert_eq!(class, SideEffectClass::MutateLocal);

        let ev = build_evidence(
            "ctx-3".into(),
            "POST /users".into(),
            &risk(class),
            100,
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Delta);
    }

    #[test]
    fn get_yields_read_then_validation() {
        // End-to-end: GET /items classifies as Read → build_evidence records Validation
        let class = infer_side_effect_class("GET", "/items");
        assert_eq!(class, SideEffectClass::Read);

        let ev = build_evidence("ctx-4".into(), "GET /items".into(), &risk(class), 200, None);
        assert!(!ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Validation);
    }

    #[test]
    fn post_to_webhook_yields_network_egress_then_full() {
        // End-to-end: POST /webhook classifies as NetworkEgress → Full
        let class = infer_side_effect_class("POST", "/api/v1/webhook/hook1");
        assert_eq!(class, SideEffectClass::NetworkEgress);

        let ev = build_evidence(
            "ctx-5".into(),
            "POST /api/v1/webhook/hook1".into(),
            &risk(class),
            300,
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
    }
}
