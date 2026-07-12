use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

/// Infer [`SideEffectClass`] from HTTP method + path heuristics.
///
/// This is the gateway-level default (heuristic) classifier. It does **not**
/// consult the `x-aep-side-effect-class` request header — use
/// [`resolve_side_effect_class`] for the entry point that honors a
/// caller-supplied override.
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

/// Resolve the effective [`SideEffectClass`] for a request, honoring an explicit
/// caller-supplied override from the `x-aep-side-effect-class` request header.
///
/// The gateway's method/path heuristics ([`infer_side_effect_class`]) are a
/// conservative default. Some deployments carry high-volume traffic that the
/// heuristic would capture in full — for example internal mesh control-plane
/// calls on `/network/…` paths classify as [`SideEffectClass::NetworkEgress`]
/// and thus record in full (`RecordingMode::Full`). To avoid storage exhaustion
/// on such traffic, an operator (or an upstream L7 policy) may pin a specific
/// class for a request via the override header, superseding the heuristic.
///
/// Accepted values are the snake_case forms used in AEP records (`read`,
/// `mutate_local`, `mutate_external`, `network_egress`, `unknown`); kebab-case
/// and any ASCII casing are also accepted because the value travels in an HTTP
/// header. An unrecognized value is ignored and the heuristic is used, so a
/// malformed override never breaks the request.
pub fn resolve_side_effect_class(
    override_header: Option<&str>,
    method: &str,
    path: &str,
) -> SideEffectClass {
    if let Some(raw) = override_header {
        let normalized = raw.trim().to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "read" => return SideEffectClass::Read,
            "mutate_local" => return SideEffectClass::MutateLocal,
            "mutate_external" => return SideEffectClass::MutateExternal,
            "network_egress" => return SideEffectClass::NetworkEgress,
            "unknown" => return SideEffectClass::Unknown,
            _ => {}
        }
    }
    infer_side_effect_class(method, path)
}

/// Build an [`ActionEvidence`] record for a single proxied action.
///
/// `state_changing` is a coarse read-vs-mutate summary (`false` only for
/// [`SideEffectClass::Read`]); it is intentionally not a per-method flag. The
/// full method and path are preserved verbatim in `tool_name`, and the recording
/// granularity (`validation` / `delta` / `full`) is preserved in `recording_mode`,
/// so downstream consumers that need to distinguish e.g. GET from POST read both
/// fields rather than relying on `state_changing` alone.
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

    #[test]
    fn state_changing_flag_distinguishes_read_from_mutate() {
        // Review finding #1: `state_changing` is a coarse read-vs-mutate flag by
        // design — GET (Read) is false, POST (MutateLocal) is true. The full method
        // is retained in `tool_name` and the recording granularity in
        // `recording_mode`, so GET-vs-POST is not silently dropped.
        let get_ev = build_evidence(
            "get".into(),
            "GET /items".into(),
            &risk(SideEffectClass::Read),
            0,
            None,
        );
        let post_ev = build_evidence(
            "post".into(),
            "POST /items".into(),
            &risk(SideEffectClass::MutateLocal),
            0,
            None,
        );
        assert!(!get_ev.state_changing);
        assert!(post_ev.state_changing);
        assert_eq!(get_ev.tool_name, "GET /items");
        assert_eq!(post_ev.tool_name, "POST /items");
        assert_eq!(get_ev.recording_mode, RecordingMode::Validation);
        assert_eq!(post_ev.recording_mode, RecordingMode::Delta);
    }

    #[test]
    fn unknown_method_is_fail_closed_to_full_capture() {
        // Review finding #2: an unrecognized method (e.g. WebDAV PROPFIND) classifies
        // as Unknown and intentionally records in Full. An evidence system fails
        // closed (over-record) when it cannot classify a request rather than
        // risking under-recording.
        let class = infer_side_effect_class("PROPFIND", "/");
        assert_eq!(class, SideEffectClass::Unknown);
        let ev = build_evidence(
            "propfind".into(),
            "PROPFIND /".into(),
            &risk(class),
            0,
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
    }

    #[test]
    fn override_header_downgrades_network_path_to_mutate_local() {
        // Review finding #3: high-volume internal traffic on `/network/…` paths
        // would otherwise be captured in full. An operator can set the
        // `x-aep-side-effect-class` override header to pin a cheaper class for
        // that request, avoiding storage exhaustion.
        assert_eq!(
            resolve_side_effect_class(Some("mutate_local"), "POST", "/network/peers"),
            SideEffectClass::MutateLocal,
        );
        // End-to-end: the override yields Delta (not Full) evidence.
        let ev = build_evidence(
            "override".into(),
            "POST /network/peers".into(),
            &risk(SideEffectClass::MutateLocal),
            1,
            None,
        );
        assert_eq!(ev.recording_mode, RecordingMode::Delta);
    }

    #[test]
    fn override_header_accepts_case_and_separator_variants() {
        // The override travels in an HTTP header — accept kebab-case and any casing.
        assert_eq!(
            resolve_side_effect_class(Some("MUTATE-EXTERNAL"), "GET", "/x"),
            SideEffectClass::MutateExternal,
        );
        assert_eq!(
            resolve_side_effect_class(Some("  Network_Egress "), "GET", "/x"),
            SideEffectClass::NetworkEgress,
        );
        assert_eq!(
            resolve_side_effect_class(Some("READ"), "POST", "/users"),
            SideEffectClass::Read,
        );
    }

    #[test]
    fn unrecognized_or_absent_override_falls_back_to_heuristic() {
        // Absent override → heuristic (POST /network/peers → NetworkEgress).
        assert_eq!(
            resolve_side_effect_class(None, "POST", "/network/peers"),
            SideEffectClass::NetworkEgress,
        );
        // Garbage override → heuristic, never breaks the request.
        assert_eq!(
            resolve_side_effect_class(Some("nonsense"), "POST", "/network/peers"),
            SideEffectClass::NetworkEgress,
        );
        // Override is all-or-nothing: a value with trailing junk does not parse.
        assert_eq!(
            resolve_side_effect_class(Some("read please"), "POST", "/users"),
            SideEffectClass::MutateLocal,
        );
    }
}
