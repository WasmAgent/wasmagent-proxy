use aep_core::{
    evidence::{ActionEvidence, McpHeaderRisk},
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

/// Check whether `value` has an email-like structure (`local@domain.tld`).
///
/// Returns `true` if the value contains a single `@` with at least one
/// character before it and a `.` after it in the domain portion. This avoids
/// the false positives that a naive `.contains('@')` + `.contains('.')` would
/// produce (e.g. `@example` or `user@`).
fn looks_like_email(value: &str) -> bool {
    if let Some(at_pos) = value.rfind('@') {
        // At least one char before '@'
        if at_pos == 0 {
            return false;
        }
        // At least one char after '@'
        let after_at = &value[at_pos + 1..];
        if after_at.is_empty() {
            return false;
        }
        // The domain part must contain at least one '.'
        if after_at.contains('.') {
            return true;
        }
    }
    false
}

/// Check whether `value` starts with a known credential/token prefix.
fn has_credential_prefix(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    lower.starts_with("ghp_")
        || lower.starts_with("sk-")
        || lower.starts_with("bearer ")
}

/// Classify an MCP header value for sensitive-data leakage risk.
///
/// Examines the value against three heuristics:
/// - **Credential prefixes**: `ghp_`, `sk-`, `Bearer `
/// - **High-entropy**: length > 32 characters (proxy for tokens, JWTs)
/// - **Email-like**: structured `local@domain.tld` pattern
///
/// Returns `Some(McpHeaderRisk)` if at least one heuristic fires, `None`
/// if the value appears benign.
fn classify_single_mcp_value(source_header: &str, value: &str) -> Option<McpHeaderRisk> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let has_credential_prefix = has_credential_prefix(trimmed);
    let is_high_entropy = trimmed.len() > 32;
    let is_email_like = looks_like_email(trimmed);

    if has_credential_prefix || is_high_entropy || is_email_like {
        let snippet = if trimmed.len() > 40 {
            format!("{}...", &trimmed[..40])
        } else {
            trimmed.to_string()
        };
        Some(McpHeaderRisk {
            has_credential_prefix,
            is_high_entropy,
            is_email_like,
            source_header: source_header.to_string(),
            value_snippet: snippet,
        })
    } else {
        None
    }
}

/// Classify `MCP-Method` and `MCP-Name` header values for sensitive-data
/// leakage risk.
///
/// Returns the first detected risk (MCP-Method checked first, then MCP-Name),
/// or `None` if neither header carries a risky value.
pub fn classify_mcp_headers(
    mcp_method: Option<&str>,
    mcp_name: Option<&str>,
) -> Option<McpHeaderRisk> {
    if let Some(val) = mcp_method {
        if !val.trim().is_empty() {
            if let Some(risk) = classify_single_mcp_value("MCP-Method", val) {
                return Some(risk);
            }
        }
    }
    if let Some(val) = mcp_name {
        if !val.trim().is_empty() {
            if let Some(risk) = classify_single_mcp_value("MCP-Name", val) {
                return Some(risk);
            }
        }
    }
    None
}

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
///
/// `mcp_header_risk` carries sensitive-data leakage signals detected in the
/// MCP-Method and MCP-Name request headers (see [`classify_mcp_headers`]).
pub fn build_evidence(
    action_id: String,
    tool_name: String,
    risk_ctx: &RiskContext,
    timestamp_ms: u64,
    precondition_digest: Option<String>,
    mcp_header_risk: Option<McpHeaderRisk>,
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
        mcp_header_risk,
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

    // ── classify_mcp_headers tests ──────────────────────────────────────

    #[test]
    fn mcp_method_contains_github_token() {
        let risk = classify_mcp_headers(Some("ghp_abc123def456"), None);
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.has_credential_prefix);
        assert_eq!(r.source_header, "MCP-Method");
    }

    #[test]
    fn mcp_name_contains_sk_prefix() {
        let risk = classify_mcp_headers(None, Some("sk-proj-xxxxxxxxxxxx"));
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.has_credential_prefix);
        assert_eq!(r.source_header, "MCP-Name");
    }

    #[test]
    fn mcp_method_contains_bearer_token() {
        let risk = classify_mcp_headers(Some("Bearer eyJhbGciOiJIUzI1NiJ9"), None);
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.has_credential_prefix);
    }

    #[test]
    fn mcp_name_contains_email() {
        let risk = classify_mcp_headers(None, Some("user@example.com"));
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.is_email_like);
        assert!(!r.has_credential_prefix);
        assert_eq!(r.source_header, "MCP-Name");
    }

    #[test]
    fn mcp_method_long_string_is_high_entropy() {
        let long = "a".repeat(40);
        let risk = classify_mcp_headers(Some(&long), None);
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.is_high_entropy);
    }

    #[test]
    fn mcp_method_short_string_no_risk() {
        let risk = classify_mcp_headers(Some("tools/call"), None);
        assert!(risk.is_none());
    }

    #[test]
    fn mcp_name_short_string_no_risk() {
        let risk = classify_mcp_headers(None, Some("list-files"));
        assert!(risk.is_none());
    }

    #[test]
    fn both_headers_absent_no_risk() {
        let risk = classify_mcp_headers(None, None);
        assert!(risk.is_none());
    }

    #[test]
    fn empty_values_no_risk() {
        let risk = classify_mcp_headers(Some(""), Some(""));
        assert!(risk.is_none());
    }

    #[test]
    fn whitespace_only_values_no_risk() {
        let risk = classify_mcp_headers(Some("   "), Some(" \t "));
        assert!(risk.is_none());
    }

    #[test]
    fn mcp_method_risky_takes_precedence_over_mcp_name() {
        // When both headers are present and both are risky, MCP-Method wins
        // because it is checked first.
        let risk = classify_mcp_headers(Some("ghp_xxx"), Some("user@example.com"));
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.has_credential_prefix);
        assert_eq!(r.source_header, "MCP-Method");
    }

    #[test]
    fn mcp_name_risky_when_method_absent() {
        let risk = classify_mcp_headers(None, Some("ghp_xxx"));
        assert!(risk.is_some());
        let r = risk.unwrap();
        assert!(r.has_credential_prefix);
        assert_eq!(r.source_header, "MCP-Name");
    }

    #[test]
    fn email_detection_rejects_no_local_part() {
        assert!(!looks_like_email("@example.com"));
    }

    #[test]
    fn email_detection_rejects_no_domain_dot() {
        assert!(!looks_like_email("user@example"));
    }

    #[test]
    fn email_detection_rejects_no_at() {
        assert!(!looks_like_email("userexample.com"));
    }

    #[test]
    fn email_detection_accepts_valid() {
        assert!(looks_like_email("user@example.com"));
        assert!(looks_like_email("first.last@sub.example.co.uk"));
    }

    #[test]
    fn value_snippet_truncates_long_values() {
        let long = "a".repeat(100);
        let risk = classify_mcp_headers(Some(&long), None).unwrap();
        assert_eq!(risk.value_snippet.len(), 43); // 40 chars + "..."
        assert!(risk.value_snippet.ends_with("..."));
    }

    #[test]
    fn value_snippet_short_values_no_ellipsis() {
        let risk = classify_mcp_headers(Some("ghp_abcdef"), None).unwrap();
        assert_eq!(risk.value_snippet, "ghp_abcdef");
    }

    // ── Existing side-effect classification tests ──────────────────────

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
            None, // no MCP risk
        );
        assert!(!ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Validation);
        assert_eq!(ev.action_id, "ctx-1");
        assert_eq!(ev.tool_name, "GET /x");
        assert_eq!(ev.timestamp_ms, 1_700_000_000_000);
        assert!(ev.precondition_digest.is_none());
        assert!(ev.result_digest.is_none());
        assert!(ev.capability_decision.is_none());
        assert!(ev.mcp_header_risk.is_none());
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
            None,
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

        let ev = build_evidence(
            "ctx-4".into(),
            "GET /items".into(),
            &risk(class),
            200,
            None,
            None,
        );
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
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
    }

    #[test]
    fn state_changing_flag_distinguishes_read_from_mutate() {
        let get_ev = build_evidence(
            "get".into(),
            "GET /items".into(),
            &risk(SideEffectClass::Read),
            0,
            None,
            None,
        );
        let post_ev = build_evidence(
            "post".into(),
            "POST /items".into(),
            &risk(SideEffectClass::MutateLocal),
            0,
            None,
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
        let class = infer_side_effect_class("PROPFIND", "/");
        assert_eq!(class, SideEffectClass::Unknown);
        let ev = build_evidence(
            "propfind".into(),
            "PROPFIND /".into(),
            &risk(class),
            0,
            None,
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
    }

    #[test]
    fn override_header_downgrades_network_path_to_mutate_local() {
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
            None,
        );
        assert_eq!(ev.recording_mode, RecordingMode::Delta);
    }

    #[test]
    fn override_header_accepts_case_and_separator_variants() {
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
        assert_eq!(
            resolve_side_effect_class(None, "POST", "/network/peers"),
            SideEffectClass::NetworkEgress,
        );
        assert_eq!(
            resolve_side_effect_class(Some("nonsense"), "POST", "/network/peers"),
            SideEffectClass::NetworkEgress,
        );
        assert_eq!(
            resolve_side_effect_class(Some("read please"), "POST", "/users"),
            SideEffectClass::MutateLocal,
        );
    }

    #[test]
    fn build_evidence_includes_mcp_header_risk() {
        let mcp_risk = McpHeaderRisk {
            has_credential_prefix: true,
            is_high_entropy: false,
            is_email_like: false,
            source_header: "MCP-Method".into(),
            value_snippet: "ghp_xxx".into(),
        };
        let ev = build_evidence(
            "ctx-risk".into(),
            "GET /x".into(),
            &risk(SideEffectClass::Read),
            0,
            None,
            Some(mcp_risk.clone()),
        );
        assert_eq!(ev.mcp_header_risk, Some(mcp_risk));
    }

    #[test]
    fn classify_mcp_headers_detects_sk_prefix_case_insensitive() {
        // sk- prefix check should be case-insensitive
        let risk = classify_mcp_headers(Some("SK-XXXXXXXX"), None);
        assert!(risk.is_some());
        assert!(risk.unwrap().has_credential_prefix);
    }

    #[test]
    fn classify_mcp_headers_credential_prefix_leading_whitespace() {
        // Leading whitespace before credential prefix should still be detected
        let risk = classify_mcp_headers(Some("  ghp_xxx"), None);
        assert!(risk.is_some());
        assert!(risk.unwrap().has_credential_prefix);
    }
}
