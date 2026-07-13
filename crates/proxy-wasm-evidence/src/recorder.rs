use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

/// Risk level detected in MCP-specific headers (MCP 2026-07-28+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpHeaderRisk {
    /// Credential-like pattern detected (e.g. ghp_, sk-, Bearer prefix).
    CredentialLeak,
    /// High-entropy string > 32 chars detected (potential API key).
    HighEntropyValue,
    /// Email-like pattern detected in MCP-Name header.
    PiiLeak,
}

/// Check MCP-Method and MCP-Name header values for sensitive-data leakage patterns.
///
/// Returns the highest-severity risk detected, or None if no risk is found.
/// Called from the gateway filter before recording; a Some result causes the
/// evidence record to be annotated with x-aep-mcp-header-risk.
pub fn classify_mcp_headers(
    mcp_method: Option<&str>,
    mcp_name: Option<&str>,
) -> Option<McpHeaderRisk> {
    const CREDENTIAL_PREFIXES: &[&str] = &["ghp_", "ghb_", "sk-", "Bearer ", "token ", "api_"];
    const MIN_HIGH_ENTROPY_LEN: usize = 32;

    for val in [mcp_method, mcp_name].into_iter().flatten() {
        // Credential prefix detection (case-insensitive)
        let lower = val.to_lowercase();
        for prefix in CREDENTIAL_PREFIXES {
            if lower.starts_with(&prefix.to_lowercase() as &str) {
                return Some(McpHeaderRisk::CredentialLeak);
            }
        }
        // High-entropy detection: long alphanumeric strings
        let alnum_run: usize = val
            .split(|c: char| !c.is_alphanumeric())
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        if alnum_run >= MIN_HIGH_ENTROPY_LEN {
            return Some(McpHeaderRisk::HighEntropyValue);
        }
    }

    // PII: email pattern in MCP-Name
    if let Some(name) = mcp_name {
        if name.contains('@') && name.contains('.') {
            return Some(McpHeaderRisk::PiiLeak);
        }
    }

    None
}

/// Infer SideEffectClass from HTTP method + path heuristics, with optional
/// MCP-Method header input (MCP 2026-07-28+ protocol).
///
/// When mcp_method is provided it takes precedence over the HTTP method
/// heuristic for MCP tool-call semantics:
/// - "tools/call" → MutateExternal (tool invocations can have external effects)
/// - "tools/list", "resources/list", "resources/read" → Read
/// - "prompts/list", "prompts/get" → Read
///
/// In a real deployment, callers can also set x-aep-side-effect-class header to override.
pub fn infer_side_effect_class(method: &str, path: &str) -> SideEffectClass {
    infer_side_effect_class_with_mcp(method, path, None)
}

/// Full variant: accepts optional MCP-Method header for MCP 2026-07-28+ semantics.
pub fn infer_side_effect_class_with_mcp(
    method: &str,
    path: &str,
    mcp_method: Option<&str>,
) -> SideEffectClass {
    // MCP-Method header overrides HTTP method heuristic for known MCP operations.
    if let Some(mcp_op) = mcp_method {
        return match mcp_op {
            "tools/call" => SideEffectClass::MutateExternal,
            "tools/list" | "resources/list" | "resources/read"
            | "prompts/list" | "prompts/get" | "completion/complete" => SideEffectClass::Read,
            _ => SideEffectClass::Unknown,
        };
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
            assert_eq!(infer_side_effect_class(method, "/anything"), SideEffectClass::Read);
        }
    }

    #[test]
    fn classifies_external_mutations() {
        assert_eq!(infer_side_effect_class("POST", "/users"), SideEffectClass::MutateExternal);
        assert_eq!(infer_side_effect_class("DELETE", "/users/42"), SideEffectClass::MutateExternal);
    }

    #[test]
    fn classifies_network_egress_by_path() {
        assert_eq!(infer_side_effect_class("POST", "/network/peers"), SideEffectClass::NetworkEgress);
        assert_eq!(infer_side_effect_class("PUT", "/v1/webhook/xyz"), SideEffectClass::NetworkEgress);
    }

    #[test]
    fn classifies_unknown_methods() {
        assert_eq!(infer_side_effect_class("PROPFIND", "/"), SideEffectClass::Unknown);
        assert_eq!(infer_side_effect_class("", ""), SideEffectClass::Unknown);
    }

    #[test]
    fn mcp_method_tools_call_is_mutate_external() {
        assert_eq!(
            infer_side_effect_class_with_mcp("POST", "/mcp", Some("tools/call")),
            SideEffectClass::MutateExternal
        );
    }

    #[test]
    fn mcp_method_tools_list_is_read() {
        for op in ["tools/list", "resources/list", "resources/read", "prompts/get"] {
            assert_eq!(
                infer_side_effect_class_with_mcp("POST", "/mcp", Some(op)),
                SideEffectClass::Read,
                "expected Read for MCP op: {}",
                op
            );
        }
    }

    #[test]
    fn mcp_method_unknown_op_is_unknown() {
        assert_eq!(
            infer_side_effect_class_with_mcp("POST", "/mcp", Some("custom/operation")),
            SideEffectClass::Unknown
        );
    }

    #[test]
    fn classify_mcp_headers_detects_credential_prefix() {
        assert_eq!(
            classify_mcp_headers(Some("ghp_abc123"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
        assert_eq!(
            classify_mcp_headers(Some("sk-abcdefghij"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
        assert_eq!(
            classify_mcp_headers(Some("Bearer token_here"), None),
            Some(McpHeaderRisk::CredentialLeak)
        );
    }

    #[test]
    fn classify_mcp_headers_detects_high_entropy() {
        // 40-char alphanumeric string in MCP-Name
        let long_val = "a".repeat(40);
        assert_eq!(
            classify_mcp_headers(None, Some(&long_val)),
            Some(McpHeaderRisk::HighEntropyValue)
        );
    }

    #[test]
    fn classify_mcp_headers_detects_pii_in_name() {
        assert_eq!(
            classify_mcp_headers(None, Some("user@example.com")),
            Some(McpHeaderRisk::PiiLeak)
        );
    }

    #[test]
    fn classify_mcp_headers_clean_values_return_none() {
        assert_eq!(classify_mcp_headers(Some("tools/call"), Some("my_tool")), None);
        assert_eq!(classify_mcp_headers(None, None), None);
        assert_eq!(classify_mcp_headers(Some("tools/list"), None), None);
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
