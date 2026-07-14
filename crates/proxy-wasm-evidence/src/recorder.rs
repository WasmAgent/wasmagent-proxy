use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
};

// ---------------------------------------------------------------------------
// MCP header sensitive-data leakage detection
// ---------------------------------------------------------------------------

/// Credential / secret prefixes that must never appear in MCP-specific headers.
const CREDENTIAL_PREFIXES: &[&str] = &["ghp_", "ghb_", "sk-", "Bearer ", "token ", "api_"];

/// Minimum character length before entropy analysis triggers.
const HIGH_ENTROPY_MIN_LEN: usize = 32;

/// Shannon entropy threshold (bits per byte) above which a string is flagged.
const HIGH_ENTROPY_THRESHOLD: f64 = 4.0;

/// Risk category detected in MCP-specific HTTP headers.
#[derive(Debug, Clone)]
pub enum McpHeaderRisk {
    /// Header value starts with a known credential prefix (e.g. `ghp_`, `sk-`).
    CredentialPrefix {
        header: &'static str,
        prefix: String,
    },
    /// Header value is a long, high-entropy string suggesting an encoded secret.
    HighEntropy { header: &'static str, entropy: f64 },
    /// MCP-Name header contains an email-like pattern, suggesting PII leakage.
    EmailPattern,
}

impl PartialEq for McpHeaderRisk {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::CredentialPrefix {
                    header: a,
                    prefix: pa,
                },
                Self::CredentialPrefix {
                    header: b,
                    prefix: pb,
                },
            ) => a == b && pa == pb,
            (
                Self::HighEntropy {
                    header: a,
                    entropy: ea,
                },
                Self::HighEntropy {
                    header: b,
                    entropy: eb,
                },
            ) => a == b && (ea - eb).abs() < 1e-10,
            (Self::EmailPattern, Self::EmailPattern) => true,
            _ => false,
        }
    }
}

impl McpHeaderRisk {
    /// Short label for the `x-aep-mcp-header-risk` response header and the
    /// `mcp_header_risk` evidence field.
    pub fn label(&self) -> String {
        match self {
            McpHeaderRisk::CredentialPrefix { prefix, .. } => {
                format!("credential_prefix:{}", prefix.trim_end_matches(' '))
            }
            McpHeaderRisk::HighEntropy { entropy, .. } => format!("high_entropy:{:.2}", entropy),
            McpHeaderRisk::EmailPattern => "email_pattern".to_string(),
        }
    }
}

/// Maximum byte length accepted for MCP header values before rejecting outright.
/// Prevents unbounded heap allocation from maliciously oversized headers.
const MAX_HEADER_VALUE_LEN: usize = 4096;

/// Check a single header value for credential prefixes and high entropy.
fn check_single_header(header_name: &'static str, value: &str) -> Option<McpHeaderRisk> {
    // Reject oversized values early to prevent unbounded allocation.
    if value.len() > MAX_HEADER_VALUE_LEN {
        return None;
    }

    // 1. Credential prefix check (case-insensitive, zero-allocation via
    //    eq_ignore_ascii_case on the truncated slice).
    for prefix in CREDENTIAL_PREFIXES {
        if value.get(..prefix.len()).is_some_and(|v| v.eq_ignore_ascii_case(prefix)) {
            return Some(McpHeaderRisk::CredentialPrefix {
                header: header_name,
                prefix: prefix.to_string(),
            });
        }
    }

    // 2. High-entropy check (only for values long enough to be suspicious)
    if value.len() > HIGH_ENTROPY_MIN_LEN {
        let entropy = shannon_entropy(value);
        if entropy > HIGH_ENTROPY_THRESHOLD {
            return Some(McpHeaderRisk::HighEntropy {
                header: header_name,
                entropy,
            });
        }
    }

    None
}

/// Compute Shannon entropy (bits per byte) of a string.
fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0usize; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Check MCP-Name for email-like patterns (PII leakage).
fn check_email_pattern(name: &str) -> bool {
    // Simple heuristic: look for something@something.something
    let parts: Vec<&str> = name.split('@').collect();
    if parts.len() == 2 {
        let local = parts[0];
        let domain = parts[1];
        // Local part must be non-empty and domain must contain a dot
        !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
    } else {
        false
    }
}

/// Classify MCP-specific HTTP headers for sensitive-data leakage.
///
/// Returns `Some(McpHeaderRisk)` when a value in `mcp_method` or `mcp_name`
/// matches a known risk pattern (credential prefix, high entropy, email in name).
/// Returns `None` when both values are absent or benign.
///
/// Priority: credential prefix > high entropy > email pattern (first match wins).
pub fn classify_mcp_headers(
    mcp_method: Option<&str>,
    mcp_name: Option<&str>,
) -> Option<McpHeaderRisk> {
    // Check MCP-Method first (credential prefix and high entropy)
    if let Some(method) = mcp_method {
        if let Some(risk) = check_single_header("MCP-Method", method) {
            return Some(risk);
        }
    }

    // Check MCP-Name (credential prefix, high entropy, then email pattern)
    if let Some(name) = mcp_name {
        if let Some(risk) = check_single_header("MCP-Name", name) {
            return Some(risk);
        }
        if check_email_pattern(name) {
            return Some(McpHeaderRisk::EmailPattern);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Side-effect classification
// ---------------------------------------------------------------------------

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
            "tools/list"
            | "resources/list"
            | "resources/read"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete" => SideEffectClass::Read,
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

// ---------------------------------------------------------------------------
// Evidence builder
// ---------------------------------------------------------------------------

pub fn build_evidence(
    action_id: String,
    tool_name: String,
    risk_ctx: &RiskContext,
    timestamp_ms: u64,
    precondition_digest: Option<String>,
    mcp_header_risk: Option<String>,
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
        trace_id: None,
        session_id: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // -- side-effect classification tests --

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
    fn classifies_external_mutations() {
        assert_eq!(
            infer_side_effect_class("POST", "/users"),
            SideEffectClass::MutateExternal
        );
        assert_eq!(
            infer_side_effect_class("DELETE", "/users/42"),
            SideEffectClass::MutateExternal
        );
    }

    #[test]
    fn classifies_network_egress_by_path() {
        assert_eq!(
            infer_side_effect_class("POST", "/network/peers"),
            SideEffectClass::NetworkEgress
        );
        assert_eq!(
            infer_side_effect_class("PUT", "/v1/webhook/xyz"),
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

    // -- MCP-method-aware side-effect classification tests --

    #[test]
    fn mcp_method_tools_call_is_mutate_external() {
        assert_eq!(
            infer_side_effect_class_with_mcp("POST", "/mcp", Some("tools/call")),
            SideEffectClass::MutateExternal
        );
    }

    #[test]
    fn mcp_method_tools_list_is_read() {
        for op in [
            "tools/list",
            "resources/list",
            "resources/read",
            "prompts/get",
        ] {
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

    // -- classify_mcp_headers tests --

    #[test]
    fn no_risk_when_headers_absent() {
        assert_eq!(classify_mcp_headers(None, None), None);
    }

    #[test]
    fn no_risk_when_headers_benign() {
        assert_eq!(
            classify_mcp_headers(Some("tools/list"), Some("my-tool")),
            None
        );
    }

    #[test]
    fn classify_mcp_headers_clean_values_return_none() {
        assert_eq!(
            classify_mcp_headers(Some("tools/call"), Some("my_tool")),
            None
        );
        assert_eq!(classify_mcp_headers(None, None), None);
        assert_eq!(classify_mcp_headers(Some("tools/list"), None), None);
    }

    #[test]
    fn detects_ghp_credential_prefix() {
        let risk = classify_mcp_headers(Some("ghp_xxxxDeadBeef"), None);
        let found = risk.and_then(|r| match r {
            McpHeaderRisk::CredentialPrefix { prefix, .. } => Some(prefix),
            _ => None,
        });
        assert_eq!(found, Some("ghp_".to_string()));
    }

    #[test]
    fn detects_sk_credential_prefix() {
        let risk = classify_mcp_headers(None, Some("sk-proj-abc123"));
        let found = risk.and_then(|r| match r {
            McpHeaderRisk::CredentialPrefix { prefix, .. } => Some(prefix),
            _ => None,
        });
        assert_eq!(found, Some("sk-".to_string()));
    }

    #[test]
    fn detects_bearer_credential_prefix() {
        let risk = classify_mcp_headers(Some("Bearer eyJhbGciOiJIUzI1NiJ9"), None);
        let found = risk.and_then(|r| match r {
            McpHeaderRisk::CredentialPrefix { prefix, .. } => Some(prefix),
            _ => None,
        });
        assert_eq!(found, Some("Bearer ".to_string()));
    }

    #[test]
    fn classify_mcp_headers_detects_credential_prefix() {
        assert_eq!(
            classify_mcp_headers(Some("ghp_abc123"), None),
            Some(McpHeaderRisk::CredentialPrefix {
                header: "MCP-Method",
                prefix: "ghp_".to_string()
            })
        );
        assert_eq!(
            classify_mcp_headers(Some("sk-abcdefghij"), None),
            Some(McpHeaderRisk::CredentialPrefix {
                header: "MCP-Method",
                prefix: "sk-".to_string()
            })
        );
        assert_eq!(
            classify_mcp_headers(Some("Bearer token_here"), None),
            Some(McpHeaderRisk::CredentialPrefix {
                header: "MCP-Method",
                prefix: "Bearer ".to_string()
            })
        );
    }

    #[test]
    fn detects_high_entropy_in_mcp_method() {
        // 40-char base64-like string with high Shannon entropy
        let high_entropy_val = "aB3dE7fG9hJ1kL5mN8pQ2rS4tU6vW0xY9zA1bC3";
        let risk = classify_mcp_headers(Some(high_entropy_val), None);
        assert!(matches!(risk, Some(McpHeaderRisk::HighEntropy { .. })));
    }

    #[test]
    fn detects_high_entropy_in_mcp_name() {
        let high_entropy_val = "Zk9mL2hC4nN6pR8sT0uV2wX4yZ6aB8cD0eF2gH4iJ6kL8mN0";
        let risk = classify_mcp_headers(None, Some(high_entropy_val));
        assert!(matches!(risk, Some(McpHeaderRisk::HighEntropy { .. })));
    }

    #[test]
    fn classify_mcp_headers_detects_high_entropy() {
        // High-entropy string (not just long repetitive chars)
        let high_entropy_val = "aB3dE7fG9hJ1kL5mN8pQ2rS4tU6vW0xY9zA1bC3";
        let risk = classify_mcp_headers(None, Some(high_entropy_val));
        assert!(matches!(risk, Some(McpHeaderRisk::HighEntropy { .. })));
    }

    #[test]
    fn low_entropy_string_not_flagged() {
        // Long but repetitive — entropy will be low
        let low_entropy_val = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(classify_mcp_headers(Some(low_entropy_val), None), None);
    }

    #[test]
    fn short_string_not_flagged_for_entropy() {
        // Too short for entropy check even if random-looking
        let short = "abc123xyz";
        assert_eq!(classify_mcp_headers(Some(short), None), None);
    }

    #[test]
    fn detects_email_pattern_in_mcp_name() {
        let risk = classify_mcp_headers(None, Some("alice@example.com"));
        assert_eq!(risk, Some(McpHeaderRisk::EmailPattern));
    }

    #[test]
    fn detects_email_with_subdomain() {
        let risk = classify_mcp_headers(None, Some("bob@mail.corp.org"));
        assert_eq!(risk, Some(McpHeaderRisk::EmailPattern));
    }

    #[test]
    fn classify_mcp_headers_detects_pii_in_name() {
        assert_eq!(
            classify_mcp_headers(None, Some("user@example.com")),
            Some(McpHeaderRisk::EmailPattern)
        );
    }

    #[test]
    fn no_email_pattern_from_at_sign_only() {
        // Must have local part, @, and domain with a dot
        assert_eq!(classify_mcp_headers(None, Some("@example.com")), None);
        assert_eq!(classify_mcp_headers(None, Some("user@")), None);
        assert_eq!(classify_mcp_headers(None, Some("user@domain")), None);
        assert_eq!(classify_mcp_headers(None, Some("@")), None);
    }

    #[test]
    fn credential_prefix_takes_priority_over_entropy() {
        // A Bearer token that is also long enough for entropy check
        let bearer = "Bearer aB3dE7fG9hJ1kL5mN8pQ2rS4tU6vW0xY9zA1bC3";
        let risk = classify_mcp_headers(Some(bearer), None);
        assert!(matches!(risk, Some(McpHeaderRisk::CredentialPrefix { .. })));
    }

    #[test]
    fn credential_prefix_takes_priority_over_email() {
        let risk = classify_mcp_headers(None, Some("sk-alice@example.com"));
        assert!(matches!(risk, Some(McpHeaderRisk::CredentialPrefix { .. })));
    }

    #[test]
    fn mcp_header_risk_label_format() {
        assert_eq!(
            classify_mcp_headers(Some("ghp_abc"), None).unwrap().label(),
            "credential_prefix:ghp_"
        );
        assert_eq!(
            classify_mcp_headers(None, Some("user@host.io"))
                .unwrap()
                .label(),
            "email_pattern"
        );
        let risk =
            classify_mcp_headers(Some("aB3dE7fG9hJ1kL5mN8pQ2rS4tU6vW0xY9zA1bC3"), None).unwrap();
        let label = risk.label();
        assert!(label.starts_with("high_entropy:"));
    }

    #[test]
    fn shannon_entropy_of_uniform_distribution() {
        // A string with all 26 lowercase letters repeated 4 times = 104 chars
        // Each letter has probability 4/104 = 1/26, so entropy ≈ log2(26) ≈ 4.7
        let s: String = "abcdefghijklmnopqrstuvwxyz".repeat(4);
        let e = shannon_entropy(&s);
        assert!(e > 4.5, "expected entropy near log2(26), got {}", e);
    }

    #[test]
    fn shannon_entropy_of_constant_string() {
        let s = "a".repeat(100);
        let e = shannon_entropy(&s);
        assert!(e.abs() < 0.01, "expected zero entropy, got {}", e);
    }

    // -- build_evidence tests --

    #[test]
    fn build_evidence_marks_reads_as_non_state_changing() {
        let ev = build_evidence(
            "ctx-1".into(),
            "GET /x".into(),
            &risk(SideEffectClass::Read),
            1_700_000_000_000,
            None,
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
        assert!(ev.mcp_header_risk.is_none());
        assert!(ev.trace_id.is_none());
        assert!(ev.session_id.is_none());
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
            None,
        );
        assert!(ev.state_changing);
        assert_eq!(ev.recording_mode, RecordingMode::Full);
        assert_eq!(ev.precondition_digest.as_deref(), Some(digest.as_str()));
        assert!(ev.trace_id.is_none());
        assert!(ev.session_id.is_none());
    }
}
