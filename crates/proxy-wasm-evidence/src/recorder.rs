use std::collections::VecDeque;

use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RiskContext, SideEffectClass},
    McpHeaderRisk,
};

/// Default maximum number of in-flight evidence entries retained by
/// [`EvidenceBuffer`].
pub const DEFAULT_EVIDENCE_BUFFER_CAPACITY: usize = 1024;

/// Bounded ring-buffer for in-flight evidence entries.
///
/// Holds at most `capacity` [`ActionEvidence`] records. When the buffer is full
/// and a new entry is pushed, the oldest entry is evicted (FIFO). This avoids
/// unbounded heap allocation in long-lived gateway instances.
pub struct EvidenceBuffer {
    entries: VecDeque<ActionEvidence>,
    capacity: usize,
}

impl EvidenceBuffer {
    /// Create a new buffer with the given maximum capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "EvidenceBuffer capacity must be > 0");
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Create a new buffer with the default capacity of 1024 entries.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_EVIDENCE_BUFFER_CAPACITY)
    }

    /// Push an entry into the buffer. If the buffer is full, the oldest entry
    /// is evicted and returned.
    ///
    /// Returns `Some(evicted)` when an entry was displaced, `None` otherwise.
    pub fn push(&mut self, evidence: ActionEvidence) -> Option<ActionEvidence> {
        let evicted = if self.entries.len() == self.capacity {
            self.entries.pop_front()
        } else {
            None
        };
        self.entries.push_back(evidence);
        evicted
    }

    /// Number of entries currently in the buffer.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maximum capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drain all entries from the buffer, returning them as a `Vec`.
    pub fn drain(&mut self) -> Vec<ActionEvidence> {
        self.entries.drain(..).collect()
    }
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
        mcp_header_risk: mcp_header_risk.map(|risk| risk.as_str().to_string()),
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
        assert_eq!(
            classify_mcp_headers(Some("tools/call"), Some("my_tool")),
            None
        );
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
        assert!(ev.mcp_header_risk.is_none());
    }

    #[test]
    fn build_evidence_assigns_mcp_header_risk() {
        let ev = build_evidence(
            "ctx-3".into(),
            "POST /mcp".into(),
            &risk(SideEffectClass::MutateExternal),
            100,
            None,
            Some(McpHeaderRisk::CredentialLeak),
        );
        assert_eq!(ev.mcp_header_risk.as_deref(), Some("CredentialLeak"));

        let ev2 = build_evidence(
            "ctx-4".into(),
            "GET /safe".into(),
            &risk(SideEffectClass::Read),
            200,
            None,
            Some(McpHeaderRisk::PiiLeak),
        );
        assert_eq!(ev2.mcp_header_risk.as_deref(), Some("PiiLeak"));
    }

    // --- EvidenceBuffer tests ---

    fn make_evidence(id: &str) -> ActionEvidence {
        ActionEvidence {
            action_id: id.into(),
            tool_name: format!("tool-{}", id),
            state_changing: false,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Validation,
            capability_decision: None,
            mcp_header_risk: None,
        }
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn evidence_buffer_panics_on_zero_capacity() {
        EvidenceBuffer::new(0);
    }

    #[test]
    fn evidence_buffer_with_defaults_has_capacity_1024() {
        let buf = EvidenceBuffer::with_defaults();
        assert_eq!(buf.capacity(), 1024);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn evidence_buffer_push_without_overflow() {
        let mut buf = EvidenceBuffer::new(4);
        assert!(buf.push(make_evidence("a")).is_none());
        assert_eq!(buf.len(), 1);
        assert!(buf.push(make_evidence("b")).is_none());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn evidence_buffer_evicts_oldest_on_overflow() {
        let mut buf = EvidenceBuffer::new(2);

        assert!(buf.push(make_evidence("a")).is_none());
        assert!(buf.push(make_evidence("b")).is_none());

        // Third push evicts "a"
        let evicted = buf.push(make_evidence("c")).unwrap();
        assert_eq!(evicted.action_id, "a");
        assert_eq!(buf.len(), 2);

        // Fourth push evicts "b"
        let evicted = buf.push(make_evidence("d")).unwrap();
        assert_eq!(evicted.action_id, "b");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn evidence_buffer_drain_returns_all_entries() {
        let mut buf = EvidenceBuffer::new(4);
        buf.push(make_evidence("a"));
        buf.push(make_evidence("b"));
        buf.push(make_evidence("c"));

        let drained = buf.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].action_id, "a");
        assert_eq!(drained[2].action_id, "c");
        assert!(buf.is_empty());
    }

    #[test]
    fn evidence_buffer_drain_after_overflow() {
        let mut buf = EvidenceBuffer::new(2);
        buf.push(make_evidence("a"));
        buf.push(make_evidence("b"));
        buf.push(make_evidence("c")); // evicts "a"

        let drained = buf.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].action_id, "b");
        assert_eq!(drained[1].action_id, "c");
    }
}
