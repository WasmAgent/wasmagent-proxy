use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use aep_core::{
    evidence::ActionEvidence,
    recording::{compile_recording_policy, RecordingMode, RiskContext, SideEffectClass},
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
    /// Entries displaced by capacity pressure — the "capture completeness"
    /// signal: dropped evidence must be observable, never silent.
    dropped_total: u64,
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
            dropped_total: 0,
        }
    }

    /// Entries evicted by capacity pressure since creation — surfaced as the
    /// `aep.evidence.dropped_total` completeness signal.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
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
        let evicted = if self.entries.len() >= self.capacity {
            self.entries.pop_front()
        } else {
            None
        };
        if evicted.is_some() {
            self.dropped_total += 1;
        }
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

impl Default for EvidenceBuffer {
    fn default() -> Self {
        Self::with_defaults()
    }
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
///
/// FAIL-CLOSED rule: the MCP-Method header is client-controlled untrusted
/// metadata. It may RAISE the inferred risk but must never LOWER it — the
/// verdict is the more severe of the HTTP heuristic and the MCP semantics.
/// `POST /x + MCP-Method: tools/list` therefore stays MutateExternal.
pub fn infer_side_effect_class_with_mcp(
    method: &str,
    path: &str,
    mcp_method: Option<&str>,
) -> SideEffectClass {
    // Layer 1 — HTTP heuristic (independent of any client header).
    let http = match method.to_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => SideEffectClass::Read,
        "POST" | "PUT" | "PATCH" | "DELETE" => {
            if path.contains("/network/") || path.contains("/webhook") {
                SideEffectClass::NetworkEgress
            } else {
                SideEffectClass::MutateExternal
            }
        }
        _ => SideEffectClass::Unknown,
    };

    // Layer 2 — untrusted MCP metadata may RAISE the verdict, never lower it.
    let Some(mcp_op) = mcp_method else {
        return http;
    };
    let mcp = match mcp_op {
        "tools/call" => SideEffectClass::MutateExternal,
        "tools/list"
        | "resources/list"
        | "resources/read"
        | "prompts/list"
        | "prompts/get"
        | "completion/complete" => SideEffectClass::Read,
        _ => SideEffectClass::Unknown,
    };
    max_severity(http, mcp)
}

/// Safety ordering for severity folding: unknown could be mutating, so it
/// outranks read; the attacker-controlled header can never drag a verdict
/// below what the HTTP layer already established.
fn severity_rank(class: &SideEffectClass) -> u8 {
    match class {
        SideEffectClass::Read => 0,
        SideEffectClass::Unknown => 1,
        SideEffectClass::MutateLocal => 2,
        SideEffectClass::MutateExternal => 3,
        SideEffectClass::NetworkEgress => 4,
    }
}

fn max_severity(a: SideEffectClass, b: SideEffectClass) -> SideEffectClass {
    if severity_rank(&b) > severity_rank(&a) {
        b
    } else {
        a
    }
}

/// Convert a wall-clock time to Unix milliseconds. Times before the epoch map
/// to `None` — callers must surface a clock-failure signal rather than
/// silently stamping evidence with 1970-01-01.
pub fn unix_millis_checked(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Legacy convenience: epoch-0 fallback. Prefer [`unix_millis_checked`] so a
/// failed host clock is visible to the caller.
pub fn unix_millis(time: SystemTime) -> u64 {
    unix_millis_checked(time).unwrap_or(0)
}

/// Recording-mode assurance ordering: Validation < Delta < Full.
///
/// The operator's configured `default_mode` is the MINIMUM baseline for
/// captured evidence — the compile_recording_policy verdict may only raise
/// it, never lower it (audit P0: `default_mode=full + GET` must stay Full).
pub fn max_recording_mode(a: RecordingMode, b: RecordingMode) -> RecordingMode {
    let rank = |m: &RecordingMode| match m {
        RecordingMode::Validation => 0u8,
        RecordingMode::Delta => 1,
        RecordingMode::Full => 2,
    };
    if rank(&b) > rank(&a) {
        b
    } else {
        a
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
        mcp_header_risk: mcp_header_risk.map(|r| r.as_str().to_string()),
        side_effect_class: Some(risk_ctx.side_effect_class.canonical_str().to_string()),
        extra: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aep_core::recording::RecordingMode;
    use std::time::Duration;

    #[test]
    fn unix_millis_converts_epoch_plus_duration() {
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        assert_eq!(unix_millis(t), 1_700_000_000_123);
    }

    #[test]
    fn unix_millis_maps_pre_epoch_to_zero() {
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert_eq!(unix_millis(UNIX_EPOCH), 0);
    }

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
    fn mcp_header_cannot_downgrade_http_risk() {
        // FAIL-CLOSED: untrusted client metadata may raise risk, never lower
        // it. POST implies mutation regardless of any MCP-Method header.
        for op in ["tools/list", "resources/read", "prompts/get"] {
            assert!(
                matches!(
                    infer_side_effect_class_with_mcp("POST", "/dangerous", Some(op)),
                    SideEffectClass::MutateExternal | SideEffectClass::NetworkEgress
                ),
                "POST must not be downgraded by MCP-Method: {op}"
            );
        }
        assert!(matches!(
            infer_side_effect_class_with_mcp("DELETE", "/items/1", Some("resources/read")),
            SideEffectClass::MutateExternal
        ));
        // Escalation is allowed: GET + tools/call is mutating.
        assert!(matches!(
            infer_side_effect_class_with_mcp("GET", "/safe", Some("tools/call")),
            SideEffectClass::MutateExternal
        ));
        // Network-egress heuristic cannot be downgraded either.
        assert!(matches!(
            infer_side_effect_class_with_mcp("POST", "/network/export", Some("tools/list")),
            SideEffectClass::NetworkEgress
        ));
    }

    #[test]
    fn mcp_method_tools_list_is_read_on_safe_http() {
        // Read semantics only apply where the HTTP layer is already safe.
        assert_eq!(
            infer_side_effect_class_with_mcp("GET", "/mcp", Some("tools/list")),
            SideEffectClass::Read
        );
    }

    #[test]
    fn mcp_method_unknown_op_cannot_lower_http_verdict() {
        // POST + unknown MCP op: HTTP mutation stands (Unknown never lowers).
        assert_eq!(
            infer_side_effect_class_with_mcp("POST", "/mcp", Some("custom/operation")),
            SideEffectClass::MutateExternal
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
        assert_eq!(ev.mcp_header_risk.as_deref(), Some("credential_leak"));

        let ev2 = build_evidence(
            "ctx-4".into(),
            "GET /safe".into(),
            &risk(SideEffectClass::Read),
            200,
            None,
            Some(McpHeaderRisk::PiiLeak),
        );
        assert_eq!(ev2.mcp_header_risk.as_deref(), Some("pii_leak"));
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
            side_effect_class: None,
            extra: Default::default(),
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
        assert_eq!(buf.capacity(), DEFAULT_EVIDENCE_BUFFER_CAPACITY);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn evidence_buffer_default_has_capacity_1024() {
        let buf = EvidenceBuffer::default();
        assert_eq!(buf.capacity(), DEFAULT_EVIDENCE_BUFFER_CAPACITY);
        assert!(buf.is_empty());
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
