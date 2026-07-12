// Proxy-Wasm-specific imports are only available when targeting wasm32.
// On native (including `cargo test`) the struct and its constructor are still
// compiled so unit tests can verify construction and field-mutation logic.
#[cfg(target_arch = "wasm32")]
use proxy_wasm::traits::*;
#[cfg(target_arch = "wasm32")]
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, infer_side_effect_class};
use aep_core::recording::RiskContext;

pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    trace_id: Option<String>,
    agent_id: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            agent_id: None,
        }
    }
}

/// Pure, host-call-free computation of the value the filter would emit for the
/// `x-aep-recording-mode` response header for a given request.
///
/// Extracted from `on_http_response_headers` so the classify → recording-policy
/// → header-value pipeline is unit-testable on the native target, which cannot
/// link the proxy-wasm host imports that the `HttpContext` trait methods rely
/// on. The Wasm path delegates here so the two cannot drift.
pub fn recording_mode_for_request(method: &str, path: &str, context_id: u32) -> String {
    let side_effect_class = infer_side_effect_class(method, path);
    let risk_ctx = RiskContext {
        was_vetted: false,
        has_consent_anomaly: false,
        taint_chain_length: 0,
        side_effect_class,
    };
    let action_id = format!("ctx-{}", context_id);
    let tool_name = format!("{} {}", method, path);
    let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None);
    // Canonical snake_case form matching the `recording_mode` field serialized
    // into AEP records, rather than the Debug-format PascalCase.
    evidence.recording_mode.as_str().to_string()
}

#[cfg(target_arch = "wasm32")]
impl Context for EvidenceFilter {}

#[cfg(target_arch = "wasm32")]
impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.trace_id = self.get_http_request_header("x-b3-traceid");
        self.agent_id = self.get_http_request_header("x-agent-id");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let header_value = recording_mode_for_request(&self.method, &self.path, self.context_id);
        self.set_http_response_header("x-aep-recording-mode", Some(&header_value));
        Action::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_context_id() {
        let filter = EvidenceFilter::new(42);
        assert_eq!(filter.context_id, 42);
    }

    #[test]
    fn new_initializes_empty_state() {
        let filter = EvidenceFilter::new(1);
        assert!(filter.method.is_empty());
        assert!(filter.path.is_empty());
        assert!(filter.trace_id.is_none());
        assert!(filter.agent_id.is_none());
    }

    #[test]
    fn after_request_headers_fields_are_populated() {
        let mut filter = EvidenceFilter::new(7);
        // Simulates what on_http_request_headers would do with real headers.
        filter.method = "POST".into();
        filter.path = "/api/v1/data".into();
        filter.trace_id = Some("trace-abc".into());
        filter.agent_id = Some("agent-007".into());

        assert_eq!(filter.method, "POST");
        assert_eq!(filter.path, "/api/v1/data");
        assert_eq!(filter.trace_id.as_deref(), Some("trace-abc"));
        assert_eq!(filter.agent_id.as_deref(), Some("agent-007"));
    }

    #[test]
    fn recording_mode_for_read_request_is_validation() {
        // Exercises the on_http_response_headers pipeline end-to-end on the
        // native target: GET → SideEffectClass::Read → Validation mode.
        assert_eq!(
            recording_mode_for_request("GET", "/api/v1/data", 9),
            "validation"
        );
    }

    #[test]
    fn recording_mode_for_external_mutation_is_full() {
        // POST to a non-network path → MutateExternal → Full recording.
        assert_eq!(
            recording_mode_for_request("POST", "/api/v1/users", 3),
            "full"
        );
    }

    #[test]
    fn recording_mode_for_network_egress_is_full() {
        // POST to a /network/ path → NetworkEgress → Full recording.
        assert_eq!(
            recording_mode_for_request("POST", "/network/peers", 5),
            "full"
        );
    }
}
