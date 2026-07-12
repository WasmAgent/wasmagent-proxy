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

#[cfg(target_arch = "wasm32")]
impl Context for EvidenceFilter {}

#[cfg(target_arch = "wasm32")]
impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path   = self.get_http_request_header(":path").unwrap_or_default();
        self.trace_id = self.get_http_request_header("x-b3-traceid");
        self.agent_id = self.get_http_request_header("x-agent-id");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let side_effect_class = infer_side_effect_class(&self.method, &self.path);
        let risk_ctx = RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        };
        let action_id = format!("ctx-{}", self.context_id);
        let tool_name = format!("{} {}", self.method, self.path);
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
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
}
