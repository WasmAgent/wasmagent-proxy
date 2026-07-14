use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, resolve_side_effect_class};
use aep_core::recording::RiskContext;

pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    trace_id: Option<String>,
    agent_id: Option<String>,
    side_effect_override: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            agent_id: None,
            side_effect_override: None,
        }
    }
}

impl Context for EvidenceFilter {}

impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.trace_id = self.get_http_request_header("x-b3-traceid");
        self.agent_id = self.get_http_request_header("x-agent-id");
        // Per-request override of the side-effect heuristic (see
        // `resolve_side_effect_class`). Recognized values are the snake_case
        // SideEffectClass variants; an unrecognized value is ignored.
        self.side_effect_override = self.get_http_request_header("x-aep-side-effect-class");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let side_effect_class = resolve_side_effect_class(
            self.side_effect_override.as_deref(),
            &self.method,
            &self.path,
        );
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
