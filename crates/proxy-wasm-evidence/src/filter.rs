use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, infer_side_effect_class};
use aep_core::recording::{RiskContext, SideEffectClass};

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

impl Context for EvidenceFilter {}

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
        let mode = format!("{:?}", evidence.recording_mode);
        self.set_http_response_header("x-aep-recording-mode", Some(&mode));
        Action::Continue
    }
}
