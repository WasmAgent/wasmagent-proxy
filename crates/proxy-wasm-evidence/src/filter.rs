use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, classify_mcp_headers, infer_side_effect_class_with_mcp};
use aep_core::recording::RiskContext;

pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    trace_id: Option<String>,
    agent_id: Option<String>,
    /// MCP-Method header value (MCP 2026-07-28+ protocol). When present, used in
    /// place of the HTTP method heuristic for side-effect classification.
    mcp_method: Option<String>,
    /// MCP-Name header value (MCP 2026-07-28+). Checked for PII/credential leakage.
    mcp_name: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            agent_id: None,
            mcp_method: None,
            mcp_name: None,
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
        self.mcp_method = self.get_http_request_header("mcp-method");
        self.mcp_name = self.get_http_request_header("mcp-name");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let side_effect_class =
            infer_side_effect_class_with_mcp(&self.method, &self.path, self.mcp_method.as_deref());
        let risk_ctx = RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        };
        let mcp_header_risk = classify_mcp_headers(self.mcp_method.as_deref(), self.mcp_name.as_deref());
        let action_id = format!("ctx-{}", self.context_id);
        let tool_name = format!("{} {}", self.method, self.path);
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None, mcp_header_risk);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        if let Some(ref risk) = evidence.mcp_header_risk {
            self.set_http_response_header("x-aep-mcp-header-risk", Some(risk.as_str()));
        }
        Action::Continue
    }
}
