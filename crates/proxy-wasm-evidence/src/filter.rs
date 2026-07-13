use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, classify_mcp_headers, infer_side_effect_class};
use aep_core::recording::RiskContext;

pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    trace_id: Option<String>,
    session_id: Option<String>,
    mcp_header_risk: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            session_id: None,
            mcp_header_risk: None,
        }
    }
}

impl Context for EvidenceFilter {}

impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path   = self.get_http_request_header(":path").unwrap_or_default();

        // --- MCP 2026-07-28 trace correlation ---
        // Check MCP-standard headers first, then fall back to Zipkin B3 / x-agent-id.
        self.trace_id = self.get_http_request_header("mcp-trace-id")
            .or_else(|| self.get_http_request_header("x-b3-traceid"));
        self.session_id = self.get_http_request_header("mcp-session-id")
            .or_else(|| self.get_http_request_header("x-agent-id"));

        // Detect sensitive-data leakage in MCP-specific headers.
        let mcp_method = self.get_http_request_header("MCP-Method");
        let mcp_name   = self.get_http_request_header("MCP-Name");
        self.mcp_header_risk =
            classify_mcp_headers(mcp_method.as_deref(), mcp_name.as_deref())
                .map(|r| r.label());

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
        let mut evidence = build_evidence(
            action_id,
            tool_name,
            &risk_ctx,
            0,
            None,
            self.mcp_header_risk.clone(),
        );
        // Populate MCP trace correlation fields.
        evidence.trace_id = self.trace_id.clone();
        evidence.session_id = self.session_id.clone();

        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        // If MCP header risk was detected, expose it as a response header.
        if let Some(ref risk) = self.mcp_header_risk {
            self.set_http_response_header("x-aep-mcp-header-risk", Some(risk.as_str()));
        }
        // Emit trace correlation response headers for downstream consumers.
        if let Some(ref tid) = self.trace_id {
            self.set_http_response_header("x-aep-trace-id", Some(tid.as_str()));
        }
        if let Some(ref sid) = self.session_id {
            self.set_http_response_header("x-aep-session-id", Some(sid.as_str()));
        }
        Action::Continue
    }
}
