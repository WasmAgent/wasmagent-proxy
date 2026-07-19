use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{
    build_evidence, classify_mcp_headers, infer_side_effect_class, infer_side_effect_class_with_mcp,
};
use aep_core::recording::RiskContext;
use aep_core::RecordingMode;
use proxy_wasm::hostcalls::{define_metric, increment_metric};

/// Envoy stat name prefix for AEP evidence counters.
/// Exported as `aep_evidence_recorded_total{mode="validation|delta|full"}`
/// when Envoy's Prometheus exporter is configured with appropriate tag
/// extraction rules.
const METRIC_BASE: &str = "aep.evidence.recorded_total";

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
    /// Prometheus counter IDs for `aep_evidence_recorded_total{mode=...}`.
    /// Defined via `proxy_wasm::hostcalls::define_metric` on construction.
    metric_validation: u32,
    metric_delta: u32,
    metric_full: u32,
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
            metric_validation: define_metric(
                MetricType::Counter,
                &format!("{}.validation", METRIC_BASE),
            )
            .unwrap_or(0),
            metric_delta: define_metric(MetricType::Counter, &format!("{}.delta", METRIC_BASE))
                .unwrap_or(0),
            metric_full: define_metric(MetricType::Counter, &format!("{}.full", METRIC_BASE))
                .unwrap_or(0),
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
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None, None);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        // Increment the appropriate Prometheus counter for this recording mode.
        let metric_id = match evidence.recording_mode {
            RecordingMode::Validation => self.metric_validation,
            RecordingMode::Delta => self.metric_delta,
            RecordingMode::Full => self.metric_full,
        };
        let _ = increment_metric(metric_id, 1);
        Action::Continue
    }
}
