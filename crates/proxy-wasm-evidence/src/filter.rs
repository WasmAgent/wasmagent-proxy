use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::PluginConfig;
use crate::recorder::{build_evidence, infer_side_effect_class_with_mcp, EvidenceBuffer};
use aep_core::classify_mcp_headers;
use aep_core::recording::RiskContext;
use aep_core::RecordingMode;
use proxy_wasm::hostcalls::{define_metric, increment_metric};
use proxy_wasm::types::MetricType;

/// Envoy stat name prefix for AEP evidence counters.
/// Exported as `aep_evidence_recorded_total{mode="validation|delta|full"}`
/// when Envoy's Prometheus exporter is configured with appropriate tag
/// extraction rules.
const METRIC_BASE: &str = "aep.evidence.recorded_total";

pub struct EvidenceRoot {
    config: PluginConfig,
}

impl EvidenceRoot {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for EvidenceRoot {
    fn default() -> Self {
        Self {
            config: PluginConfig::default(),
        }
    }
}

impl Context for EvidenceRoot {}

impl RootContext for EvidenceRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        if plugin_configuration_size == 0 {
            self.config = PluginConfig::default();
            return true;
        }

        let Some(config_bytes) = self.get_plugin_configuration() else {
            return false;
        };

        match serde_json::from_slice::<PluginConfig>(&config_bytes) {
            Ok(config) => {
                if config.max_evidence_buffer == 0 {
                    log::error!("proxy-wasm evidence max_evidence_buffer must be greater than 0");
                    return false;
                }
                self.config = config;
                true
            }
            Err(err) => {
                log::error!("failed to parse proxy-wasm evidence config JSON: {err}");
                false
            }
        }
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EvidenceFilter::new(
            context_id,
            self.config.clone(),
        )))
    }
}

pub struct EvidenceFilter {
    context_id: u32,
    config: PluginConfig,
    evidence_buffer: EvidenceBuffer,
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
    pub fn new(context_id: u32, config: PluginConfig) -> Self {
        let evidence_buffer = EvidenceBuffer::new(config.max_evidence_buffer);
        Self {
            context_id,
            config,
            evidence_buffer,
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
        self.trace_id = self.get_http_request_header(&self.config.trace_id_header);
        self.agent_id = self.get_http_request_header(&self.config.agent_id_header);
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
        let action_id = format!("ctx-{}", self.context_id);
        let tool_name = format!("{} {}", self.method, self.path);
        let mcp_header_risk =
            classify_mcp_headers(self.mcp_method.as_deref(), self.mcp_name.as_deref());
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None, mcp_header_risk);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        // Surface MCP 2026-07-28 header leakage detection on the response so
        // downstream observers can react without parsing the AEP record body.
        // Carries the same snake_case variant name stored on
        // `ActionEvidence::mcp_header_risk`; omitted entirely when no risk was
        // detected (None clears/omits the header).
        self.set_http_response_header(
            "x-aep-mcp-header-risk",
            evidence.mcp_header_risk.as_deref(),
        );
        // Increment the appropriate Prometheus counter for this recording mode.
        let metric_id = match evidence.recording_mode {
            RecordingMode::Validation => self.metric_validation,
            RecordingMode::Delta => self.metric_delta,
            RecordingMode::Full => self.metric_full,
        };
        let _ = increment_metric(metric_id, 1);
        let _ = self.evidence_buffer.push(evidence);
        Action::Continue
    }
}
