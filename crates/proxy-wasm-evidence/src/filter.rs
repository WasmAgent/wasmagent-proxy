use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::PluginConfig;
use crate::recorder::{
    build_evidence, infer_side_effect_class_with_mcp, unix_millis, EvidenceBuffer,
};
use aep_core::classify_mcp_headers;
use aep_core::recording::RiskContext;
use aep_core::RecordingMode;
use proxy_wasm::hostcalls::{define_metric, get_current_time, increment_metric};
use proxy_wasm::types::MetricType;

/// Envoy stat name prefix for AEP evidence counters.
/// Exported as `aep_evidence_recorded_total{mode="validation|delta|full"}`
/// when Envoy's Prometheus exporter is configured with appropriate tag
/// extraction rules.
const METRIC_BASE: &str = "aep.evidence.recorded_total";

/// Proxy-Wasm counter IDs for `aep_evidence_recorded_total{mode=...}`, defined
/// once per VM in [`EvidenceRoot::on_configure`] (a hostcall per HTTP context
/// would otherwise run on every request). `0` means the host refused the
/// definition; incrementing metric 0 is a harmless no-op error.
#[derive(Clone, Copy, Default)]
struct EvidenceMetrics {
    validation: u32,
    delta: u32,
    full: u32,
}

impl EvidenceMetrics {
    fn define() -> Self {
        Self {
            validation: define_metric(MetricType::Counter, &format!("{}.validation", METRIC_BASE))
                .unwrap_or(0),
            delta: define_metric(MetricType::Counter, &format!("{}.delta", METRIC_BASE))
                .unwrap_or(0),
            full: define_metric(MetricType::Counter, &format!("{}.full", METRIC_BASE)).unwrap_or(0),
        }
    }

    fn id_for(&self, mode: &RecordingMode) -> u32 {
        match mode {
            RecordingMode::Validation => self.validation,
            RecordingMode::Delta => self.delta,
            RecordingMode::Full => self.full,
        }
    }
}

pub struct EvidenceRoot {
    config: PluginConfig,
    metrics: EvidenceMetrics,
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
            metrics: EvidenceMetrics::default(),
        }
    }
}

impl Context for EvidenceRoot {}

impl RootContext for EvidenceRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        // Define counters once per VM, before any HTTP context exists.
        self.metrics = EvidenceMetrics::define();

        if plugin_configuration_size == 0 {
            self.config = PluginConfig::default();
            return true;
        }

        let Some(config_bytes) = self.get_plugin_configuration() else {
            return false;
        };

        match serde_json::from_slice::<PluginConfig>(&config_bytes) {
            Ok(config) => match config.validate() {
                Ok(()) => self.config = config,
                Err(reason) => {
                    log::error!("invalid proxy-wasm evidence config: {reason}");
                    return false;
                }
            },
            Err(err) => {
                log::error!("failed to parse proxy-wasm evidence config JSON: {err}");
                return false;
            }
        }
        true
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EvidenceFilter::new(
            context_id,
            self.config.clone(),
            self.metrics,
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
    /// Counter IDs defined once by the root context — see [`EvidenceMetrics`].
    metrics: EvidenceMetrics,
}

impl EvidenceFilter {
    /// Contexts are only created by [`EvidenceRoot::create_http_context`] in
    /// this module; keeping `new` private also avoids exposing the
    /// module-private [`EvidenceMetrics`] through a public signature.
    fn new(context_id: u32, config: PluginConfig, metrics: EvidenceMetrics) -> Self {
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
            metrics,
        }
    }

    /// Unix-milliseconds timestamp for evidence records, sourced from the
    /// host so the Wasm module needs no direct wall-clock access. Falls back
    /// to 0 if the host call fails.
    fn current_time_ms(&self) -> u64 {
        get_current_time().map(unix_millis).unwrap_or(0)
    }
}

impl Context for EvidenceFilter {}

impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.trace_id = self.get_http_request_header(&self.config.trace_id_header);
        self.agent_id = self.get_http_request_header(&self.config.agent_id_header);
        // Capture mcp_method from "x-mcp-method" (prefixed variant) or
        // "mcp-method" (bare variant). proxy-wasm normalises header names to
        // lowercase, so both "X-MCP-Method" and "MCP-Method" map to the same
        // lookup key.
        self.mcp_method = self
            .get_http_request_header("x-mcp-method")
            .or_else(|| self.get_http_request_header("mcp-method"));
        // Capture mcp_name from "mcp-name" or "x-mcp-name".
        self.mcp_name = self
            .get_http_request_header("mcp-name")
            .or_else(|| self.get_http_request_header("x-mcp-name"));
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
        // The configured default_mode is the operator's MINIMUM recording
        // baseline: evidence may escalate above it, never fall below it
        // (audit P0: default_mode=full + GET must stay Full).
        let mut evidence = build_evidence(
            action_id,
            tool_name,
            &risk_ctx,
            self.current_time_ms(),
            None,
            mcp_header_risk,
        );
        evidence.recording_mode = crate::recorder::max_recording_mode(
            evidence.recording_mode.clone(),
            self.config.default_mode.clone(),
        );
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        // Increment the appropriate Prometheus counter for this recording mode.
        let _ = increment_metric(self.metrics.id_for(&evidence.recording_mode), 1);
        if let Some(ref risk_str) = evidence.mcp_header_risk {
            self.set_http_response_header("x-aep-mcp-header-risk", Some(risk_str));
        }
        let _ = self.evidence_buffer.push(evidence);
        Action::Continue
    }
}
