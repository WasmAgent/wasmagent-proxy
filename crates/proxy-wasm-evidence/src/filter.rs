use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, infer_side_effect_class};
use aep_core::evidence::TraceCorrelation;
use aep_core::recording::RiskContext;

/// Proxy-Wasm HTTP context that records AEP evidence for intercepted requests.
///
/// # Trace correlation model
///
/// Under the MCP 2026-07-28 stateless/handle-based architecture (RC locked
/// 2026-05-21), each request is independent — protocol-level session state no
/// longer exists. The proxy reads three correlation headers:
///
/// - `MCP-Protocol-Version` — mandatory MCP version header (e.g. `2026-07-28`).
/// - `Mcp-Method` — the JSON-RPC method name (e.g. `tools/call`), used as
///   higher-signal input for side-effect classification.
/// - `Mcp-Name` — the tool or resource name invoked (e.g. `search`).
/// - `Mcp-Handle-Id` — the handle ID threaded by the model between tool calls
///   for correlating evidence across independent stateless requests.
///
/// Additionally, the proxy reads two **implementation-specific** headers that
/// are NOT part of the MCP specification but are widely used in OpenTelemetry
/// deployments for distributed-trace correlation:
///
/// - `x-b3-traceid` — Zipkin/OpenTelemetry trace ID (implementation-specific).
/// - `x-agent-id` — caller-supplied agent identifier (implementation-specific).
///
/// Under the new stateless model, trace IDs no longer span a full
/// conversation context; evidence records linked by `trace_id` may become
/// disconnected across independent requests. The `mcp_method`, `mcp_name`,
/// and `mcp_handle_id` headers provide a more reliable per-request correlation
/// mechanism aligned with the MCP 2026-07-28 spec.
///
/// The filter validates the trace correlation model against the MCP 2026-07-28
/// stateless/handle spec using [`TraceCorrelation::from_headers`] and echoes
/// all MCP correlation headers as `x-aep-*` response headers so that downstream
/// components (e.g. the wasmagent-js MCP firewall) can reconstruct a fully
/// correlated `AepRecord` using [`AepRecord::build_evidence_record`].
pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    /// Zipkin/OpenTelemetry trace ID (implementation-specific; NOT part of the
    /// MCP protocol). Under MCP 2026-07-28 stateless architecture, this may
    /// not span a full conversation context.
    trace_id: Option<String>,
    /// Caller-supplied agent identifier (implementation-specific; NOT part of
    /// the MCP protocol).
    agent_id: Option<String>,
    /// Validated MCP trace correlation (populated after header processing).
    correlation: Option<TraceCorrelation>,
    /// Validation error message, if any, from trace correlation validation.
    correlation_error: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            agent_id: None,
            correlation: None,
            correlation_error: None,
        }
    }
}

impl Context for EvidenceFilter {}

impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();

        // Implementation-specific correlation headers (NOT part of MCP protocol).
        self.trace_id = self.get_http_request_header("x-b3-traceid");
        self.agent_id = self.get_http_request_header("x-agent-id");

        // MCP 2026-07-28 protocol headers (mandatory under stateless/handle spec).
        let mcp_protocol_version = self.get_http_request_header("MCP-Protocol-Version");
        let mcp_method = self.get_http_request_header("Mcp-Method");
        let mcp_name = self.get_http_request_header("Mcp-Name");
        // Handle ID is the primary correlation key under the stateless model.
        let handle_id = self.get_http_request_header("Mcp-Handle-Id");

        // Validate trace correlation against MCP 2026-07-28 stateless model.
        match TraceCorrelation::from_headers(
            self.trace_id.clone(),
            handle_id.clone(),
            mcp_protocol_version.clone(),
            mcp_method.clone(),
            mcp_name.clone(),
        ) {
            Ok(correlation) => {
                self.correlation = Some(correlation);
                self.correlation_error = None;
            }
            Err(e) => {
                log::warn!("trace correlation validation failed: {}", e);
                self.correlation = None;
                self.correlation_error = Some(e);
            }
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // When MCP-Method is present, use it for higher-signal side-effect
        // classification (e.g. `tools/call` implies external mutation) instead
        // of falling back to HTTP method + path heuristics alone.
        let mcp_method = self
            .correlation
            .as_ref()
            .and_then(|c| c.mcp_method.as_deref());
        let mcp_name = self
            .correlation
            .as_ref()
            .and_then(|c| c.mcp_name.as_deref());
        let handle_id = self
            .correlation
            .as_ref()
            .and_then(|c| c.handle_id.as_deref());
        let mcp_protocol_version = self
            .correlation
            .as_ref()
            .and_then(|c| c.mcp_protocol_version.as_deref());

        let side_effect_class =
            infer_side_effect_class(&self.method, &self.path, mcp_method);
        let risk_ctx = RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        };
        let action_id = format!("ctx-{}", self.context_id);
        // Prefer MCP tool name for evidence identification when available,
        // falling back to HTTP method + path.
        let tool_name = mcp_name
            .map(String::from)
            .or_else(|| mcp_method.map(String::from))
            .unwrap_or_else(|| format!("{} {}", self.method, self.path));
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );

        // Propagate MCP 2026-07-28 correlation headers as x-aep-* response
        // headers so downstream components (e.g. wasmagent-js MCP firewall)
        // can reconstruct a fully correlated AepRecord using
        // AepRecord::build_evidence_record.
        //
        // Under the stateless/handle-based architecture these fields are the
        // primary correlation mechanism, taking precedence over trace_id.

        // Echo the handle ID — the primary correlation key under stateless model.
        if let Some(id) = handle_id {
            self.set_http_response_header("x-aep-handle-id", Some(id));
        }
        // Echo the MCP protocol version when present.
        if let Some(ver) = mcp_protocol_version {
            self.set_http_response_header("x-aep-mcp-protocol-version", Some(ver));
        }
        // Echo the MCP method name when present.
        if let Some(method) = mcp_method {
            self.set_http_response_header("x-aep-mcp-method", Some(method));
        }
        // Echo the MCP tool/resource name when present.
        if let Some(name) = mcp_name {
            self.set_http_response_header("x-aep-mcp-name", Some(name));
        }
        // Echo the trace ID for downstream correlation when present.
        if let Some(ref trace_id) = self.trace_id {
            self.set_http_response_header("x-aep-trace-id", Some(trace_id));
        }
        // Echo the agent ID for downstream correlation when present.
        if let Some(ref agent_id) = self.agent_id {
            self.set_http_response_header("x-aep-agent-id", Some(agent_id));
        }

        // If trace correlation validation failed, emit a header indicating the
        // validation error so downstream components are aware.
        if let Some(ref err) = self.correlation_error {
            self.set_http_response_header("x-aep-correlation-error", Some(err));
        }

        Action::Continue
    }
}
