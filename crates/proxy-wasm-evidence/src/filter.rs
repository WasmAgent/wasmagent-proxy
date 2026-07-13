use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::recorder::{build_evidence, infer_side_effect_class};
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
    /// MCP protocol version header (e.g. `2026-07-28`). Mandatory under the
    /// MCP 2026-07-28 stateless/handle-based specification.
    mcp_protocol_version: Option<String>,
    /// MCP JSON-RPC method name (e.g. `tools/call`, `resources/read`).
    /// Used as higher-signal input for side-effect classification.
    mcp_method: Option<String>,
    /// MCP tool or resource name (e.g. `search`). Used as additional
    /// correlation signal under the stateless/handle-based model.
    mcp_name: Option<String>,
    /// MCP handle ID for stateless request correlation. Threaded by the model
    /// between tool calls as arguments and carried in the `Mcp-Handle-Id`
    /// header. Under MCP 2026-07-28 this is the primary correlation key;
    /// preferred over `trace_id` for linking evidence records.
    handle_id: Option<String>,
}

impl EvidenceFilter {
    pub fn new(context_id: u32) -> Self {
        Self {
            context_id,
            method: String::new(),
            path: String::new(),
            trace_id: None,
            agent_id: None,
            mcp_protocol_version: None,
            mcp_method: None,
            mcp_name: None,
            handle_id: None,
        }
    }
}

impl Context for EvidenceFilter {}

impl HttpContext for EvidenceFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path   = self.get_http_request_header(":path").unwrap_or_default();

        // Implementation-specific correlation headers (NOT part of MCP protocol).
        self.trace_id = self.get_http_request_header("x-b3-traceid");
        self.agent_id = self.get_http_request_header("x-agent-id");

        // MCP 2026-07-28 protocol headers (mandatory under stateless/handle spec).
        self.mcp_protocol_version = self.get_http_request_header("MCP-Protocol-Version");
        self.mcp_method = self.get_http_request_header("Mcp-Method");
        self.mcp_name = self.get_http_request_header("Mcp-Name");
        // Handle ID is the primary correlation key under the stateless model.
        self.handle_id = self.get_http_request_header("Mcp-Handle-Id");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // When MCP-Method is present, use it for higher-signal side-effect
        // classification (e.g. `tools/call` implies external mutation) instead
        // of falling back to HTTP method + path heuristics alone.
        let side_effect_class = infer_side_effect_class(
            &self.method,
            &self.path,
            self.mcp_method.as_deref(),
        );
        let risk_ctx = RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        };
        let action_id = format!("ctx-{}", self.context_id);
        // Prefer MCP tool name for evidence identification when available,
        // falling back to HTTP method + path.
        let tool_name = self
            .mcp_name
            .clone()
            .or_else(|| self.mcp_method.clone())
            .unwrap_or_else(|| format!("{} {}", self.method, self.path));
        let evidence = build_evidence(action_id, tool_name, &risk_ctx, 0, None);
        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );
        // When an MCP handle ID was received, echo it back so the caller can
        // correlate this proxy's evidence with downstream tool-call evidence.
        if let Some(ref handle_id) = self.handle_id {
            self.set_http_response_header("x-aep-handle-id", Some(handle_id));
        }
        Action::Continue
    }
}
