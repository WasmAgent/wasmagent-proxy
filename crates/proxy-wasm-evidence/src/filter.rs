use proxy_wasm::traits::*;
use proxy_wasm::types::*;

use crate::config::PluginConfig;
use crate::recorder::{build_evidence, classify_mcp_headers, resolve_side_effect_class};
use aep_core::evidence::McpHeaderRisk;
use aep_core::recording::{RiskContext, SideEffectClass};

pub struct EvidenceFilter {
    context_id: u32,
    method: String,
    path: String,
    trace_id: Option<String>,
    agent_id: Option<String>,
    side_effect_override: Option<String>,
    mcp_method: Option<String>,
    mcp_name: Option<String>,
    mcp_header_risk: Option<McpHeaderRisk>,
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
            mcp_method: None,
            mcp_name: None,
            mcp_header_risk: None,
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
        //
        // SECURITY: This header is trusted only if the plugin configuration
        // includes an `override_trust_token` AND the request carries a matching
        // `x-aep-override-token` header. Without trust validation, any downstream
        // client could set `x-aep-side-effect-class` to downgrade the evidence
        // recording mode. When `override_trust_token` is not configured, the
        // override is silently ignored — the side-effect class is always
        // determined by the method/path heuristic.
        let raw_override = self.get_http_request_header("x-aep-side-effect-class");
        self.side_effect_override = if is_override_trusted(self, raw_override.is_some()) {
            raw_override
        } else {
            None
        };

        // Read MCP 2026-07-28 protocol-specific headers for sensitive-data
        // leakage detection.
        self.mcp_method = self.get_http_request_header("MCP-Method");
        self.mcp_name = self.get_http_request_header("MCP-Name");

        // Classify MCP header values for credential / high-entropy / PII risks.
        self.mcp_header_risk = classify_mcp_headers(
            self.mcp_method.as_deref(),
            self.mcp_name.as_deref(),
        );

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let side_effect_class = resolve_side_effect_class(
            self.side_effect_override.as_deref(),
            &self.method,
            &self.path,
        );

        // When MCP header risk is detected (credential/high-entropy/PII leakage in
        // MCP-Method or MCP-Name headers), escalate the side-effect class to
        // MutateExternal so that compile_recording_policy produces Full recording.
        // This ensures the evidence system captures the full request/response for
        // forensic analysis of the leaked sensitive data.
        let side_effect_class = if self.mcp_header_risk.is_some() {
            SideEffectClass::MutateExternal
        } else {
            side_effect_class
        };

        let risk_ctx = RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        };
        let action_id = format!("ctx-{}", self.context_id);
        let tool_name = format!("{} {}", self.method, self.path);

        // Take the MCP header risk (if any) detected during request header processing.
        let mcp_risk = self.mcp_header_risk.take();

        let evidence = build_evidence(
            action_id,
            tool_name,
            &risk_ctx,
            0,
            None,
            mcp_risk,
        );

        // Emit the canonical snake_case form (matching the `recording_mode` field
        // serialized into AEP records) rather than the Debug-format PascalCase.
        self.set_http_response_header(
            "x-aep-recording-mode",
            Some(evidence.recording_mode.as_str()),
        );

        // When MCP header risk was detected, surface it as a response header
        // so intermediaries and downstream consumers are alerted.
        if let Some(ref risk) = evidence.mcp_header_risk {
            // Serialize the risk classification as a compact JSON value.
            let risk_json = serde_json::to_string(risk).unwrap_or_default();
            self.set_http_response_header(
                "x-aep-mcp-header-risk",
                Some(&risk_json),
            );
        }

        Action::Continue
    }
}

/// Check whether the `x-aep-side-effect-class` override header can be trusted.
///
/// Returns `true` when:
/// - No override header is present (trivially trusted — nothing to validate).
/// - The plugin configuration has an `override_trust_token` AND the request
///   carries a matching `x-aep-override-token` header.
///
/// Returns `false` when:
/// - An override header IS present but `override_trust_token` is not configured
///   (the override feature is disabled by default for security).
/// - An override header IS present and the `x-aep-override-token` header either
///   is absent or does not match the configured trust token.
fn is_override_trusted(ctx: &impl Context, has_override: bool) -> bool {
    if !has_override {
        // No override to validate — trivially trusted.
        return true;
    }

    // Try to load the plugin configuration.
    let config: PluginConfig = ctx
        .get_plugin_configuration()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();

    match config.override_trust_token {
        Some(ref token) if !token.is_empty() => {
            // Trust token is configured — require a matching request header.
            let request_token = ctx
                .get_http_request_header("x-aep-override-token")
                .unwrap_or_default();
            request_token == *token
        }
        _ => {
            // Trust token is NOT configured — override is disabled by default.
            // This is the secure default: clients cannot downgrade evidence
            // unless the operator explicitly enables the feature.
            false
        }
    }
}
