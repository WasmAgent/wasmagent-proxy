use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

/// Risk level detected in MCP-specific headers (MCP 2026-07-28+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpHeaderRisk {
    /// Credential-like pattern detected (e.g. ghp_, sk-, Bearer prefix).
    CredentialLeak,
    /// High-entropy string > 32 chars detected (potential API key).
    HighEntropyValue,
    /// Email-like pattern detected in MCP-Name header.
    PiiLeak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDecision {
    pub capability: String,
    pub subject: String,
    pub resource: String,
    pub decision: String,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvidence {
    pub action_id: String,
    pub tool_name: String,
    pub state_changing: bool,
    pub precondition_digest: Option<String>,
    pub result_digest: Option<String>,
    pub timestamp_ms: u64,
    pub parent_action_id: Option<String>,
    pub causal_chain_id: Option<String>,
    pub recording_mode: RecordingMode,
    pub capability_decision: Option<CapabilityDecision>,
    pub mcp_header_risk: Option<McpHeaderRisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepRecord {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub actions: Vec<ActionEvidence>,
    pub created_at_ms: u64,
    pub signature: Option<AepSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AepSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}
