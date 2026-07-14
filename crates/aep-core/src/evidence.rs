use crate::recording::RecordingMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDecision {
    pub capability: String,
    pub subject: String,
    pub resource: String,
    pub decision: String,
    pub reason_code: Option<String>,
}

/// Risk classification for MCP-Method / MCP-Name header values.
///
/// The MCP 2026-07-28 specification introduces `MCP-Method` and `MCP-Name`
/// as HTTP headers that carry structured tool-call metadata. If upstream
/// services incorrectly map secrets or PII into these headers, the values
/// become visible to every intermediary. This struct captures the signals
/// that `classify_mcp_headers` detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpHeaderRisk {
    /// Set when the value starts with a known credential prefix
    /// (e.g. `ghp_`, `sk-`, `Bearer `).
    pub has_credential_prefix: bool,
    /// Set when the value exceeds 32 characters (proxy for high-entropy
    /// secrets such as API tokens or JWTs).
    pub is_high_entropy: bool,
    /// Set when the value matches an email-like pattern (local-part followed
    /// by `@domain.tld`) — relevant only for `MCP-Name` headers where a
    /// service might mistakenly inject a user email.
    pub is_email_like: bool,
    /// Which header carried the risky value: `"MCP-Method"` or `"MCP-Name"`.
    pub source_header: String,
    /// First 40 characters of the risky value — enough for forensics without
    /// leaking the full secret across intermediary hops.
    pub value_snippet: String,
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
    /// Present when the MCP-Method or MCP-Name request header contained a
    /// value that looks like a credential, high-entropy secret, or PII.
    #[serde(default)]
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
