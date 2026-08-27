pub mod evidence;
pub mod mcp_headers;
pub mod prov;
pub mod recording;
pub mod signing;

pub use evidence::{ActionEvidence, AepRecord, CapabilityDecision};
pub use mcp_headers::{classify_mcp_headers, McpHeaderRisk};
pub use prov::{ProvActivity, ProvAgent, ProvEntity, ProvGraph};
pub use recording::{
    compile_recording_policy, RecordingMode, RecordingPolicy, RiskContext, SideEffectClass,
};
pub use signing::{sign_record, verify_record, SigningKey};
