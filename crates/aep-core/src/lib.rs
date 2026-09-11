pub mod dsse;
pub mod evidence;
pub mod mcp_headers;
pub mod prov;
pub mod recording;
pub mod signing;

pub use dsse::{pae_encode, sign_record_dsse, verify_record_dsse};
pub use evidence::{
    ActionEvidence, AepRecord, CapabilityDecision, DsseEnvelope, DsseSignature, AEP_SCHEMA_VERSION,
};
pub use mcp_headers::{classify_mcp_headers, McpHeaderRisk};
pub use prov::{ProvActivity, ProvAgent, ProvEntity, ProvGraph};
pub use recording::{
    compile_recording_policy, RecordingMode, RecordingPolicy, RiskContext, SideEffectClass,
};
pub use signing::{sign_record, verify_record, SigningKey};
