use base64::Engine as _;
pub use ed25519_dalek::SigningKey;

/// Encode an Ed25519 signature the way every verifier in the ecosystem
/// expects: standard base64. (JS `verifyAEPRecord` and trace-pipeline's
/// Python verifier both base64-decode `signature.sig`.)
pub fn encode_signature(sig_bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig_bytes)
}

// Historical note — the legacy signing profile was REMOVED in the clean cut:
// `sign_record` (Ed25519 over SHA-256(struct-order JSON)) and `verify_record`
// no longer exist. DSSE (`sign_record_dsse` / `verify_record_dsse`) is the
// only signing profile. Historical legacy records survive solely as evidence
// in wasmagent-protocol `conformance/aep/historical/` — they are NOT part of
// the conformance target and no verifier supports them.
