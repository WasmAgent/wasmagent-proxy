use crate::evidence::AepRecord;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub use ed25519_dalek::SigningKey;

/// Errors that can occur during signature verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The record has no signature attached.
    MissingSignature,
    /// The signature string could not be decoded (base64 or legacy hex).
    MalformedSignatureEncoding,
    /// The decoded signature bytes are not the expected length.
    InvalidSignatureLength,
    /// The cryptographic verification failed (wrong key or tampered data).
    SignatureMismatch,
}

/// Encode an Ed25519 signature the way every verifier in the ecosystem
/// expects: standard base64. (JS `verifyAEPRecord` and trace-pipeline's
/// Python verifier both base64-decode `signature.sig`; the gateway used to
/// emit hex, which made gateway records unverifiable outside Rust.)
pub fn encode_signature(sig_bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig_bytes)
}

/// Decode a signature string. Current producers emit standard base64;
/// pre-aep/v0.5 gateway releases emitted 128-char lowercase hex — accepted
/// for backward compatibility with already-published records.
fn decode_signature(sig: &str) -> Result<Vec<u8>, VerificationError> {
    let s = sig.trim();
    let is_legacy_hex = s.len() == 128 && s.chars().all(|c| c.is_ascii_hexdigit());
    if is_legacy_hex {
        return hex::decode(s).map_err(|_| VerificationError::MalformedSignatureEncoding);
    }
    // Tolerate URL-safe alphabets and missing padding on the base64 path.
    let normalized: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let padded = match normalized.len() % 4 {
        2 => format!("{}==", normalized),
        3 => format!("{}=", normalized),
        _ => normalized,
    };
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|_| VerificationError::MalformedSignatureEncoding)
}

pub fn sign_record(record: &mut AepRecord, key: &DalekSigningKey, key_id: &str) {
    // Sign the UNSIGNED form: a previous `signature` value (e.g. when
    // re-signing a record emitted elsewhere) must not be covered by the new
    // signature — the JS verifier strips `signature` before canonicalizing.
    let mut unsigned = record.clone();
    unsigned.signature = None;
    let canonical = canonical_bytes(&unsigned);
    let sig = key.sign(&canonical);
    record.signature = Some(crate::evidence::AepSignature {
        alg: "ed25519".into(),
        key_id: key_id.into(),
        sig: encode_signature(&sig.to_bytes()),
    });
}

/// Which historical message construction a legacy signature covers.
///
/// The Rust gateway signer hashes the canonical bytes before signing
/// (`Ed25519(SHA256(canonical))`), while the JS emitter signs the raw
/// sorted-canonical bytes (`Ed25519(canonical)`). Both are legitimate
/// historical profiles; verification that accepts either MUST report which
/// one held so `valid: true` never hides a semantics choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacySignatureProfile {
    /// Ed25519 over SHA-256(canonical bytes) — this crate's signer.
    CanonicalSha256,
    /// Ed25519 over the raw sorted-canonical bytes — the JS emitter
    /// construction (serde's sorted-key serialization, matching the JS
    /// canonicalizer byte-for-byte).
    RawCanonical,
}

/// Verify a legacy-signed record, accepting either historical message
/// construction and reporting which profile held. The primary check is this
/// crate's own profile (SHA-256); the raw-canonical profile exists so
/// records signed by the JS emitter verify without re-signing.
pub fn verify_record_profile(
    record: &AepRecord,
    verifying_key: &VerifyingKey,
) -> Result<LegacySignatureProfile, VerificationError> {
    let sig_meta = record
        .signature
        .as_ref()
        .ok_or(VerificationError::MissingSignature)?;
    let sig_bytes = decode_signature(&sig_meta.sig)?;
    let sig_array: [u8; ed25519_dalek::Signature::BYTE_SIZE] = sig_bytes
        .try_into()
        .map_err(|_| VerificationError::InvalidSignatureLength)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    let mut unsigned = record.clone();
    unsigned.signature = None;

    // Profile 1 (primary): SHA-256(canonical bytes) — struct-order JSON.
    let hashed = canonical_bytes(&unsigned);
    if verifying_key.verify_strict(&hashed, &sig).is_ok() {
        return Ok(LegacySignatureProfile::CanonicalSha256);
    }

    // Profile 2 (compatibility): raw sorted-canonical bytes — the JS
    // emitter's message construction (serde Value = sorted BTreeMap, the
    // same bytes the JS canonicalizer produces).
    let value =
        serde_json::to_value(&unsigned).map_err(|_| VerificationError::SignatureMismatch)?;
    let raw = crate::dsse::canonical_json(&value).into_bytes();
    if verifying_key.verify_strict(&raw, &sig).is_ok() {
        return Ok(LegacySignatureProfile::RawCanonical);
    }

    Err(VerificationError::SignatureMismatch)
}

pub fn verify_record(
    record: &AepRecord,
    verifying_key: &VerifyingKey,
) -> Result<(), VerificationError> {
    let sig_meta = record
        .signature
        .as_ref()
        .ok_or(VerificationError::MissingSignature)?;
    let sig_bytes = decode_signature(&sig_meta.sig)?;
    let sig_array: [u8; ed25519_dalek::Signature::BYTE_SIZE] = sig_bytes
        .try_into()
        .map_err(|_| VerificationError::InvalidSignatureLength)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    let mut unsigned = record.clone();
    unsigned.signature = None;
    let canonical = canonical_bytes(&unsigned);
    verifying_key
        .verify_strict(&canonical, &sig)
        .map_err(|_| VerificationError::SignatureMismatch)
}

fn canonical_bytes(record: &AepRecord) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let json = serde_json::to_string(record).unwrap_or_default();
    hasher.update(json.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ActionEvidence, AepRecord};
    use crate::recording::RecordingMode;

    /// Helper: build a minimal `AepRecord` suitable for signing tests.
    fn test_record() -> AepRecord {
        AepRecord {
            schema_version: crate::evidence::AEP_SCHEMA_VERSION.into(),
            run_id: "test-run-42".into(),
            trace_id: Some("trace-abc".into()),
            session_id: None,
            dsse_envelope: None,
            user_id: None,
            authorized_by: None,
            authority_origin: None,
            identity_source: None,
            attribution_backing: None,
            run_attribution_backing_floor: None,
            run_attribution_backing_observed: None,
            run_side_effect_class_max: None,
            recording_mode: None,
            actions: vec![ActionEvidence {
                action_id: "act-1".into(),
                tool_name: "bash".into(),
                state_changing: true,
                precondition_digest: None,
                result_digest: Some("deadbeef".into()),
                timestamp_ms: 1_700_000_000_000,
                parent_action_id: None,
                causal_chain_id: None,
                recording_mode: RecordingMode::Full,
                capability_decision: None,
                mcp_header_risk: None,
                side_effect_class: None,
                extra: Default::default(),
            }],
            created_at_ms: 1_700_000_000_000,
            signature: None,
            extra: Default::default(),
            authorization_evidence_count: Default::default(),
        }
    }

    #[test]
    fn round_trip_sign_and_verify() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rng());
        let pubkey: VerifyingKey = key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        // Signature must have been populated.
        assert!(record.signature.is_some());
        let sig = record.signature.as_ref().unwrap();
        assert_eq!(sig.alg, "ed25519");
        assert_eq!(sig.key_id, "key-1");

        // Verify must succeed with the correct key.
        assert!(verify_record(&record, &pubkey).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rng());
        let pubkey: VerifyingKey = key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        // Tamper with a field after signing.
        record.run_id = "tampered-run".into();

        assert!(verify_record(&record, &pubkey).is_err());
    }

    #[test]
    fn tampered_action_fails_verification() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rng());
        let pubkey: VerifyingKey = key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        // Tamper inside an action element.
        record.actions[0].tool_name = "malicious-tool".into();

        assert!(verify_record(&record, &pubkey).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rng());
        let other_key = DalekSigningKey::generate(&mut rand::rng());
        let wrong_pubkey: VerifyingKey = other_key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        assert!(verify_record(&record, &wrong_pubkey).is_err());
    }

    #[test]
    fn profile_reported_for_our_own_signature() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rng());
        sign_record(&mut record, &key, "key-1");

        assert_eq!(
            verify_record_profile(&record, &key.verifying_key()).expect("verify"),
            LegacySignatureProfile::CanonicalSha256
        );
    }

    #[test]
    fn raw_canonical_profile_verifies_js_signed_records() {
        // The JS emitter signs the RAW SORTED-canonical JSON bytes (no
        // SHA-256 pre-hash). verify_record rejects that construction; the
        // compatibility profile accepts it and names it.
        use base64::Engine as _;

        let key = DalekSigningKey::from_bytes(&[9u8; 32]);
        let mut record = test_record();
        record.signature = None;
        let value = serde_json::to_value(&record).expect("serialize");
        let raw = crate::dsse::canonical_json(&value).into_bytes();
        let sig = key.sign(&raw);

        record.signature = Some(crate::evidence::AepSignature {
            alg: "ed25519".into(),
            key_id: "js-emitter".into(),
            sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        });

        // Strict single-profile verifier rejects the foreign construction.
        assert!(verify_record(&record, &key.verifying_key()).is_err());
        // Compatibility verifier accepts it and reports the profile.
        assert_eq!(
            verify_record_profile(&record, &key.verifying_key()).expect("verify"),
            LegacySignatureProfile::RawCanonical
        );
    }

    #[test]
    fn unsigned_record_fails_verification() {
        let record = test_record(); // signature is None
        let key = DalekSigningKey::generate(&mut rand::rng());
        let pubkey: VerifyingKey = key.verifying_key();

        assert_eq!(
            verify_record(&record, &pubkey),
            Err(VerificationError::MissingSignature)
        );
    }
}
