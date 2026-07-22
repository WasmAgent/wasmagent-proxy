use crate::evidence::AepRecord;
use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub use ed25519_dalek::SigningKey;

/// Errors that can occur during signature verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The record has no signature attached.
    MissingSignature,
    /// The signature hex string could not be decoded.
    MalformedSignatureHex,
    /// The decoded signature bytes are not the expected length.
    InvalidSignatureLength,
    /// The cryptographic verification failed (wrong key or tampered data).
    SignatureMismatch,
}

pub fn sign_record(record: &mut AepRecord, key: &DalekSigningKey, key_id: &str) {
    let canonical = canonical_bytes(record);
    let sig = key.sign(&canonical);
    record.signature = Some(crate::evidence::AepSignature {
        alg: "ed25519".into(),
        key_id: key_id.into(),
        sig: hex::encode(sig.to_bytes()),
    });
}

pub fn verify_record(record: &AepRecord, verifying_key: &VerifyingKey) -> Result<(), VerificationError> {
    let sig_meta = record
        .signature
        .as_ref()
        .ok_or(VerificationError::MissingSignature)?;
    let sig_bytes =
        hex::decode(&sig_meta.sig).map_err(|_| VerificationError::MalformedSignatureHex)?;
    let sig_array: [u8; ed25519_dalek::Signature::BYTE_SIZE] =
        sig_bytes
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
            schema_version: "aep/0.1".into(),
            run_id: "test-run-42".into(),
            trace_id: Some("trace-abc".into()),
            session_id: None,
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
            }],
            created_at_ms: 1_700_000_000_000,
            signature: None,
        }
    }

    #[test]
    fn round_trip_sign_and_verify() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
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
        let key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey: VerifyingKey = key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        // Tamper with a field after signing.
        record.run_id = "tampered-run".into();

        assert!(verify_record(&record, &pubkey).is_err());
    }

    #[test]
    fn tampered_action_fails_verification() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey: VerifyingKey = key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        // Tamper inside an action element.
        record.actions[0].tool_name = "malicious-tool".into();

        assert!(verify_record(&record, &pubkey).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut record = test_record();
        let key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let other_key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_pubkey: VerifyingKey = other_key.verifying_key();

        sign_record(&mut record, &key, "key-1");

        assert!(verify_record(&record, &wrong_pubkey).is_err());
    }

    #[test]
    fn unsigned_record_fails_verification() {
        let record = test_record(); // signature is None
        let key = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey: VerifyingKey = key.verifying_key();

        assert_eq!(
            verify_record(&record, &pubkey),
            Err(VerificationError::MissingSignature)
        );
    }
}
