use crate::evidence::AepRecord;
use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub use ed25519_dalek::SigningKey;

pub fn sign_record(record: &mut AepRecord, key: &DalekSigningKey, key_id: &str) {
    let canonical = canonical_bytes(record);
    let sig = key.sign(&canonical);
    record.signature = Some(crate::evidence::AepSignature {
        alg: "ed25519".into(),
        key_id: key_id.into(),
        sig: hex::encode(sig.to_bytes()),
    });
}

pub fn verify_record(record: &AepRecord, verifying_key: &VerifyingKey) -> bool {
    let Some(sig_meta) = &record.signature else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(&sig_meta.sig) else {
        return false;
    };
    let Ok(sig_array) = sig_bytes.try_into() else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    let mut unsigned = record.clone();
    unsigned.signature = None;
    let canonical = canonical_bytes(&unsigned);
    verifying_key.verify_strict(&canonical, &sig).is_ok()
}

fn canonical_bytes(record: &AepRecord) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let json = serde_json::to_string(record).unwrap_or_default();
    hasher.update(json.as_bytes());
    hasher.finalize().to_vec()
}
