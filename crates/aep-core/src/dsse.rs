//! DSSE envelope signing for AEP records (aep/v0.4+).
//!
//! Mirrors `packages/aep/src/dsse.ts` in WasmAgent/wasmagent-js so that
//! gateway-produced envelopes verify with the JS `verifyDSSEEnvelope` /
//! `dsseEnvelopeBindsRecord` pair — and vice versa for JS-emitted envelopes
//! verified here.
//!
//! Canonicalization: sorted-key compact JSON. `serde_json` serializes object
//! values through a BTreeMap (sorted) unless its `preserve_order` feature is
//! enabled, which matches the JS `canonicalBytes` sorted-key rule for the
//! string/number/array/object shapes an AEP record contains. (See the
//! canonicalization notes in the JS module: this is sorted-key JSON.stringify,
//! not RFC 8785/JCS.)

use base64::Engine as _;
use serde_json::{json, Value};

use crate::evidence::{AepRecord, DsseEnvelope, DsseSignature};
use crate::signing::encode_signature;

pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const AEP_PREDICATE_TYPE: &str = "https://wasmagent.dev/attestations/aep/v0.4";

/// DSSE Pre-Authentication Encoding:
/// `PAE(type, payload) = "DSSEv1" || SP || LEN(type) || SP || type || SP || LEN(payload) || SP || payload`
/// with `LEN(s)` the decimal ASCII representation of the byte length.
/// Byte-for-byte identical to the JS `paeEncode`.
pub fn pae_encode(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 24);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(payload_type.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(payload);
    out
}

/// Sorted-key compact JSON — the form the JS side re-derives via its
/// `sortedReplacer`, so digests computed on either side agree.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("Value serialization cannot fail")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// in-toto Statement wrapper — same shape as the JS `wrapInTotoStatement`.
fn wrap_in_toto_statement(predicate: Value, run_id: &str, payload_digest_hex: &str) -> Value {
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": format!("urn:wasmagent:run:{run_id}"),
            "digest": { "sha256": payload_digest_hex },
        }],
        "predicateType": AEP_PREDICATE_TYPE,
        "predicate": predicate,
    })
}

/// Sign `record` as a DSSE/in-toto envelope, mirroring the JS emit() DSSE
/// path:
///
/// 1. strip `signature` and `dsse_envelope` from the record,
/// 2. stamp `schema_version` (already aep/v0.5 for the gateway),
/// 3. canonical JSON → `payload_digest` (sha256 hex),
/// 4. wrap the predicate in an in-toto Statement whose subject binds the digest,
/// 5. payload = base64(statement JSON); sign `PAE(payloadType, payload)`,
/// 6. attach `dsse_envelope` and mirror the envelope signature into the
///    legacy `signature` field for backward compatibility.
///
/// The existing [`crate::sign_record`] legacy signature is replaced by the
/// PAE signature exactly as the JS emitter does.
pub fn sign_record_dsse(
    record: &mut AepRecord,
    key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> Result<(), serde_json::Error> {
    use ed25519_dalek::Signer;

    let run_id = record.run_id.clone();
    let mut unsigned = serde_json::to_value(&*record)?;
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("signature");
        obj.remove("dsse_envelope");
    }

    let predicate_json = canonical_json(&unsigned);
    let payload_digest = sha256_hex(predicate_json.as_bytes());

    let statement = wrap_in_toto_statement(unsigned, &run_id, &payload_digest);
    let statement_json = canonical_json(&statement);
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(statement_json.as_bytes());

    let pae = pae_encode(IN_TOTO_PAYLOAD_TYPE, payload_b64.as_bytes());
    let sig = key.sign(&pae);
    let sig_b64 = encode_signature(&sig.to_bytes());

    record.dsse_envelope = Some(DsseEnvelope {
        payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: payload_b64,
        signatures: vec![DsseSignature {
            keyid: key_id.to_string(),
            sig: sig_b64.clone(),
        }],
    });
    if let Some(sig_block) = record.signature.as_mut() {
        sig_block.key_id = key_id.to_string();
        sig_block.sig = sig_b64;
    } else {
        record.signature = Some(crate::evidence::AepSignature {
            alg: "ed25519".into(),
            key_id: key_id.to_string(),
            sig: sig_b64,
        });
    }
    Ok(())
}

/// Verify a DSSE envelope against a public key: PAE signature check plus the
/// payload↔record binding (predicate equals the record minus `signature` /
/// `dsse_envelope`; subject digest binds the canonical predicate bytes).
pub fn verify_record_dsse(
    record: &AepRecord,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), &'static str> {
    use ed25519_dalek::Verifier;

    let envelope = record.dsse_envelope.as_ref().ok_or("no dsse envelope")?;
    let envelope_sig = envelope
        .signatures
        .first()
        .ok_or("dsse envelope has no signatures")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope_sig.sig.as_bytes())
        .map_err(|_| "dsse signature is not valid base64")?;
    let sig_array: [u8; ed25519_dalek::Signature::BYTE_SIZE] = sig_bytes
        .try_into()
        .map_err(|_| "dsse signature has the wrong length")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    // PAE covers the base64 payload STRING bytes (not the decoded statement) —
    // matching the JS verifier's paeEncode(payloadType, payloadB64) input.
    let pae = pae_encode(&envelope.payload_type, envelope.payload.as_bytes());
    verifying_key
        .verify(&pae, &sig)
        .map_err(|_| "dsse PAE signature verification failed")?;

    let statement: Value = serde_json::from_slice(&payload_bytes_decoded(envelope)?)
        .map_err(|_| "dsse payload is not valid JSON")?;
    if statement.get("predicateType").and_then(|v| v.as_str()) != Some(AEP_PREDICATE_TYPE) {
        return Err("dsse predicateType mismatch");
    }

    let mut unsigned = serde_json::to_value(record).map_err(|_| "record serialization")?;
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("signature");
        obj.remove("dsse_envelope");
    }

    let subject_digest = statement
        .get("subject")
        .and_then(|s| s.get(0))
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.get("sha256"))
        .and_then(|v| v.as_str())
        .ok_or("dsse statement subject has no sha256 digest")?;
    if subject_digest != sha256_hex(canonical_json(&unsigned).as_bytes()) {
        return Err("dsse subject digest does not bind the record");
    }
    if statement.get("predicate").map(|p| p) != Some(&unsigned) {
        return Err("dsse predicate does not match the record");
    }
    Ok(())
}

fn payload_bytes_decoded(envelope: &DsseEnvelope) -> Result<Vec<u8>, &'static str> {
    base64::engine::general_purpose::STANDARD
        .decode(envelope.payload.as_bytes())
        .map_err(|_| "dsse payload is not valid base64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ActionEvidence, AepRecord};
    use crate::recording::RecordingMode;
    use ed25519_dalek::VerifyingKey;

    fn sample_record() -> AepRecord {
        AepRecord {
            schema_version: crate::evidence::AEP_SCHEMA_VERSION.into(),
            run_id: "run-dsse-rs-001".into(),
            trace_id: Some("trace-dsse".into()),
            session_id: None,
            dsse_envelope: None,
            user_id: Some("user-dana@acme.example".into()),
            authorized_by: None,
            authority_origin: Some("subject_consented".into()),
            identity_source: None,
            attribution_backing: Some("principal_key_signed".into()),
            run_attribution_backing_floor: None,
            run_attribution_backing_observed: None,
            run_side_effect_class_max: Some("network-egress".into()),
            recording_mode: Some("full".into()),
            actions: vec![ActionEvidence {
                action_id: "act-1".into(),
                tool_name: "POST /mcp".into(),
                state_changing: true,
                precondition_digest: None,
                result_digest: Some("sha256:post".into()),
                timestamp_ms: 1_700_000_000_000,
                parent_action_id: None,
                causal_chain_id: None,
                recording_mode: RecordingMode::Full,
                capability_decision: None,
                mcp_header_risk: None,
                side_effect_class: Some("network-egress".into()),
            }],
            created_at_ms: 1_700_000_000_000,
            signature: None,
        }
    }

    #[test]
    fn pae_matches_dsse_spec_layout() {
        // "DSSEv1" || SP || LEN(type) || SP || type || SP || LEN(payload) || SP || payload
        let pae = pae_encode("application/vnd.in-toto+json", b"hello");
        let expected = b"DSSEv1 28 application/vnd.in-toto+json 5 hello";
        assert_eq!(pae, expected);
    }

    #[test]
    fn sign_and_verify_dsse_round_trip() {
        let mut record = sample_record();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        sign_record_dsse(&mut record, &key, "gateway-key-1").expect("sign");

        let envelope = record.dsse_envelope.as_ref().expect("envelope attached");
        assert_eq!(envelope.payload_type, IN_TOTO_PAYLOAD_TYPE);
        assert_eq!(
            record.signature.as_ref().unwrap().sig,
            envelope.signatures[0].sig
        );

        let verifying_key = VerifyingKey::from(&key);
        verify_record_dsse(&record, &verifying_key).expect("dsse verification");
    }

    #[test]
    fn tampered_record_fails_dsse_binding() {
        let mut record = sample_record();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        sign_record_dsse(&mut record, &key, "gateway-key-1").expect("sign");

        record.user_id = Some("user-attacker".into());
        let verifying_key = VerifyingKey::from(&key);
        assert!(verify_record_dsse(&record, &verifying_key).is_err());
    }
}
