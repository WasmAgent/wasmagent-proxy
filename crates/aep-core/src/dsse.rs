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
) -> Result<(), String> {
    use ed25519_dalek::Signer;

    // Floor consistency (aep/v0.5): the floor must be the weakest observed
    // grade — a stronger floor masks weak authorizations behind a
    // strong-looking record (the exact attack the floor exists to expose).
    if let (Some(floor), Some(observed)) = (
        &record.run_attribution_backing_floor,
        &record.run_attribution_backing_observed,
    ) {
        if !observed.is_empty() {
            const ORDER: [&str; 4] = [
                "unknown",
                "operator_asserted",
                "principal_key_signed",
                "qualified_signature",
            ];
            let rank = |g: &str| ORDER.iter().position(|o| *o == g);
            if rank(floor).is_some() && observed.iter().all(|g| rank(g).is_some()) {
                let floor_rank = rank(floor).unwrap();
                let weakest = observed.iter().map(|g| rank(g).unwrap()).min().unwrap();
                if floor_rank != weakest {
                    return Err(
                        "attribution: run_attribution_backing_floor is not the weakest \
                         grade in run_attribution_backing_observed"
                            .to_string(),
                    );
                }
            }
        }
    }

    let run_id = record.run_id.clone();
    let mut unsigned =
        serde_json::to_value(&*record).map_err(|e| format!("serialize record: {e}"))?;
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
    // AEP signature-count policy: exactly one signature. Current emitters
    // produce one; multisig/threshold semantics are deliberately undefined.
    if envelope.signatures.len() != 1 {
        return Err("dsse envelope must carry exactly one signature");
    }
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

    // AEP payload type: the envelope wraps an in-toto statement.
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err("dsse payload type mismatch");
    }

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
    if statement.get("_type").and_then(|v| v.as_str()) != Some("https://in-toto.io/Statement/v1") {
        return Err("in-toto statement _type mismatch");
    }

    let mut unsigned = serde_json::to_value(record).map_err(|_| "record serialization")?;
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("signature");
        obj.remove("dsse_envelope");
    }

    let subjects = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .ok_or("dsse statement has no subject array")?;
    if subjects.len() != 1 {
        return Err("dsse statement must carry exactly one subject");
    }
    let subject = &subjects[0];
    let subject_digest = subject
        .get("digest")
        .and_then(|d| d.get("sha256"))
        .and_then(|v| v.as_str())
        .ok_or("dsse statement subject has no sha256 digest")?;
    if subject_digest != sha256_hex(canonical_json(&unsigned).as_bytes()) {
        return Err("dsse subject digest does not bind the record");
    }
    // Exact canonical subject name — binds the attestation to this run.
    let subject_name = subject
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("dsse statement subject has no name")?;
    if subject_name != format!("urn:wasmagent:run:{}", record.run_id) {
        return Err("dsse subject name does not match the run_id");
    }
    if statement.get("predicate") != Some(&unsigned) {
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
mod adversarial_tests {
    use super::*;
    use crate::evidence::ActionEvidence;
    use crate::recording::RecordingMode;
    use ed25519_dalek::VerifyingKey;

    fn record_with(run_id: &str, tool: &str) -> AepRecord {
        AepRecord {
            schema_version: crate::evidence::AEP_SCHEMA_VERSION.into(),
            run_id: run_id.into(),
            trace_id: None,
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
                action_id: "a-1".into(),
                tool_name: tool.into(),
                state_changing: true,
                precondition_digest: None,
                result_digest: None,
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
    fn floor_weaker_than_observed_is_rejected() {
        let mut record = record_with("run-floor-lie", "bash");
        record.run_attribution_backing_observed = Some(vec!["qualified_signature".into()]);
        record.run_attribution_backing_floor = Some("operator_asserted".into());
        let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let err = sign_record_dsse(&mut record, &key, "k").unwrap_err();
        assert!(err.contains("weakest"), "err: {err}");
    }

    #[test]
    fn floor_equal_to_weakest_passes() {
        let mut record = record_with("run-floor-ok", "bash");
        record.run_attribution_backing_observed = Some(vec![
            "operator_asserted".into(),
            "qualified_signature".into(),
        ]);
        record.run_attribution_backing_floor = Some("operator_asserted".into());
        let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        assert!(sign_record_dsse(&mut record, &key, "k").is_ok());
    }

    #[test]
    fn signature_from_another_record_fails_subject_binding() {
        // Envelope lifting: sign record A, attach A's envelope to a record
        // with a different run_id — the subject binding must reject it.
        let key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let mut a = record_with("run-victim", "bash");
        sign_record_dsse(&mut a, &key, "k").expect("sign a");

        let b = record_with("run-other", "bash");
        let mut lifted = b;
        lifted.dsse_envelope = a.dsse_envelope.clone();
        let vkey = VerifyingKey::from(&key);
        assert!(verify_record_dsse(&lifted, &vkey).is_err());
    }

    #[test]
    fn unicode_run_id_round_trips() {
        // CJK + emoji in run_id: both sides serialize raw UTF-8 (no escapes)
        // so the canonical bytes and the DSSE binding must agree.
        let mut record = record_with("run-健壮性-🛡", "bash");
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        sign_record_dsse(&mut record, &key, "k").expect("sign unicode run");
        verify_record_dsse(&record, &key.verifying_key()).expect("unicode verify");
    }

    #[test]
    fn large_payload_signs_and_verifies() {
        // Stress: a wide record (many actions) still signs/verifies.
        let mut record = record_with("run-large", "bash");
        for i in 0..2000 {
            record.actions.push(ActionEvidence {
                action_id: format!("a-{i}"),
                tool_name: format!("tool-{}", i % 7),
                state_changing: i % 3 == 0,
                precondition_digest: None,
                result_digest: None,
                timestamp_ms: 1_700_000_000_000 + i as u64,
                parent_action_id: None,
                causal_chain_id: None,
                recording_mode: RecordingMode::Validation,
                capability_decision: None,
                mcp_header_risk: None,
                side_effect_class: None,
                extra: Default::default(),
            });
        }
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        sign_record_dsse(&mut record, &key, "k").expect("sign large");
        verify_record_dsse(&record, &key.verifying_key()).expect("verify large");
    }
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
                extra: Default::default(),
            }],
            created_at_ms: 1_700_000_000_000,
            signature: None,
            extra: Default::default(),
            authorization_evidence_count: Default::default(),
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
    fn canonical_json_orders_keys_by_utf8_bytes_matching_js() {
        // Same pin as wasmagent-js `canonical.boundary.test.ts`: keys sort by
        // UTF-8 byte order ("a" 0x61 < "Ａ" EF BC A1 < "𐀀" F0 90 80 80), and by
        // BTreeMap order rather than insertion order — if `preserve_order`
        // were ever enabled transitively, this assertion fails loudly.
        let mut map = serde_json::Map::new();
        map.insert("\u{10000}".to_string(), serde_json::json!(1));
        map.insert("\u{FF21}".to_string(), serde_json::json!(2));
        map.insert("a".to_string(), serde_json::json!(3));
        assert_eq!(
            canonical_json(&serde_json::Value::Object(map)),
            "{\"a\":3,\"Ａ\":2,\"𐀀\":1}"
        );
    }

    #[test]
    fn canonical_json_keeps_proto_key() {
        // serde BTreeMap treats "__proto__" as an ordinary string key; the JS
        // canonicalizer must (and does, via defineProperty) keep it too.
        let mut map = serde_json::Map::new();
        map.insert("__proto__".to_string(), serde_json::json!({"x":1}));
        map.insert("run_id".to_string(), serde_json::json!("r1"));
        assert_eq!(
            canonical_json(&serde_json::Value::Object(map)),
            "{\"__proto__\":{\"x\":1},\"run_id\":\"r1\"}"
        );
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
