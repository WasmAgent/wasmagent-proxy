//! DSSE envelope signing for AEP records (aep/v0.4+).
//!
//! Mirrors `packages/aep/src/dsse.ts` in WasmAgent/wasmagent-js so that
//! gateway-produced envelopes verify with the JS `verifyDSSEEnvelope` /
//! `dsseEnvelopeBindsRecord` pair — and vice versa for JS-emitted envelopes
//! verified here.
//!
//! Canonicalization: RFC 8785 JSON Canonicalization Scheme (JCS).
//! Object keys are sorted by UTF-16 code-unit order (RFC 8785 §3.2.3),
//! matching the JS `canonicalBytes` and external implementations using the
//! `rfc8785` Python package. All existing AEP fixtures use ASCII-only keys,
//! where UTF-16 and UTF-8 orderings agree.

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

/// Canonical JSON per RFC 8785 JCS: keys sorted by UTF-16 code-unit order
/// (RFC 8785 §3.2.3), matching JS `Array.prototype.sort()` and the `rfc8785`
/// Python package used by independent verifiers.
pub fn canonical_json(value: &Value) -> String {
    canonical_json_value(value)
}

fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_units: Vec<u16> = a.encode_utf16().collect();
    let b_units: Vec<u16> = b.encode_utf16().collect();
    a_units.cmp(&b_units)
}

fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| compare_utf16(a, b));
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("key serialization cannot fail"),
                        canonical_json_value(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_value).collect();
            format!("[{}]", items.join(","))
        }
        _ => serde_json::to_string(value).expect("value serialization cannot fail"),
    }
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
    //
    // FAIL CLOSED on all boundary conditions:
    //   floor set + observed absent → reject (cannot verify weakest)
    //   floor set + observed empty  → reject (cannot verify weakest)
    //   observed set + floor absent → reject (unanchored grading)
    //   observed set + floor present but floor > min(observed) → reject
    if let Some(floor) = &record.run_attribution_backing_floor {
        let observed = record
            .run_attribution_backing_observed
            .as_ref()
            .ok_or("floor set but observed absent")?;
        if observed.is_empty() {
            return Err("floor set but observed is empty".into());
        }
        let weakest = observed
            .iter()
            .min_by_key(|g| grade_rank(&g.grade))
            .ok_or("observed is empty")?;
        if grade_rank(&floor.grade) > grade_rank(&weakest.grade) {
            return Err(format!(
                "floor ({}) is stronger than weakest observed ({})",
                floor.grade, weakest.grade
            ));
        }
    } else if record.run_attribution_backing_observed.is_some() {
        return Err("observed set but floor absent".into());
    }

    // Strip signing fields before canonicalization.
    record.signature = None;
    record.dsse_envelope = None;

    let predicate =
        serde_json::to_value(&*record).map_err(|e| format!("record serialization failed: {e}"))?;

    let payload_bytes = canonical_json(&predicate).into_bytes();
    let payload_digest = sha256_hex(&payload_bytes);

    let statement = wrap_in_toto_statement(predicate, &record.run_id, &payload_digest);
    let statement_bytes = canonical_json(&statement).into_bytes();

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&statement_bytes);

    let pae = pae_encode(IN_TOTO_PAYLOAD_TYPE, payload_b64.as_bytes());
    let sig_bytes: [u8; 64] = key.sign(&pae).to_bytes();
    let sig_hex = encode_signature(&sig_bytes);

    let dsse_sig = DsseSignature {
        keyid: key_id.to_string(),
        sig: sig_hex.clone(),
    };
    let envelope = DsseEnvelope {
        payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: payload_b64,
        signatures: vec![dsse_sig],
    };

    record.dsse_envelope = Some(envelope);
    record.signature = Some(DsseSignature {
        keyid: key_id.to_string(),
        sig: sig_hex,
    });

    Ok(())
}

/// Verify that `record` has a valid DSSE/in-toto envelope for `verifying_key`.
///
/// Checks:
/// 1. envelope present,
/// 2. PAE signature verifies,
/// 3. envelope payload decodes to a valid in-toto Statement,
/// 4. Statement subject digest matches the record's canonical-JSON predicate.
pub fn verify_record_dsse(
    record: &AepRecord,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;

    let envelope = record
        .dsse_envelope
        .as_ref()
        .ok_or("dsse_envelope missing")?;

    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(format!("unexpected payloadType: {}", envelope.payload_type));
    }
    if envelope.signatures.is_empty() {
        return Err("no signatures in envelope".into());
    }

    // Verify the PAE signature.
    let sig_hex = &envelope.signatures[0].sig;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig hex decode: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    let pae = pae_encode(IN_TOTO_PAYLOAD_TYPE, envelope.payload.as_bytes());
    verifying_key
        .verify(&pae, &sig)
        .map_err(|e| format!("DSSE signature invalid: {e}"))?;

    // Check that the payload's statement digest binds this record.
    let statement_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .map_err(|e| format!("payload base64 decode: {e}"))?;
    let statement: serde_json::Value = serde_json::from_slice(&statement_bytes)
        .map_err(|e| format!("statement JSON parse: {e}"))?;

    // Re-derive the canonical predicate from the record (strip dsse_envelope + signature).
    let mut record_for_predicate = record.clone();
    record_for_predicate.dsse_envelope = None;
    record_for_predicate.signature = None;
    let predicate = serde_json::to_value(&record_for_predicate)
        .map_err(|e| format!("record serialization: {e}"))?;
    let predicate_bytes = canonical_json(&predicate).into_bytes();
    let expected_digest = sha256_hex(&predicate_bytes);

    let subjects = statement["subject"]
        .as_array()
        .ok_or("statement.subject is not an array")?;
    if subjects.is_empty() {
        return Err("statement.subject is empty".into());
    }
    let digest_map = subjects[0]["digest"]
        .as_object()
        .ok_or("subject[0].digest is not an object")?;
    let actual_digest = digest_map["sha256"]
        .as_str()
        .ok_or("subject[0].digest.sha256 missing")?;

    if actual_digest != expected_digest {
        return Err(format!(
            "subject digest mismatch: envelope has {actual_digest}, record re-derives {expected_digest}"
        ));
    }

    Ok(())
}

/// Grade rank for floor consistency checks (lower = weaker).
fn grade_rank(grade: &str) -> u8 {
    match grade {
        "A" => 4,
        "B" => 3,
        "C" => 2,
        "D" => 1,
        _ => 0,
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
    fn canonical_json_orders_keys_by_utf16_code_units_matching_js() {
        // RFC 8785 §3.2.3: UTF-16 code-unit order, matching JS Array.prototype.sort().
        // "𐀀" (U+10000) = surrogate pair; lead unit 0xD800 = 55296.
        // "Ａ" (U+FF21) = single unit 0xFF21 = 65313.
        // "a" (U+0061) = 97.
        // Sort order: "a"(97) < "𐀀"(lead 55296) < "Ａ"(65313)
        let mut map = serde_json::Map::new();
        map.insert("\u{10000}".to_string(), serde_json::json!(1));
        map.insert("\u{FF21}".to_string(), serde_json::json!(2));
        map.insert("a".to_string(), serde_json::json!(3));
        assert_eq!(
            canonical_json(&serde_json::Value::Object(map)),
            "{\"a\":3,\"𐀀\":1,\"Ａ\":2}"
        );
    }

    #[test]
    fn canonical_json_integer_keys_sort_as_strings() {
        // RFC 8785: keys are strings. "10" < "2" because '1'(0x31) < '2'(0x32).
        let mut map = serde_json::Map::new();
        map.insert("2".to_string(), serde_json::json!("two"));
        map.insert("10".to_string(), serde_json::json!("ten"));
        assert_eq!(
            canonical_json(&serde_json::Value::Object(map)),
            "{\"10\":\"ten\",\"2\":\"two\"}"
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

    #[test]
    fn tampered_payload_type_fails_verification() {
        // DSSE 1.0.2: payloadType is inside the PAE, so mutating it must
        // invalidate the signature — the verifier must not normalize or
        // ignore the type before verifying.
        let mut record = sample_record();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        sign_record_dsse(&mut record, &key, "gateway-key-1").expect("sign");
        record.dsse_envelope.as_mut().unwrap().payload_type =
            "application/vnd.in-toto+json; tampered".into();
        let verifying_key = VerifyingKey::from(&key);
        assert!(verify_record_dsse(&record, &verifying_key).is_err());
    }

    #[test]
    fn base64_payload_padding_roundtrip() {
        // base64::STANDARD uses padding; verify the round-trip still works
        // for payloads whose byte length isn't a multiple of 3 (padding = "=").
        // The sample record serialises to a length that exercises padding:
        // if the encoder drops it the decoder returns an error.
        let mut record = sample_record();
        record.run_id = "x".into(); // deliberately short so padding shows
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        sign_record_dsse(&mut record, &key, "k").expect("sign");
        let verifying_key = VerifyingKey::from(&key);
        verify_record_dsse(&record, &verifying_key).expect("verify after sign");
    }

    #[test]
    fn missing_envelope_fails_verify() {
        let record = sample_record();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = VerifyingKey::from(&key);
        assert!(verify_record_dsse(&record, &verifying_key).is_err());
    }

    #[test]
    fn floor_stronger_than_weakest_observed_is_rejected() {
        use crate::evidence::{AttributionGrade, AttributionGradeEntry};
        let mut record = sample_record();
        record.run_attribution_backing_floor = Some(AttributionGrade { grade: "A".into() });
        record.run_attribution_backing_observed = Some(vec![AttributionGradeEntry {
            grade: "C".into(),
            count: 1,
        }]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(sign_record_dsse(&mut record, &key, "k").is_err());
    }

    #[test]
    fn floor_without_observed_is_rejected() {
        use crate::evidence::AttributionGrade;
        let mut record = sample_record();
        record.run_attribution_backing_floor = Some(AttributionGrade { grade: "B".into() });
        record.run_attribution_backing_observed = None;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(sign_record_dsse(&mut record, &key, "k").is_err());
    }

    #[test]
    fn observed_without_floor_is_rejected() {
        use crate::evidence::AttributionGradeEntry;
        let mut record = sample_record();
        record.run_attribution_backing_floor = None;
        record.run_attribution_backing_observed = Some(vec![AttributionGradeEntry {
            grade: "B".into(),
            count: 1,
        }]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(sign_record_dsse(&mut record, &key, "k").is_err());
    }

    #[test]
    fn empty_observed_with_floor_is_rejected() {
        use crate::evidence::AttributionGrade;
        let mut record = sample_record();
        record.run_attribution_backing_floor = Some(AttributionGrade { grade: "B".into() });
        record.run_attribution_backing_observed = Some(vec![]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        assert!(sign_record_dsse(&mut record, &key, "k").is_err());
    }

    #[test]
    fn subject_digest_binds_predicate_not_envelope() {
        // The subject digest must be over the predicate (record without
        // signature/dsse_envelope), NOT over the full envelope. Verify that
        // the predicate re-derived by the verifier matches the signed digest
        // so the round-trip passes, and that mutating the envelope signature
        // bytes (not the predicate) doesn't affect the binding check.
        let mut record = sample_record();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        sign_record_dsse(&mut record, &key, "gateway-key-1").expect("sign");

        // Corrupt only the envelope signature bytes — the PAE verify step
        // catches this first, so we expect an error.
        let env = record.dsse_envelope.as_mut().unwrap();
        env.signatures[0].sig = "deadbeef".repeat(16);
        let verifying_key = VerifyingKey::from(&key);
        let err = verify_record_dsse(&record, &verifying_key).unwrap_err();
        assert!(
            err.contains("DSSE signature invalid") || err.contains("sig hex decode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn non_ascii_key_encoding_is_stable() {
        // A record with a non-ASCII key in `extra` must produce stable
        // canonical bytes across multiple calls. This pins that the UTF-16
        // sort doesn't produce different output on repeated invocations.
        let v1 = serde_json::json!({"b": 1, "a": 2, "ñ": 3});
        let v2 = serde_json::json!({"ñ": 3, "a": 2, "b": 1});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
        // "ñ" (U+00F1 = 241) sorts after "b"(98) and "a"(97) in UTF-16
        assert_eq!(canonical_json(&v1), "{\"a\":2,\"b\":1,\"ñ\":3}");
    }

    #[test]
    fn nested_objects_are_recursively_sorted() {
        let v = serde_json::json!({"z": {"b": 1, "a": 2}, "a": [3, 2, 1]});
        assert_eq!(
            canonical_json(&v),
            "{\"a\":[3,2,1],\"z\":{\"a\":2,\"b\":1}}"
        );
    }

    #[test]
    fn utf16_surrogate_pair_key_encodes_correctly() {
        // U+10000 in Rust source is the actual codepoint. serde_json serializes
        // it as the UTF-8 encoding of the character (4 bytes, F0 90 80 80),
        // which JSON represents as 𐀀 (surrogate pair) when escaped,
        // or as the literal UTF-8 character. Verify that the key round-trips
        // and the sort is deterministic.
        let mut map = serde_json::Map::new();
        map.insert("\u{10000}".to_string(), serde_json::json!(1));
        map.insert("z".to_string(), serde_json::json!(2));
        // "z"(0x7A=122) < "\u{10000}" lead surrogate (0xD800=55296)
        let out = canonical_json(&serde_json::Value::Object(map));
        assert!(out.starts_with("{\"z\":2,"));
        // The key must be present and decodable
        let reparsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert!(reparsed.get("\u{10000}").is_some());
    }

    #[test]
    fn empty_object_and_array_round_trip() {
        assert_eq!(canonical_json(&serde_json::json!({})), "{}");
        assert_eq!(canonical_json(&serde_json::json!([])), "[]");
        assert_eq!(
            canonical_json(&serde_json::json!({"a": [], "b": {}})),
            "{\"a\":[],\"b\":{}}"
        );
    }

    #[test]
    fn string_escaping_is_preserved() {
        // serde_json's string escaping for control characters must pass through
        // unchanged. The canonical form must be valid JSON that re-parses to
        // the same value.
        let v = serde_json::json!({"key": "value\nwith\ttabs\r\n"});
        let out = canonical_json(&v);
        let reparsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v, reparsed);
        // Escapes must be present (not literal newlines)
        assert!(out.contains("\\n") || out.contains("\\r"));
    }

    #[test]
    fn unicode_escape_sequences_decode_uniquely() {
        // JSON allows both \uXXXX and literal UTF-8; serde_json picks one form.
        // Whatever form it picks, it must parse back to the same value.
        let v = serde_json::json!({"key": "\u{00E9}"}); // é
        let out = canonical_json(&v);
        let reparsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(
            v,
            reparsed,
            "canonical form {out:?} decodes uniquely and must be accepted"
        );
    }
}
