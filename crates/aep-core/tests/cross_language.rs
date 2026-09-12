//! Cross-language conformance: records emitted by the TypeScript emitter
//! (WasmAgent/wasmagent-js, packages/aep) must verify with the Rust DSSE
//! verifier. The fixtures were generated with the emitter's real signing
//! path — the same 32-byte seed both sides derive their Ed25519 key from
//! (RFC 8032: public key = scalar-from-seed × basepoint, identical in
//! @noble/ed25519 and ed25519-dalek).

use aep_core::{verify_record_dsse, AepRecord, SigningKey};
use base64::Engine as _;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    path
}

fn load_fixture(name: &str) -> AepRecord {
    let json = std::fs::read_to_string(fixture_path(name)).expect("read fixture");
    serde_json::from_str(&json).expect("deserialize fixture")
}

/// TEST_SEED from packages/aep/src/index.test.ts: "deadbeef" × 8.
fn js_test_seed() -> [u8; 32] {
    [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
        0xbe, 0xef,
    ]
}

#[test]
fn js_emitted_dsse_record_verifies_with_the_same_seed() {
    let key = SigningKey::from_bytes(&js_test_seed());
    let record = load_fixture("wasmagent-js-dsse.json");

    // The record is a v0.5 attribution-graded run, DSSE-signed by the JS
    // emitter (payloadType application/vnd.in-toto+json). The Rust verifier
    // must accept the PAE signature and the predicate/subject binding.
    verify_record_dsse(&record, &key.verifying_key())
        .expect("cross-language DSSE verification failed");
}

#[test]
fn tampered_js_record_fails_binding() {
    let key = SigningKey::from_bytes(&js_test_seed());
    let mut record = load_fixture("wasmagent-js-dsse.json");
    record.user_id = Some("user-attacker".into());
    assert!(verify_record_dsse(&record, &key.verifying_key()).is_err());
}

// The historical legacy signing profile (Ed25519 over SHA-256(struct-order
// JSON)) was REMOVED in the clean cut — see signing.rs. Its specimens live
// in wasmagent-protocol `conformance/aep/historical/` as evidence only; no
// verifier supports them, so there is no legacy test here anymore.

/// Tamper matrix: every mutation of a signed cross-language record must fail
/// verification. Each case mutates exactly one thing about the JS-emitted
/// fixture; the DSSE PAE signature and the predicate/subject binding must
/// reject all of them.
mod tamper_matrix {
    use super::*;

    fn signed_fixture() -> (AepRecord, ed25519_dalek::VerifyingKey) {
        let key = SigningKey::from_bytes(&js_test_seed());
        (load_fixture("wasmagent-js-dsse.json"), key.verifying_key())
    }

    #[test]
    fn tampered_run_id_fails() {
        let (mut record, vk) = signed_fixture();
        record.run_id = "run-impersonated".into();
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_actions_fail() {
        let (mut record, vk) = signed_fixture();
        record.actions[0].tool_name = "POST /tampered".into();
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_created_at_fails() {
        let (mut record, vk) = signed_fixture();
        record.created_at_ms = record.created_at_ms.wrapping_add(1);
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_attribution_floor_fails() {
        let (mut record, vk) = signed_fixture();
        // Round the floor up: the bytes no longer match what was signed, and
        // a verifier-side semantic check would reject it independently.
        record.run_attribution_backing_floor = Some("qualified_signature".into());
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_observed_grades_fail() {
        let (mut record, vk) = signed_fixture();
        record
            .run_attribution_backing_observed
            .as_mut()
            .expect("fixture carries observed grades")
            .push("unknown".into());
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_payload_fails_pae_signature() {
        let (mut record, vk) = signed_fixture();
        let envelope = record.dsse_envelope.as_mut().expect("envelope");
        let mut statement: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(envelope.payload.as_bytes())
                .expect("payload base64"),
        )
        .expect("payload json");
        statement["predicate"]["run_id"] = serde_json::json!("run-impersonated");
        envelope.payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).expect("re-serialize"));
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn tampered_subject_digest_fails_pae_signature() {
        let (mut record, vk) = signed_fixture();
        let envelope = record.dsse_envelope.as_mut().expect("envelope");
        let mut statement: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(envelope.payload.as_bytes())
                .expect("payload base64"),
        )
        .expect("payload json");
        statement["subject"][0]["digest"]["sha256"] = serde_json::json!("0".repeat(64));
        envelope.payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).expect("re-serialize"));
        assert!(verify_record_dsse(&record, &vk).is_err());
    }

    #[test]
    fn wrong_public_key_fails() {
        let (record, _) = signed_fixture();
        let attacker = SigningKey::from_bytes(&[0x42u8; 32]);
        assert!(verify_record_dsse(&record, &attacker.verifying_key()).is_err());
    }

    #[test]
    fn empty_signature_list_fails() {
        let (mut record, vk) = signed_fixture();
        record
            .dsse_envelope
            .as_mut()
            .expect("envelope")
            .signatures
            .clear();
        assert!(verify_record_dsse(&record, &vk).is_err());
    }
}
