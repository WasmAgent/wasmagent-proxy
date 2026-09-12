//! Cross-language conformance: records emitted by the TypeScript emitter
//! (WasmAgent/wasmagent-js, packages/aep) must verify with the Rust DSSE
//! verifier. The fixtures were generated with the emitter's real signing
//! path — the same 32-byte seed both sides derive their Ed25519 key from
//! (RFC 8032: public key = scalar-from-seed × basepoint, identical in
//! @noble/ed25519 and ed25519-dalek).

use aep_core::{verify_record, verify_record_dsse, AepRecord, SigningKey};
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

#[test]
fn legacy_hex_signature_still_verifies() {
    // Pre-aep/v0.5 gateway releases emitted hex-encoded signatures. The
    // verifier must keep accepting them alongside the current base64 form.
    let seed = [7u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let mut record = load_fixture("wasmagent-js-dsse.json");
    record.dsse_envelope = None;
    aep_core::sign_record(&mut record, &key, "legacy-key");

    // Re-encode the base64 signature as 128-char lowercase hex the legacy way.
    let sig_b64 = record.signature.as_ref().expect("signature").sig.clone();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.as_bytes())
        .expect("base64 sig");
    record.signature.as_mut().expect("signature").sig = hex::encode(decoded);

    verify_record(&record, &key.verifying_key()).expect("legacy hex signature must verify");
}
