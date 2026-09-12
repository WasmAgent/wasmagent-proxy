//! Protocol central corpus adapter — executes the DSSE authenticity and
//! chain verdicts declared in wasmagent-protocol
//! `conformance/aep/manifest.json` with THIS crate's verifier, so the
//! shared corpus constrains the Rust implementation exactly as it
//! constrains JS.
//!
//! Set `AEP_PROTOCOL_CORPUS` to the corpus directory (the CI workflow
//! checks out wasmagent-protocol). Without the variable the tests are
//! skipped so local `cargo test` stays hermetic.

use aep_core::{verify_record_dsse, AepRecord};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn corpus_dir() -> Option<PathBuf> {
    let dir = std::env::var("AEP_PROTOCOL_CORPUS").ok()?;
    let path = PathBuf::from(dir);
    if path.join("manifest.json").exists() {
        Some(path)
    } else {
        None
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex byte"))
        .collect()
}

fn verifying_key_from_hex(hex: &str) -> VerifyingKey {
    // The corpus key files hold 32-byte ED25519 PUBLIC keys.
    let bytes: [u8; 32] = hex_to_bytes(hex).try_into().expect("32-byte public key");
    VerifyingKey::from_bytes(&bytes).expect("valid public key")
}

fn chain_status(records: &[AepRecord]) -> &'static str {
    // Mirrors the JS verifyAEPChain status semantics.
    if records.is_empty() {
        return "not-present";
    }
    if records.len() == 1 {
        // A JSON null prev_record_hash means "no link", not "unresolved anchor".
        let has_link = records[0]
            .extra
            .get("prev_record_hash")
            .and_then(|v| v.as_str())
            .is_some();
        return if has_link { "orphaned" } else { "not-present" };
    }
    let mut linked = 0;
    let mut missing = 0;
    for i in 1..records.len() {
        let current = &records[i];
        let prev = &records[i - 1];
        match current
            .extra
            .get("prev_record_hash")
            .and_then(|v| v.as_str())
        {
            None => missing += 1,
            Some(claimed) => {
                let mut unsigned = prev.clone();
                unsigned.signature = None;
                unsigned.dsse_envelope = None;
                // Sorted-key canonical JSON — the same bytes the JS
                // canonicalizer and the DSSE subject digest use.
                let value = serde_json::to_value(&unsigned).expect("record serialization");
                let sorted = aep_core::dsse::canonical_json(&value);
                let mut hasher = Sha256::new();
                hasher.update(sorted.as_bytes());
                let expected = hex::encode(hasher.finalize());
                if *claimed != expected {
                    return "broken";
                }
                linked += 1;
            }
        }
    }
    if linked == 0 {
        return "not-present";
    }
    if missing > 0 {
        return "partial";
    }
    // Truncated prefix: first record claims a predecessor outside this slice.
    if records[0]
        .extra
        .get("prev_record_hash")
        .and_then(|v| v.as_str())
        .is_some()
    {
        return "orphaned";
    }
    "intact"
}

#[test]
fn protocol_corpus_authenticity_and_chain() {
    let Some(corpus) = corpus_dir() else {
        eprintln!(
            "SKIP protocol corpus: AEP_PROTOCOL_CORPUS not set — \
             the CI workflow checks out wasmagent-protocol and sets it"
        );
        return;
    };

    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(corpus.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest json");
    let entries = manifest
        .get("conformance_target")
        .and_then(|v| v.as_array())
        .expect("manifest conformance_target array")
        .clone();

    let default_key_hex = manifest
        .get("verifying_keys")
        .and_then(|v| v.get("js"))
        .and_then(|v| v.as_str())
        .map(|rel| std::fs::read_to_string(corpus.join(rel)).expect("read js verify key"))
        .unwrap_or_else(|| {
            std::fs::read_to_string(corpus.join("dsse/js-verify-key.hex"))
                .expect("read default verify key")
        })
        .trim()
        .to_string();

    let mut executed = 0usize;
    for entry in &entries {
        let path = entry
            .get("path")
            .and_then(|v| v.as_str())
            .expect("manifest entry path");
        let fixture = corpus.join(path);

        // Authenticity: every DSSE-valid / invalid fixture must match the
        // manifest verdict under the Rust verifier (.jsonl = every record).
        let authenticity = entry.get("authenticity").and_then(|v| v.as_str());
        if matches!(authenticity, Some("dsse-valid") | Some("invalid")) {
            let json = std::fs::read_to_string(&fixture).expect("read fixture");
            let records: Vec<AepRecord> = if path.ends_with(".jsonl") {
                json.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| serde_json::from_str(l).expect("fixture record"))
                    .collect()
            } else {
                vec![serde_json::from_str(&json).expect("fixture deserializes")]
            };
            let key_hex = entry
                .get("verify_key")
                .and_then(|v| v.as_str())
                .map(|rel| std::fs::read_to_string(corpus.join(rel)).expect("read verify key"))
                .unwrap_or_else(|| default_key_hex.clone());
            let key = verifying_key_from_hex(key_hex.trim());
            let expected_ok = authenticity == Some("dsse-valid");
            for (i, record) in records.iter().enumerate() {
                let verdict = verify_record_dsse(record, &key);
                match (&verdict, expected_ok) {
                    (Err(e), true) => panic!(
                        "authenticity mismatch for {path}[{i}]: verifier rejected ({e})"
                    ),
                    (Ok(()), false) => panic!(
                        "authenticity mismatch for {path}[{i}]: verifier accepted a non-conformant record"
                    ),
                    _ => {}
                }
            }
            executed += 1;
        }

        // Chain: every .jsonl fixture with a chain expectation.
        let expected_chain = entry.get("chain").and_then(|v| v.as_str());
        if let Some(expected) = expected_chain {
            if expected == "not-checked" {
                continue;
            }
            let json = std::fs::read_to_string(&fixture).expect("read chain fixture");
            let records: Vec<AepRecord> = json
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).expect("chain record"))
                .collect();
            let status = chain_status(&records);
            assert_eq!(
                status, expected,
                "chain status mismatch for {path} (got {status})"
            );
            executed += 1;
        }
    }

    assert!(
        executed >= 15,
        "corpus executed too few checks: {executed} — manifest or adapter broken"
    );
    println!("protocol corpus: {executed} verdict(s) enforced");
}
