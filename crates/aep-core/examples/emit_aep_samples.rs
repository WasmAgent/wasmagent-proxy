//! Emit representative AEP record JSON files for schema-conformance checks.
//!
//! Used by the CI `schema-conformance` job: the samples are validated against
//! the canonical `aep-record` schema fetched from the published
//! `@wasmagent/protocol` package (pinned version — never vendored or
//! hand-copied into this repo).
//!
//! Usage: `cargo run -p aep-core --example emit_aep_samples -- <out-dir>`

use std::fs;
use std::path::Path;

use aep_core::{
    recording::SideEffectClass, sign_record, sign_record_dsse, ActionEvidence, AepRecord,
    CapabilityDecision, RecordingMode, SigningKey, AEP_SCHEMA_VERSION,
};

fn minimal_record() -> AepRecord {
    AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: "run-minimal".into(),
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
        actions: vec![],
        created_at_ms: 1_700_000_000_000,
        signature: None,
    }
}

fn annotated_record() -> AepRecord {
    AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: "run-annotated".into(),
        trace_id: Some("b3f1c2d3e4f5a6b7".into()),
        session_id: Some("session-77".into()),
        dsse_envelope: None,
        user_id: Some("user-dana@acme.example".into()),
        authorized_by: Some("manager-ade@acme.example".into()),
        authority_origin: Some("subject_consented".into()),
        identity_source: Some("organization_attested".into()),
        attribution_backing: Some("principal_key_signed".into()),
        run_attribution_backing_floor: Some("operator_asserted".into()),
        run_attribution_backing_observed: Some(vec![
            "operator_asserted".into(),
            "principal_key_signed".into(),
        ]),
        run_side_effect_class_max: Some("network-egress".into()),
        recording_mode: Some("full".into()),
        actions: vec![ActionEvidence {
            action_id: "ctx-42".into(),
            tool_name: "POST /api/payments".into(),
            state_changing: true,
            precondition_digest: Some("sha256:aa11".into()),
            result_digest: Some("sha256:bb22".into()),
            timestamp_ms: 1_700_000_000_001,
            parent_action_id: None,
            causal_chain_id: Some("chain-9".into()),
            recording_mode: RecordingMode::Full,
            capability_decision: Some(CapabilityDecision {
                capability: "payments.charge".into(),
                subject: "agent-1".into(),
                resource: "acct-42".into(),
                decision: "allow".into(),
                reason_code: Some("policy-match".into()),
                deny_reason_class: None,
            }),
            mcp_header_risk: Some("credential_leak".into()),
            side_effect_class: Some(SideEffectClass::NetworkEgress.canonical_str().into()),
        }],
        created_at_ms: 1_700_000_000_001,
        signature: None,
    }
}

fn signed_record(key: &SigningKey) -> AepRecord {
    let mut record = AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: "run-signed".into(),
        trace_id: Some("0a1b2c3d4e5f6071".into()),
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
            action_id: "ctx-7".into(),
            tool_name: "GET /mcp/resources".into(),
            state_changing: false,
            precondition_digest: None,
            result_digest: None,
            timestamp_ms: 1_700_000_000_002,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Validation,
            capability_decision: None,
            mcp_header_risk: None,
            side_effect_class: Some(SideEffectClass::Read.canonical_str().into()),
        }],
        created_at_ms: 1_700_000_000_002,
        signature: None,
    };
    sign_record_dsse(&mut record, key, "ci-sample-key");
    record
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "aep-samples".into());
    let out = Path::new(&out_dir);
    fs::create_dir_all(out).expect("create output directory");

    // Fixed key so the published verifying key lets any consumer (JS / Python)
    // verify the DSSE envelope without Rust.
    let key = SigningKey::from_bytes(&[42u8; 32]);

    let samples: [(&str, AepRecord); 3] = [
        ("record-minimal.json", minimal_record()),
        ("record-annotated.json", annotated_record()),
        ("record-signed.json", signed_record(&key)),
    ];

    for (name, record) in samples {
        let json = serde_json::to_string_pretty(&record).expect("serialize sample record");
        let path = out.join(name);
        fs::write(&path, json).expect("write sample record");
        println!("{}", path.display());
    }

    // Export the verifying key (32-byte Ed25519 public key, hex) so
    // non-Rust verifiers can check the DSSE signature.
    let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
    fs::write(out.join("verify-key.hex"), pubkey_hex).expect("write verifying key");
}
