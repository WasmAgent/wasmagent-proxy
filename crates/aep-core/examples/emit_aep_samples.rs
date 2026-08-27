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
    sign_record, ActionEvidence, AepRecord, CapabilityDecision, RecordingMode, SigningKey,
    AEP_SCHEMA_VERSION,
};

fn minimal_record() -> AepRecord {
    AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: "run-minimal".into(),
        trace_id: None,
        session_id: None,
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
            }),
            mcp_header_risk: Some("credential_leak".into()),
        }],
        created_at_ms: 1_700_000_000_001,
        signature: None,
    }
}

fn signed_record() -> AepRecord {
    let mut record = AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: "run-signed".into(),
        trace_id: Some("0a1b2c3d4e5f6071".into()),
        session_id: None,
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
        }],
        created_at_ms: 1_700_000_000_002,
        signature: None,
    };
    let key = SigningKey::generate(&mut rand::rng());
    sign_record(&mut record, &key, "ci-sample-key");
    record
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "aep-samples".into());
    let out = Path::new(&out_dir);
    fs::create_dir_all(out).expect("create output directory");

    let samples: [(&str, AepRecord); 3] = [
        ("record-minimal.json", minimal_record()),
        ("record-annotated.json", annotated_record()),
        ("record-signed.json", signed_record()),
    ];

    for (name, record) in samples {
        let json = serde_json::to_string_pretty(&record).expect("serialize sample record");
        let path = out.join(name);
        fs::write(&path, json).expect("write sample record");
        println!("{}", path.display());
    }
}
