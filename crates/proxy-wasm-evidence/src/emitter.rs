//! Evidence assembly → signed `AEPRecord` — the data-plane core for the
//! gateway's signed-evidence pipeline (P0-3A).
//!
//! Native-testable by design: this module contains NO proxy-wasm imports.
//! The Wasm filter feeds captured [`ActionEvidence`] plus gateway identity in;
//! this module assembles the aep/v0.5 `AEPRecord`, binds trace/agent
//! identity, signs it with the DSSE profile (`sign_record_dsse`), and hands
//! back the signed record for export. The central conformance corpus and the
//! JS verifier verify the exact bytes this produces.
//!
//! Completeness semantics: assembly REQUIRES at least one captured evidence
//! entry — "no events" must stay distinguishable from "failed to sign" and
//! from "dropped by capacity pressure" (tracked via
//! [`EvidenceBuffer::dropped_total`]).
use aep_core::evidence::ActionEvidence;
use aep_core::{sign_record_dsse, AepRecord, AEP_SCHEMA_VERSION};

/// Gateway identity bound into every emitted record.
pub struct EmitterIdentity {
    /// Correlation id from `trace_id_header` (x-b3-traceid) — becomes the
    /// record's `trace_id` and the `run_id` stem.
    pub trace_id: String,
    /// Gateway/agent identity from `agent_id_header` — recorded as `user_id`.
    pub agent_id: String,
    /// Signing key id (from `key_id` config) recorded in the signature block.
    pub key_id: String,
}

/// Assemble captured evidence into a DSSE-signed `AEPRecord`.
///
/// Fails closed (Err) when there is nothing to sign or the signer rejects
/// the record — "failed to sign" is always distinguishable from "no events".
pub fn assemble_and_sign(
    evidence: &[ActionEvidence],
    identity: &EmitterIdentity,
    created_at_ms: u64,
    key: &aep_core::SigningKey,
) -> Result<AepRecord, String> {
    if evidence.is_empty() {
        return Err("no evidence captured — refusing to emit an empty signed record".into());
    }
    if identity.trace_id.trim().is_empty() {
        return Err("trace_id is empty — cannot bind evidence to a run".into());
    }

    let mut record = AepRecord {
        schema_version: AEP_SCHEMA_VERSION.into(),
        run_id: format!("gw-{}", identity.trace_id),
        trace_id: Some(identity.trace_id.clone()),
        user_id: Some(identity.agent_id.clone()),
        actions: evidence.to_vec(),
        created_at_ms,
        ..Default::default()
    };
    record
        .extra
        .insert("agent_id".to_string(), identity.agent_id.clone().into());

    sign_record_dsse(&mut record, key, &identity.key_id).map(|()| record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aep_core::recording::RecordingMode;
    use aep_core::{verify_record_dsse, SigningKey};

    fn sample_evidence() -> Vec<ActionEvidence> {
        vec![ActionEvidence {
            action_id: "gw-act-1".into(),
            tool_name: "POST /api/quote".into(),
            state_changing: true,
            precondition_digest: None,
            result_digest: Some("sha256:abc".into()),
            timestamp_ms: 1_700_000_000_000,
            parent_action_id: None,
            causal_chain_id: None,
            recording_mode: RecordingMode::Full,
            capability_decision: None,
            mcp_header_risk: None,
            side_effect_class: Some("mutate-external".into()),
            extra: Default::default(),
        }]
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn signed_record_verifies_and_binds_identity() {
        let identity = EmitterIdentity {
            trace_id: "trace-abc".into(),
            agent_id: "gateway-eu-1".into(),
            key_id: "gw-key-1".into(),
        };
        let signing_key = key();
        let record = assemble_and_sign(
            &sample_evidence(),
            &identity,
            1_700_000_000_000,
            &signing_key,
        )
        .expect("assemble and sign");

        assert_eq!(record.run_id, "gw-trace-abc");
        assert_eq!(record.trace_id.as_deref(), Some("trace-abc"));
        assert_eq!(record.user_id.as_deref(), Some("gateway-eu-1"));
        assert_eq!(
            record.extra.get("agent_id").and_then(|v| v.as_str()),
            Some("gateway-eu-1")
        );
        assert!(record.dsse_envelope.is_some(), "DSSE envelope attached");

        let verifying_key = signing_key.verifying_key();
        verify_record_dsse(&record, &verifying_key).expect("DSSE verification");
    }

    #[test]
    fn empty_evidence_fails_closed() {
        let identity = EmitterIdentity {
            trace_id: "t".into(),
            agent_id: "a".into(),
            key_id: "k".into(),
        };
        let signing_key = key();
        let err = assemble_and_sign(&[], &identity, 0, &signing_key).expect_err("must refuse");
        assert!(err.contains("no evidence captured"), "got: {err}");
    }

    #[test]
    fn empty_trace_id_fails_closed() {
        let identity = EmitterIdentity {
            trace_id: "  ".into(),
            agent_id: "a".into(),
            key_id: "k".into(),
        };
        let signing_key = key();
        let err = assemble_and_sign(&sample_evidence(), &identity, 0, &signing_key)
            .expect_err("must refuse");
        assert!(err.contains("trace_id"), "got: {err}");
    }

    #[test]
    fn tampered_record_fails_verification() {
        let identity = EmitterIdentity {
            trace_id: "trace-t".into(),
            agent_id: "gateway-eu-1".into(),
            key_id: "gw-key-1".into(),
        };
        let signing_key = key();
        let mut record = assemble_and_sign(
            &sample_evidence(),
            &identity,
            1_700_000_000_000,
            &signing_key,
        )
        .expect("assemble and sign");
        record.run_id = "run-tampered".into();

        let verifying_key = signing_key.verifying_key();
        assert!(verify_record_dsse(&record, &verifying_key).is_err());
    }
}
