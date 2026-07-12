use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingMode {
    Validation,
    Delta,
    Full,
}

impl RecordingMode {
    /// Wire-format identifier for this mode: the snake_case form serialized into
    /// AEP records (see the `serde(rename_all = "snake_case")` above) and emitted
    /// as the value of the gateway's `x-aep-recording-mode` response header.
    /// `recording_mode_as_str_matches_serde` pins this to the serde output so the
    /// two cannot drift.
    pub const fn as_str(&self) -> &'static str {
        match self {
            RecordingMode::Validation => "validation",
            RecordingMode::Delta => "delta",
            RecordingMode::Full => "full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    Read,
    MutateLocal,
    MutateExternal,
    NetworkEgress,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    pub was_vetted: bool,
    pub has_consent_anomaly: bool,
    pub taint_chain_length: u32,
    pub side_effect_class: SideEffectClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingPolicy {
    pub mode: RecordingMode,
    pub reason: String,
}

/// Port of capability-compiler's compileToRecordingPolicy logic.
/// Decision priority matches the TypeScript implementation exactly.
pub fn compile_recording_policy(ctx: &RiskContext) -> RecordingPolicy {
    if ctx.was_vetted {
        return RecordingPolicy {
            mode: RecordingMode::Full,
            reason: "tool flagged by vetting".into(),
        };
    }
    if ctx.has_consent_anomaly {
        return RecordingPolicy {
            mode: RecordingMode::Full,
            reason: "consent anomaly recorded".into(),
        };
    }
    if ctx.taint_chain_length > 0 && ctx.side_effect_class != SideEffectClass::Read {
        return RecordingPolicy {
            mode: RecordingMode::Full,
            reason: "tainted input reaching state-changing call".into(),
        };
    }
    if ctx.side_effect_class == SideEffectClass::Unknown {
        return RecordingPolicy {
            mode: RecordingMode::Full,
            reason: "unknown side-effect class".into(),
        };
    }
    if matches!(
        ctx.side_effect_class,
        SideEffectClass::MutateExternal | SideEffectClass::NetworkEgress
    ) {
        return RecordingPolicy {
            mode: RecordingMode::Full,
            reason: "external mutation".into(),
        };
    }
    if ctx.side_effect_class == SideEffectClass::MutateLocal {
        return RecordingPolicy {
            mode: RecordingMode::Delta,
            reason: "local mutation, low risk".into(),
        };
    }
    RecordingPolicy {
        mode: RecordingMode::Validation,
        reason: "read-only, no anomaly".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(side_effect_class: SideEffectClass) -> RiskContext {
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class,
        }
    }

    #[test]
    fn read_yields_validation() {
        assert_eq!(
            compile_recording_policy(&ctx(SideEffectClass::Read)).mode,
            RecordingMode::Validation
        );
    }

    #[test]
    fn mutate_local_yields_delta() {
        assert_eq!(
            compile_recording_policy(&ctx(SideEffectClass::MutateLocal)).mode,
            RecordingMode::Delta
        );
    }

    #[test]
    fn network_egress_yields_full() {
        assert_eq!(
            compile_recording_policy(&ctx(SideEffectClass::NetworkEgress)).mode,
            RecordingMode::Full
        );
    }

    #[test]
    fn vetted_always_full() {
        let mut c = ctx(SideEffectClass::Read);
        c.was_vetted = true;
        assert_eq!(compile_recording_policy(&c).mode, RecordingMode::Full);
    }

    #[test]
    fn consent_anomaly_yields_full_even_for_read() {
        // has_consent_anomaly is evaluated before the read short-circuit, so an
        // anomaly forces Full recording even for an otherwise read-only call.
        let mut c = ctx(SideEffectClass::Read);
        c.has_consent_anomaly = true;
        let policy = compile_recording_policy(&c);
        assert_eq!(policy.mode, RecordingMode::Full);
        assert_eq!(policy.reason, "consent anomaly recorded");
    }

    #[test]
    fn tainted_input_reaching_state_changing_call_yields_full() {
        // taint_chain_length > 0 combined with a non-Read side effect forces
        // Full recording (tainted input reaching a state-changing call).
        let mut c = ctx(SideEffectClass::MutateLocal);
        c.taint_chain_length = 3;
        let policy = compile_recording_policy(&c);
        assert_eq!(policy.mode, RecordingMode::Full);
        assert_eq!(policy.reason, "tainted input reaching state-changing call");
    }

    #[test]
    fn taint_chain_does_not_upgrade_pure_reads() {
        // Taint only matters when paired with a state-changing call; a tainted
        // read cannot propagate the taint into state, so it stays Validation.
        let mut c = ctx(SideEffectClass::Read);
        c.taint_chain_length = 5;
        assert_eq!(compile_recording_policy(&c).mode, RecordingMode::Validation);
    }

    #[test]
    fn mutate_external_yields_full() {
        assert_eq!(
            compile_recording_policy(&ctx(SideEffectClass::MutateExternal)).mode,
            RecordingMode::Full
        );
    }

    #[test]
    fn unknown_side_effect_yields_full() {
        let policy = compile_recording_policy(&ctx(SideEffectClass::Unknown));
        assert_eq!(policy.mode, RecordingMode::Full);
        assert_eq!(policy.reason, "unknown side-effect class");
    }

    #[test]
    fn vetting_takes_priority_over_consent_anomaly() {
        // was_vetted is the first decision branch, so it wins even when a
        // consent anomaly is also present — pinning the decision priority.
        let mut c = ctx(SideEffectClass::Read);
        c.was_vetted = true;
        c.has_consent_anomaly = true;
        let policy = compile_recording_policy(&c);
        assert_eq!(policy.mode, RecordingMode::Full);
        assert_eq!(policy.reason, "tool flagged by vetting");
    }

    #[test]
    fn recording_mode_as_str_matches_serde() {
        for mode in [
            RecordingMode::Validation,
            RecordingMode::Delta,
            RecordingMode::Full,
        ] {
            let serde_str = serde_json::to_string(&mode)
                .unwrap()
                .trim_matches('"')
                .to_string();
            assert_eq!(
                mode.as_str(),
                serde_str,
                "as_str drifted from serde serialization"
            );
        }
    }
}
