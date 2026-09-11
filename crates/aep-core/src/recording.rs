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

impl SideEffectClass {
    /// Canonical aep-record vocabulary for this class: hyphenated forms as
    /// declared by the `side_effect_class` field in the canonical schema
    /// (`WasmAgent/wasmagent-protocol`). Note this differs from the serde
    /// snake_case wire form above — canonical values are hyphenated.
    pub const fn canonical_str(&self) -> &'static str {
        match self {
            SideEffectClass::Read => "read",
            SideEffectClass::MutateLocal => "mutate-local",
            SideEffectClass::MutateExternal => "mutate-external",
            SideEffectClass::NetworkEgress => "network-egress",
            SideEffectClass::Unknown => "unknown",
        }
    }
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
    fn consent_anomaly_always_full() {
        let mut c = ctx(SideEffectClass::Read);
        c.has_consent_anomaly = true;
        assert_eq!(compile_recording_policy(&c).mode, RecordingMode::Full);
    }

    #[test]
    fn taint_with_read_class_stays_validation() {
        // Tainted input only escalates state-changing calls; a Read call with
        // a taint chain still lands on the cheapest mode.
        let mut c = ctx(SideEffectClass::Read);
        c.taint_chain_length = 3;
        let policy = compile_recording_policy(&c);
        assert_eq!(policy.mode, RecordingMode::Validation);
        assert_eq!(policy.reason, "read-only, no anomaly");
    }

    #[test]
    fn taint_with_mutate_local_escalates_to_full() {
        let mut c = ctx(SideEffectClass::MutateLocal);
        c.taint_chain_length = 1;
        assert_eq!(compile_recording_policy(&c).mode, RecordingMode::Full);
    }

    #[test]
    fn unknown_class_yields_full() {
        assert_eq!(
            compile_recording_policy(&ctx(SideEffectClass::Unknown)).mode,
            RecordingMode::Full
        );
    }

    #[test]
    fn risk_priority_order_vetted_beats_others() {
        // When multiple signals fire, the first matching rule's reason wins.
        let mut c = ctx(SideEffectClass::MutateExternal);
        c.was_vetted = true;
        c.has_consent_anomaly = true;
        c.taint_chain_length = 2;
        assert_eq!(
            compile_recording_policy(&c).reason,
            "tool flagged by vetting"
        );
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
