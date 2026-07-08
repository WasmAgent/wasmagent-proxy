//! Latency benchmark for the evidence recording path.
//! Run with: cargo bench --bench latency_bench

use aep_core::recording::{RiskContext, SideEffectClass, compile_recording_policy};
use std::time::Instant;

fn main() {
    let ctx = RiskContext {
        was_vetted: false,
        has_consent_anomaly: false,
        taint_chain_length: 0,
        side_effect_class: SideEffectClass::MutateExternal,
    };

    let iterations = 100_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = compile_recording_policy(&ctx);
    }
    let elapsed = start.elapsed();
    println!(
        "{} iterations in {:?} — {:.2}ns/op",
        iterations,
        elapsed,
        elapsed.as_nanos() as f64 / iterations as f64
    );
}
