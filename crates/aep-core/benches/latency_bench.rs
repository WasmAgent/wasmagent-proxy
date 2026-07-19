//! Criterion benchmark for `compile_recording_policy()`.
//!
//! Exercises all decision branches of the policy compiler:
//! 1. vetted              – was_vetted = true        → Full
//! 2. consent_anomaly     – has_consent_anomaly = true → Full
//! 3. tainted_non_read    – taint_chain > 0, non-Read → Full
//! 4. unknown_class       – SideEffectClass::Unknown  → Full
//! 5. external_mutation   – MutateExternal            → Full
//! 6. network_egress      – NetworkEgress             → Full
//! 7. mutate_local        – MutateLocal               → Delta
//! 8. read_default        – Read, no anomalies        → Validation

use aep_core::recording::{SideEffectClass, RiskContext, compile_recording_policy};
use criterion::{black_box, criterion_group, Criterion};
use std::time::Instant;

/// Helper to build a default (Read, clean) RiskContext.
fn base_ctx() -> RiskContext {
    RiskContext {
        was_vetted: false,
        has_consent_anomaly: false,
        taint_chain_length: 0,
        side_effect_class: SideEffectClass::Read,
    }
}

fn bench_compile_recording_policy(c: &mut Criterion) {
    // Path 1: was_vetted = true → Full
    let mut ctx = base_ctx();
    ctx.was_vetted = true;
    c.bench_function("path_vetted", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 2: has_consent_anomaly = true → Full
    let mut ctx = base_ctx();
    ctx.has_consent_anomaly = true;
    c.bench_function("path_consent_anomaly", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 3: tainted input reaching non-Read call → Full
    let mut ctx = base_ctx();
    ctx.taint_chain_length = 3;
    ctx.side_effect_class = SideEffectClass::MutateLocal;
    c.bench_function("path_tainted_non_read", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 4: unknown side-effect class → Full
    let mut ctx = base_ctx();
    ctx.side_effect_class = SideEffectClass::Unknown;
    c.bench_function("path_unknown_class", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 5: external mutation (MutateExternal) → Full
    let mut ctx = base_ctx();
    ctx.side_effect_class = SideEffectClass::MutateExternal;
    c.bench_function("path_external_mutation", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 6: network egress → Full
    let mut ctx = base_ctx();
    ctx.side_effect_class = SideEffectClass::NetworkEgress;
    c.bench_function("path_network_egress", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 7: local mutation → Delta
    let mut ctx = base_ctx();
    ctx.side_effect_class = SideEffectClass::MutateLocal;
    c.bench_function("path_mutate_local", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });

    // Path 8: read default → Validation
    let ctx = base_ctx();
    c.bench_function("path_read_default", |b| {
        b.iter(|| black_box(compile_recording_policy(black_box(&ctx))))
    });
}

criterion_group!(benches, bench_compile_recording_policy);

fn main() {
    // Sub-microsecond median latency assertion — fails fast in CI if regression.
    const ITERATIONS: u64 = 100_000;
    const THRESHOLD_NS: f64 = 1_000.0; // 1 μs
    for ctx in all_contexts() {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(compile_recording_policy(black_box(&ctx)));
        }
        let avg_ns = start.elapsed().as_nanos() as f64 / ITERATIONS as f64;
        assert!(
            avg_ns < THRESHOLD_NS,
            "compile_recording_policy avg {:.0} ns exceeds 1 μs threshold for context {:?}",
            avg_ns,
            ctx.side_effect_class,
        );
    }
    println!(
        "✓ all paths under {:.0} ns/op ({} iterations each)",
        THRESHOLD_NS, ITERATIONS
    );

    // Run criterion benchmarks.
    benches();
}

/// All `RiskContext` variants that exercise every exit path of
/// `compile_recording_policy`.
fn all_contexts() -> Vec<RiskContext> {
    vec![
        // Path 1: vetted
        RiskContext {
            was_vetted: true,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::Read,
        },
        // Path 2: consent anomaly
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: true,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::Read,
        },
        // Path 3: tainted + non-Read
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 3,
            side_effect_class: SideEffectClass::MutateLocal,
        },
        // Path 4: unknown class
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::Unknown,
        },
        // Path 5: external mutation
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::MutateExternal,
        },
        // Path 6: network egress
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::NetworkEgress,
        },
        // Path 7: mutate local
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::MutateLocal,
        },
        // Path 8: read default
        RiskContext {
            was_vetted: false,
            has_consent_anomaly: false,
            taint_chain_length: 0,
            side_effect_class: SideEffectClass::Read,
        },
    ]
}
