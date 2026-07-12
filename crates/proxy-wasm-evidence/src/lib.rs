//! Proxy-Wasm HTTP filter — AEP evidence recording + capability policy enforcement.
//!
//! # Native vs. Wasm compilation
//!
//! This crate ships as a Proxy-Wasm `cdylib` loaded by a gateway host
//! (Envoy/Istio/Kong). The Proxy-Wasm SDK (`proxy-wasm`) imports host callbacks
//! via `#[link(wasm_import_module = "env")]`; those imports exist only inside a
//! Proxy-Wasm host. When the crate is compiled as a *native* library the imports
//! are left undefined, which Apple's linker rejects with
//! `symbol(s) not found for architecture arm64` (GNU `ld` tolerates the
//! undefined symbols, which is why the failure was macOS-specific).
//!
//! To keep `cargo test --workspace` and `cargo clippy --workspace` green on every
//! host, the SDK and the HTTP-context entrypoint ([`filter`]) are compiled only
//! for `wasm32*` targets. The host-agnostic logic ([`config`], [`recorder`]) is
//! compiled on every target so it can be unit-tested natively.
//!
//! The [`filter`] module is additionally compiled during `cargo test` (native)
//! so that its unit tests can verify struct construction and field-mutation
//! logic without requiring a Proxy-Wasm host. The HTTP-context trait impls
//! remain gated to `wasm32*` to avoid undefined-symbol link errors.

pub mod config;
pub mod recorder;

#[cfg(any(target_arch = "wasm32", test))]
mod filter;

pub use config::PluginConfig;
pub use recorder::{build_evidence, infer_side_effect_class};

#[cfg(target_arch = "wasm32")]
use proxy_wasm::traits::HttpContext;
#[cfg(target_arch = "wasm32")]
use proxy_wasm::types::LogLevel;

/// Proxy-Wasm module entry point — registers the HTTP context factory.
///
/// Compiled only for `wasm32*`; the SDK imports host functions that exist solely
/// inside a Proxy-Wasm host (see the crate docs for why native compilation is
/// gated off).
#[cfg(target_arch = "wasm32")]
proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_http_context(|context_id, _| -> Box<dyn HttpContext> {
        Box::new(filter::EvidenceFilter::new(context_id))
    });
}}
