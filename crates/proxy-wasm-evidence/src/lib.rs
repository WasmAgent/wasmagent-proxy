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

pub mod config;
pub mod recorder;

#[cfg(target_arch = "wasm32")]
mod filter;

pub use config::{Config, PluginConfig};
pub use recorder::{build_evidence, infer_side_effect_class};

#[cfg(target_arch = "wasm32")]
use proxy_wasm::types::LogLevel;

// Proxy-Wasm module entry point. Compiled only for `wasm32*`; the SDK imports
// host functions that exist solely inside a Proxy-Wasm host.
#[cfg(target_arch = "wasm32")]
proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn proxy_wasm::traits::RootContext> {
        Box::new(filter::EvidenceRoot::new())
    });
}}
