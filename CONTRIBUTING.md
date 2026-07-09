# Contributing to wasmagent-proxy

Thank you for your interest in contributing! This guide covers the development
setup and workflow for this Rust/Wasm project.

## Prerequisites

- **Rust 1.75+** — install via [rustup](https://rustup.rs/):

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **wasm32-wasi target** — required for Wasm module builds:

  ```bash
  rustup target add wasm32-wasi
  ```

- **Make** (optional) — the `Makefile` provides convenient shortcuts.

## Quick start

```bash
# Clone and enter the repo
git clone https://github.com/WasmAgent/wasmagent-proxy.git
cd wasmagent-proxy

# Build all workspace crates (native)
cargo build --workspace

# Run tests
cargo test --workspace
```

## Development workflow

### Formatting and linting

This project enforces consistent style. Run these before submitting a PR:

```bash
cargo fmt --all              # auto-format code
cargo clippy --workspace -- -D warnings  # lint with warnings-as-errors
```

CI will fail if formatting or clippy produces any warnings.

### Testing

```bash
# Run all tests across the workspace
cargo test --workspace

# Run tests for a single crate
cargo test -p aep-core
cargo test -p proxy-wasm-evidence
```

All new code must include unit tests. See [Code quality](#code-quality) below.

### Building the Wasm module

The main deliverable is a Wasm filter for Proxy-Wasm compatible gateways:

```bash
# Using make
make wasm

# Or directly with cargo
cargo build -p proxy-wasm-evidence --target wasm32-wasi --release
```

Output: `target/wasm32-wasi/release/proxy_wasm_evidence.wasm`

### Running benchmarks

```bash
make bench
```

## Project structure

```
wasmagent-proxy/
├── crates/
│   ├── aep-core/                  # Shared AEP protocol logic
│   │   └── src/                    #   RecordingPolicy, ProvGraph, BundleSigner
│   └── proxy-wasm-evidence/       # Wasm filter crate
│       └── src/                    #   EvidenceFilter, HTTP context
├── deploy/                        # Envoy / Istio config examples
├── benchmarks/                    # Performance benchmarks
├── Cargo.toml                     # Workspace root
└── Makefile                       # Common commands
```

- **`aep-core`** — platform-independent types and logic (recording policy,
  provenance graph, Ed25519 signing). This crate compiles to native targets.
- **`proxy-wasm-evidence`** — the Proxy-Wasm HTTP filter that hosts `aep-core`
  inside a gateway. Compiles to `wasm32-wasi` for production and native for
  testing.

## Code quality

- **Tests**: Every new function or behavior must have unit tests. Run
  `cargo test --workspace` to verify.
- **Clippy**: Must pass with `-D warnings` (no warnings allowed).
- **Formatting**: Must pass `cargo fmt --all -- --check`.
- **Unsafe code**: Do not add `unsafe` blocks without a documented `// SAFETY:`
  comment explaining why it is sound.
- **OS-specific deps**: The Wasm target is `wasm32-wasi`. Avoid
  OS-specific dependencies (e.g., `std::fs`, networking crates) in
  `proxy-wasm-evidence` — it must compile to Wasm.

## Making changes

1. Create a branch from `main`:

   ```bash
   git checkout -b my-feature main
   ```

2. Make your changes, write tests, and ensure everything passes:

   ```bash
   cargo fmt --all
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```

3. Build the Wasm module to confirm it still compiles for the Wasm target:

   ```bash
   cargo build -p proxy-wasm-evidence --target wasm32-wasi --release
   ```

4. Commit and push, then open a pull request.

## Pull request checklist

Before submitting a PR, confirm:

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Wasm build succeeds (`cargo build -p proxy-wasm-evidence --target wasm32-wasi --release`)
- [ ] New code has unit tests
- [ ] No new `unsafe` without a `// SAFETY:` comment
- [ ] No OS-specific dependencies added to the Wasm crate

## Getting help

- Open a [GitHub Issue](https://github.com/WasmAgent/wasmagent-proxy/issues) for
  bugs, questions, or feature proposals.
- See [CLAUDE.md](./CLAUDE.md) for additional project context and bot-specific
  instructions.

## License

Contributions are accepted under the same [Apache-2.0](./LICENSE) license that
covers the project.
