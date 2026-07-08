WASM_TARGET := wasm32-wasi
RELEASE_DIR  := target/$(WASM_TARGET)/release

.PHONY: build test bench fmt lint clean wasm

build:
	cargo build --workspace

wasm:
	cargo build -p proxy-wasm-evidence --target $(WASM_TARGET) --release
	@echo "Wasm module: $(RELEASE_DIR)/proxy_wasm_evidence.wasm"

test:
	cargo test --workspace

bench:
	cargo run --bin latency_bench --release

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

clean:
	cargo clean
