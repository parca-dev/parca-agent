.PHONY: setup
setup:
	rustup component add rust-src
	# we need to do this as we're using an external LLVM. See: https://github.com/aya-rs/bpf-linker#using-external-llvm
	cargo install --git https://github.com/aya-rs/bpf-linker --tag v0.9.4 --no-default-features --features system-llvm -- bpf-linker

.PHONY: build
build:
	cargo xtask build-ebpf --release

.PHONY: clean
clean:
	cargo clean

.PHONY: format
format:
	rustfmt cpu-profiler/**/*.rs

.PHONY: lint
lint:
	cargo clippy
