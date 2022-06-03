.PHONY: setup
setup:
	rustup install nightly-2022-05-23
	cargo install bpf-linker
	rustup component add rust-src --toolchain nightly-2022-05-23

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