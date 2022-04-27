.PHONY: setup
setup:
	rustup install stable
	rustup install nightly
	cargo install bpf-linker
	rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

.PHONY: build
build:
	cargo xtask build-ebpf --release

.PHONY: clean
clean:
	cargo clean
