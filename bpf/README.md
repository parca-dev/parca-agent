# cpu-profiler

## Prerequisites

1. Install the rust toolchain as defined in the root `rust-toolchain.toml` file: `rustup show`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Run

```bash
cargo xtask run
```
