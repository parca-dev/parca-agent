# cpu-profiler

## Prerequisites

- Linux Kernel version 4.19+

- [LLVM](https://apt.llvm.org/)

1. On Debian based distributions you need to install the llvm-14-dev and libclang-14-dev packages. If your distro doesn't have them you can get them from the official LLVM repo at https://apt.llvm.org.
2. On rpm based distribution you need the llvm-devel and clang-devel packages. If your distro doesn't have them you can get them from Fedora Rawhide.
- [Rust](https://www.rust-lang.org/tools/install)


1. Install the rust toolchain as defined in the root `rust-toolchain.toml` file: `rustup show`
2. Install bpf-linker: `make setup`


Install the following dependencies (Instructions are linked for each dependency).

## Build eBPF programs

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Run

```bash
cargo xtask run
```
