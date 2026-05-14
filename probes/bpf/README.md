# probes BPF

`probe.bpf.c` is the kernel-side uprobe program. The compiled outputs
`probe.bpf.amd64` and `probe.bpf.arm64` are produced by `make probes-bpf`
in the parca-agent repository root and are git-ignored.

This README is committed so `//go:embed bpf` in `../loader.go` always has
a valid embed target even before the BPF object is compiled.

Build dependencies: clang (>= 14, with the bpf target) and the libbpf
headers (`bpf/bpf_helpers.h` etc., from libbpf-dev / libbpf-devel).
