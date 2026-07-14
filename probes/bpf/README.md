# probes BPF

`probe.bpf.c` is the kernel-side uprobe program. It is compiled by
cilium/ebpf's `bpf2go` (driven from `../gen.go` via `go generate`), which
emits `../probe_bpfel.go` (a Go mirror of the C structs plus a loader)
and `../probe_bpfel.o` (the BPF bytecode, embedded into the .go file
via `//go:embed`).

Run `make probes-bpf` from the repository root to regenerate both files.
The Makefile injects `BPF2GO_CFLAGS` with the multiarch include path
that Debian-derived distros need; on Fedora/RHEL `go generate ./probes/`
works directly.

A single object covers every supported Go architecture. Our BPF program
does not touch any arch-specific macros (`PT_REGS_PARM1` and friends
from `bpf/bpf_tracing.h`), so `clang -target bpf` emits identical
bytecode regardless of host arch. We restrict bpf2go to `-target bpfel`
because parca-agent only ships amd64/arm64 (both little-endian).

If a future change adds anything that branches on `__TARGET_ARCH_*`
(most likely a `PT_REGS_PARMn(ctx)` to read a function argument at
uprobe entry), the build will need to split per arch again. The bpf2go
invocation in `../gen.go` would grow a second `-target bpfeb` variant
and per-arch `__TARGET_ARCH_*` defines in `BPF2GO_CFLAGS`.

Build dependencies on the host:

- clang (>= 14, with the bpf target enabled)
- libbpf headers (`bpf/bpf_helpers.h` etc., from libbpf-dev / libbpf-devel)
- kernel UAPI headers (`linux/bpf.h` etc., from linux-libc-dev / kernel-headers)
