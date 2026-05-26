# probes BPF

`probe.bpf.c` is the kernel-side uprobe program. The compiled output
`probe.bpf.o` is produced by `make probes-bpf` from the parca-agent
repository root and is git-ignored.

A single object covers every supported Go architecture. Our BPF program
does not touch any arch-specific macros (`PT_REGS_PARM1` and friends from
`bpf/bpf_tracing.h`), so `clang -target bpf` emits identical bytecode
regardless of host arch and regardless of which `__TARGET_ARCH_*` define
might be in scope. The `runtime.GOARCH`-keyed lookup in `../loader.go`
was deliberately removed to avoid pretending we ship arch-specific
artifacts when we don't.

If a future change adds anything that branches on `__TARGET_ARCH_*` (most
likely a `PT_REGS_PARMn(ctx)` to read a function argument at uprobe
entry), the build will need to split per arch again:

- per-target `BPF_ARCH` variable in the Makefile mapping `amd64 -> x86`
  and `arm64 -> arm64`,
- `-D__TARGET_ARCH_$(BPF_ARCH)` passed to clang,
- a `probe.bpf.<GOARCH>` naming scheme,
- a matching `runtime.GOARCH`-keyed embed lookup in `loader.go`.

Git history has the previous form if you need to crib from it.

This README is committed so `//go:embed bpf` in `../loader.go` always
has a valid embed target even before any BPF object has been compiled.

Build dependencies on the host:

- clang (>= 14, with the bpf target enabled)
- libbpf headers (`bpf/bpf_helpers.h` etc., from libbpf-dev / libbpf-devel)
- kernel UAPI headers (`linux/bpf.h` etc., from linux-libc-dev / kernel-headers)
