//go:build linux

package probes

// probe_bpfel.{go,o} are generated from bpf/probe.bpf.c by cilium/ebpf's
// bpf2go. The Go file is committed; the .o file is embedded into it via
// `go:embed` and is also written next to it so the loader can find it.
//
// To regenerate after editing the C source, run `make probes-bpf` (the
// Makefile injects BPF2GO_CFLAGS with the multiarch include path that
// Debian-derived distros need). On distros without multiarch headers
// (Fedora/RHEL), `go generate ./probes/` works directly.
//
// We restrict to `bpfel` because parca-agent only ships amd64 and arm64
// builds (both little-endian); generating a `bpfeb` variant would add
// dead bytes to the binary.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type probe_event probe bpf/probe.bpf.c
