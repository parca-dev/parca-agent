//go:build linux

package probes

// probe_bpfel.{go,o} are generated from bpf/probe.bpf.c by cilium/ebpf's
// bpf2go. Neither is committed: both are gitignored and rebuilt by
// `make probes-bpf`.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type probe_event probe bpf/probe.bpf.c
