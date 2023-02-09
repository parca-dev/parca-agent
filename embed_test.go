package parcaagent

import (
	"embed"
)

//go:embed "dist/btf/test.bpf.o"
//go:embed "dist/profiler/cpu.bpf.o"
//go:embed "dist/btfhub/*"

var BPFBundle embed.FS
