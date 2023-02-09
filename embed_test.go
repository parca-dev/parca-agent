package parcaagent

import (
	"embed"
)

//go:embed "dist/test/test.bpf.o"
//go:embed "dist/profiler/cpu.bpf.o"
//go:embed "dist/btfhub/*"

var BPFBundleTest embed.FS
