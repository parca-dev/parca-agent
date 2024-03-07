// Copyright 2022-2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"debug/elf"
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

type flags struct {
	Executable string `kong:"help='The executable to print the .eh_unwind tables for.'"`
	Compact    bool   `kong:"help='Whether to use the compact format.'"`
	Final      bool   `kong:"help='Whether to print the unwind rows as they will be inserted in the BPF maps.'"`
	RelativePC uint64 `kong:"help='Filter FDEs that contain this PC'"`
}

// This tool exists for debugging .eh_frame unwinding and its intended for Parca Agent's
// developers.
func main() {
	reg := prometheus.NewRegistry()
	logger := logger.NewLogger("warn", logger.LogFormatLogfmt, "eh-frame")
	pool := objectfile.NewPool(logger, reg, "", 10, 0)
	finder := debuginfo.NewFinder(logger, noop.NewTracerProvider().Tracer("eh-frame"), reg, nil)
	uc := unwind.NewContext(logger, pool, finder)
	flags := flags{}
	kong.Parse(&flags)

	executablePath := flags.Executable

	if executablePath == "" {
		// nolint
		fmt.Fprintln(os.Stderr, "The executable argument is required")
		os.Exit(1)
	}

	var pc *uint64

	if flags.RelativePC != 0 {
		pc = &flags.RelativePC
	}

	if flags.Final {
		ut, arch, _, err := unwind.GenerateCompactUnwindTable(uc, "/", executablePath)
		if err != nil {
			// nolint:forbidigo
			fmt.Println("failed with:", err)
			return
		}
		for _, compactRow := range ut {
			showLr := arch == elf.EM_AARCH64
			// nolint:forbidigo
			fmt.Println(compactRow.ToString(showLr))
		}
		return
	}

	if err := unwind.PrintTable(uc, os.Stdout, executablePath, flags.Compact, pc); err != nil {
		// nolint:forbidigo
		fmt.Println("failed with:", err)
	}
}
