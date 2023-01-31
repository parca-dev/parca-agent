// Copyright 2022-2023 The Parca Authors
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
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

type flags struct {
	Executable string `kong:"help='The executable to print the .eh_unwind tables for.'"`
	Compact    bool   `kong:"help='Whether to use the compact format.'"`
}

// This tool exists for debugging .eh_frame unwinding and its intended for Parca Agent's
// developers.
func main() {
	logger := logger.NewLogger("debug", logger.LogFormatLogfmt, "eh-frame")

	flags := flags{}
	kong.Parse(&flags)

	executablePath := flags.Executable

	if executablePath == "" {
		// nolint
		fmt.Fprintln(os.Stderr, "The executable argument is required")
		os.Exit(1)
	}

	ptb := unwind.NewUnwindTableBuilder(logger)
	err := ptb.PrintTable(os.Stdout, executablePath, flags.Compact)
	if err != nil {
		// nolint
		fmt.Println("failed with:", err)
	}
}
