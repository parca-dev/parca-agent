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

package unwind

import (
	"debug/elf"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/xyproto/ainur"
)

func HasFramePointers(executable string) (bool, error) {
	elf, err := elf.Open(executable)
	if err != nil {
		return false, fmt.Errorf("failed to open ELF file for path %s: %w", executable, err)
	}
	defer elf.Close()

	compiler := ainur.Compiler(elf)
	// Go 1.7 [0] enabled FP for x86_64. arm64 got them enabled in 1.12 [1].
	//
	// Note: we don't take into account applications that use cgo yet.
	// If the non Go bits aren't compiled with frame pointers, too,
	// unwinding will fail. In the future might add the unwind information
	// for these bits of executable code.
	//
	// [0]: https://go.dev/doc/go1.7 (released on 2016-08-15).
	// [1]: https://go.dev/doc/go1.12 (released on 2019-02-25).
	if strings.Contains(compiler, "Go") {
		versionString := strings.Split(compiler, "Go ")[1]
		have, err := version.NewVersion(versionString)
		if err != nil {
			return false, fmt.Errorf("failed to parse semver %s: %w", versionString, err)
		}
		want, err := version.NewVersion("1.12.0")
		if err != nil {
			return false, fmt.Errorf("failed to parse semver %s: %w", "1.19.4", err)
		}

		return want.LessThan(have), nil
	}

	// By default, assume there frame pointers are not present.
	return false, nil
}
