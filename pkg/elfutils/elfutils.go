// Copyright 2021 The Parca Authors
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

package elfutils

import (
	"debug/elf"
	"fmt"
)

func IsGo(path string) (bool, error) {
	// Checks ".note.go.buildid" sections and symtab better to keep those sections in object file.
	exe, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer exe.Close()

	for _, s := range exe.Sections {
		if s.Name == ".note.go.buildid" {
			return true, nil
		}
	}

	// In case ".note.go.buildid" section is stripped, check for symbols.
	syms, err := exe.Symbols()
	if err != nil {
		return false, fmt.Errorf("failed to read symbols: %w", err)
	}
	for _, sym := range syms {
		name := sym.Name
		if name == "runtime.main" || name == "main.main" {
			return true, nil
		}
		if name == "runtime.buildVersion" {
			return true, nil
		}
	}

	return false, nil
}
