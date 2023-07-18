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

package runtime

import (
	"debug/elf"
	"errors"
	"fmt"
)

func IsPython(ef *elf.File) (bool, error) {
	python := false

	syms, err := ef.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return python, fmt.Errorf("failed to get symbols: %w", err)
	}
	for _, sym := range syms {
		if isPythonIdentifyingSymbol(sym.Name) {
			python = true
			break
		}
	}

	if !python {
		dynSyms, err := ef.DynamicSymbols()
		if err != nil {
			return python, fmt.Errorf("failed to get dynamic symbols: %w", err)
		}
		for _, sym := range dynSyms {
			if isPythonIdentifyingSymbol(sym.Name) {
				python = true
				break
			}
		}
	}

	return python, nil
}

/*
Python symbols to look for:

	2.7:`Py_Main`

	3.2:`Py_Main`
	3.3:`Py_Main`
	3.4:`Py_Main`
	3.5:`Py_Main`
	3.6:`Py_Main`
	3.7:`_Py_UnixMain`
	3.8:`Py_BytesMain`
	3.9:`Py_BytesMain`
	3.10:`Py_BytesMain`
	3.11:`Py_BytesMain`
*/
func isPythonIdentifyingSymbol(sym string) bool {
	return sym == "Py_Main" || sym == "_Py_UnixMain" || sym == "Py_BytesMain"
}
