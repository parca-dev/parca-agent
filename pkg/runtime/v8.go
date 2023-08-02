// Copyright 2023 The Parca Authors
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

package runtime

import (
	"debug/elf"
	"errors"
	"fmt"
)

var v8IdentifyingSymbols = [][]byte{
	[]byte("InterpreterEntryTrampoline"),
}

// HACK: This is a somewhat a brittle check.
func IsV8(f *elf.File) (bool, error) {
	var (
		isV8 bool
		err  error
	)

	if isV8, err = IsSymbolNameInSymbols(f, v8IdentifyingSymbols); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return isV8, fmt.Errorf("search symbols: %w", err)
	}

	return isV8, nil
}
