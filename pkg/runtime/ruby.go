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

func IsRuby(ef *elf.File) (bool, error) {
	ruby := false

	syms, err := ef.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ruby, fmt.Errorf("failed to get symbols: %w", err)
	}
	for _, sym := range syms {
		if isRubyIdentifyingSymbol(sym.Name) {
			ruby = true
			break
		}
	}

	if !ruby {
		dynSyms, err := ef.DynamicSymbols()
		if err != nil {
			return ruby, fmt.Errorf("failed to get dynamic symbols: %w", err)
		}
		for _, sym := range dynSyms {
			if isRubyIdentifyingSymbol(sym.Name) {
				ruby = true
				break
			}
		}
	}

	return ruby, nil
}

/*
Ruby symbols to look for:

	1.9:`ruby_init` and `ruby_current_vm`
	2.0:`ruby_init` and `ruby_current_vm`
	2.1:`ruby_init`
	2.2:`ruby_init`
	2.3:`ruby_init`
	2.4:`ruby_init`
	2.5:`ruby_init`
	2.6:`ruby_init`
	2.7:`ruby_init`

	3.0:`ruby_init`
	3.1:`ruby_init`
	3.2:`ruby_init`
	3.3-preview1:`ruby_init`
*/
func isRubyIdentifyingSymbol(sym string) bool {
	return sym == "ruby_init"
}
