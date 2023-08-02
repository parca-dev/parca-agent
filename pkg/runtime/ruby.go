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
var rubyIdentifyingSymbols = [][]byte{
	[]byte("ruby_init"),
}

func IsRuby(ef *elf.File) (bool, error) {
	var (
		ruby bool
		err  error
	)

	if ruby, err = IsSymbolNameInSymbols(ef, rubyIdentifyingSymbols); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ruby, fmt.Errorf("search symbols: %w", err)
	}

	if !ruby {
		if ruby, err = IsSymbolNameInDynamicSymbols(ef, rubyIdentifyingSymbols); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return ruby, fmt.Errorf("search dynamic symbols: %w", err)
		}
	}

	return ruby, nil
}
