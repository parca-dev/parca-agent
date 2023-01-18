// Copyright 2022 The Parca Authors
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

package executable

import (
	"debug/elf"
	"fmt"
)

// IsASLRElegible returns whether the elf executable could be elegible for
// address space layout randomization (ASLR).
//
// Whether to enable ASLR for a process is decided in this kernel code
// path (https://github.com/torvalds/linux/blob/v5.0/fs/binfmt_elf.c#L955).
//
// Note(javierhonduco): This check is a bit simplistic and might not work
// for every case. We might want to check across multiple kernels. It probably
// won't be correct for the dynamic loader itself. See link above.
func IsASLRElegible(path string) (bool, error) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed opening elf file with %w", err)
	}
	defer elfFile.Close()

	return elfFile.FileHeader.Type == elf.ET_DYN, nil
}
