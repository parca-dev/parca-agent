// Copyright (c) 2022 The Parca Authors
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

package metadata

import (
	"debug/elf"
	"fmt"

	"github.com/keybase/go-ps"
	"github.com/prometheus/common/model"
	"github.com/xyproto/ainur"
)

// Compiler provides metadata for determined compiler.
func Compiler() *Provider {
	return &Provider{"compiler", func(pid int) (model.LabelSet, error) {
		process, err := ps.FindProcess(pid)
		if err != nil {
			return nil, err
		}
		if process == nil {
			return nil, fmt.Errorf("process %d not found", pid)
		}

		path, err := process.Path()
		if err != nil {
			return nil, fmt.Errorf("failed to get path for process %d: %w", pid, err)
		}
		file, err := elf.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open ELF file for process %d: %w", pid, err)
		}
		defer file.Close()

		return model.LabelSet{
			"executable": model.LabelValue(process.Executable()),
			"compiler":   model.LabelValue(ainur.Compiler(file)),
			"stripped":   model.LabelValue(fmt.Sprintf("%t", ainur.Stripped(file))),
			"static":     model.LabelValue(fmt.Sprintf("%t", ainur.Static(file))),
		}, nil
	}}
}
