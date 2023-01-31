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

package metadata

import (
	"debug/elf"
	"fmt"
	"sync"

	burrow "github.com/goburrow/cache"
	"github.com/keybase/go-ps"
	"github.com/prometheus/common/model"
	"github.com/xyproto/ainur"

	"github.com/parca-dev/parca-agent/pkg/buildid"
)

var (
	c            burrow.Cache
	onceCompiler sync.Once
)

func initialiseCache() {
	c = burrow.New(burrow.WithMaximumSize(128))
}

type compilerProvider struct {
	StatelessProvider
}

func (p *compilerProvider) ShouldCache() bool {
	return false
}

// Compiler provides metadata for determined compiler.
func Compiler() Provider {
	onceCompiler.Do(initialiseCache)

	return &compilerProvider{
		StatelessProvider{"compiler", func(pid int) (model.LabelSet, error) {
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
			elf, err := elf.Open(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open ELF file for process %d: %w", pid, err)
			}
			defer elf.Close()

			buildID, err := buildid.BuildID(&buildid.ElfFile{Path: path, File: elf})
			if err != nil {
				return nil, fmt.Errorf("buildID failed")
			}

			value, ok := c.GetIfPresent(buildID)
			if ok {
				cachedLabels, ok := value.(model.LabelSet)
				if !ok {
					panic("The buildID cache contained the wrong type. This should never happen")
				}
				return cachedLabels, nil
			}

			labels := model.LabelSet{
				"compiler": model.LabelValue(ainur.Compiler(elf)),
				"stripped": model.LabelValue(fmt.Sprintf("%t", ainur.Stripped(elf))),
				"static":   model.LabelValue(fmt.Sprintf("%t", ainur.Static(elf))),
			}

			c.Put(buildID, labels)
			return labels, nil
		}},
	}
}
