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
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-kit/log"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/xyproto/ainur"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type compilerProvider struct {
	StatelessProvider
}

func (p *compilerProvider) ShouldCache() bool {
	// Uses its own cache.
	return false
}

// Compiler provides metadata for determined compiler.
func Compiler(logger log.Logger, reg prometheus.Registerer, objFilePool *objectfile.Pool) Provider {
	cache := burrow.New(
		burrow.WithMaximumSize(128),
		burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "metadata_compiler")),
	)

	return &compilerProvider{
		StatelessProvider{"compiler", func(ctx context.Context, pid int) (model.LabelSet, error) {
			// do not use filepath.EvalSymlinks
			// it will return error if exe not existed in / directory
			// but in /proc/pid/root directory
			path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				return nil, fmt.Errorf("failed to get path for process %d: %w", pid, err)
			}

			path = filepath.Join(fmt.Sprintf("/proc/%d/root", pid), path)
			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open file for process %d: %w", pid, err)
			}
			defer f.Close()

			objFile, err := objFilePool.NewFile(f)
			if err != nil {
				return nil, fmt.Errorf("failed to open ELF file for process %d: %w", pid, err)
			}

			buildID := objFile.BuildID
			value, ok := cache.GetIfPresent(buildID)
			if ok {
				cachedLabels, ok := value.(model.LabelSet)
				if !ok {
					panic("The buildID cache contained the wrong type. This should never happen")
				}
				return cachedLabels, nil
			}

			ef, err := objFile.ELF()
			if err != nil {
				return nil, fmt.Errorf("failed to get ELF file for process %d: %w", pid, err)
			}
			labels := model.LabelSet{
				"compiler": model.LabelValue(ainur.Compiler(ef)),
				"stripped": model.LabelValue(fmt.Sprintf("%t", ainur.Stripped(ef))),
				"static":   model.LabelValue(fmt.Sprintf("%t", ainur.Static(ef))),
			}

			cache.Put(buildID, labels)
			return labels, nil
		}},
	}
}
