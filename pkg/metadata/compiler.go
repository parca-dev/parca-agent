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
	cache := cache.NewLRUCache[string, model.LabelSet](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "metadata_compiler"}, reg),
		512,
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
			if cachedLabels, ok := cache.Get(path); ok {
				return cachedLabels, nil
			}

			obj, err := objFilePool.Open(path)
			if err != nil {
				return nil, fmt.Errorf("failed to open ELF file for process %d: %w", pid, err)
			}

			ef, err := obj.ELF()
			if err != nil {
				return nil, fmt.Errorf("failed to get ELF file for process %d: %w", pid, err)
			}

			labels := model.LabelSet{
				"compiler": model.LabelValue(ainur.Compiler(ef)),
				"stripped": model.LabelValue(fmt.Sprintf("%t", ainur.Stripped(ef))),
				"static":   model.LabelValue(fmt.Sprintf("%t", ainur.Static(ef))),
				"buildid":  model.LabelValue(obj.BuildID),
			}
			cache.Add(path, labels)
			return labels, nil
		}},
	}
}
