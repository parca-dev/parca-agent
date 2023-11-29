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
	"path/filepath"
	"strconv"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type compilerProvider struct {
	StatelessProvider
}

func (p *compilerProvider) ShouldCache() bool {
	// Uses its own cache.
	return false
}

// Compiler provides metadata for determined compiler.
func Compiler(logger log.Logger, reg prometheus.Registerer, procfs procfs.FS, cic *runtime.CompilerInfoManager) Provider {
	cache := cache.NewLRUCache[string, model.LabelSet](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "metadata_compiler"}, reg),
		512,
	)
	return &compilerProvider{
		StatelessProvider{"compiler", func(ctx context.Context, pid int) (model.LabelSet, error) {
			p, err := procfs.Proc(pid)
			if err != nil {
				return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
			}

			path, err := p.Executable()
			if err != nil {
				return nil, fmt.Errorf("failed to get executable path for PID %d: %w", pid, err)
			}

			path = filepath.Join(fmt.Sprintf("/proc/%d/root", pid), path)
			if cachedLabels, ok := cache.Get(path); ok {
				return cachedLabels, nil
			}

			compiler, err := cic.Fetch(path) // nolint:contextcheck
			if err != nil {
				return nil, fmt.Errorf("failed to get compiler info for %s: %w", path, err)
			}

			labels := model.LabelSet{
				"compiler": model.LabelValue(compiler.Type),
				"stripped": model.LabelValue(strconv.FormatBool(compiler.Stripped)),
				"static":   model.LabelValue(strconv.FormatBool(compiler.Static)),
				"buildid":  model.LabelValue(compiler.BuildID),
			}
			cache.Add(path, labels)
			return labels, nil
		}},
	}
}
