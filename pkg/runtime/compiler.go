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

package runtime

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xyproto/ainur"
	"golang.org/x/sync/semaphore"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type Compiler struct {
	Runtime

	Type     string
	BuildID  string
	Stripped bool
	Static   bool
}

// TODO(kakkoyun): Consider moving this to the ProcessInfoManager.
// Requires FramePointerCache to be moved as well.

// CompilerInfoManager is a cache for compiler information.
// Fetching this information is expensive, so we cache it.
// The cache is safe for concurrent use.
// It also controls throughput of fetches.
type CompilerInfoManager struct {
	p *objectfile.Pool
	c *cache.Cache[string, *Compiler]

	tokens *semaphore.Weighted
}

func NewCompilerInfoManager(reg prometheus.Registerer, objFilePool *objectfile.Pool) *CompilerInfoManager {
	cores := runtime.NumCPU()
	return &CompilerInfoManager{
		p: objFilePool,
		c: cache.NewLFUCache[string, *Compiler](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "runtime_compiler_info"}, reg),
			2048,
		),
		tokens: semaphore.NewWeighted(int64(cores/2) + 1),
	}
}

func (c *CompilerInfoManager) Fetch(path string) (*Compiler, error) {
	if compiler, ok := c.c.Get(path); ok {
		return compiler, nil
	}

	obj, err := c.p.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file %s: %w", path, err)
	}

	ef, err := obj.ELF()
	if err != nil {
		return nil, fmt.Errorf("failed to get ELF file %s: %w", path, err)
	}

	// Prevent too many concurrent fetches.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.tokens.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("failed to acquire semaphore token: %w", err)
	}
	defer c.tokens.Release(1)

	cType := ainur.Compiler(ef)
	compiler := &Compiler{
		Runtime: Runtime{
			Name:    RuntimeName(name(cType)),
			Version: version(cType),
		},
		Type:     cType,
		Static:   ainur.Static(ef),
		Stripped: ainur.Stripped(ef),
		BuildID:  obj.BuildID,
	}
	c.c.Add(path, compiler)
	return compiler, nil
}

func name(cType string) string {
	parts := strings.Split(cType, " ")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "unknown"
}

func version(cType string) *semver.Version {
	parts := strings.Split(cType, " ")
	if len(parts) < 2 {
		return nil
	}
	ver, err := semver.NewVersion(parts[1])
	if err != nil {
		return nil
	}
	return ver
}
