// Copyright 2022-2024 The Parca Authors
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

package profiler

import (
	"context"
	"time"
)

// NoopProfiler does nothing. It serves as a skeleton of what other will have
// to be implemented when adding a new profiler.
type NoopProfiler struct{}

func (p *NoopProfiler) Name() string {
	return "noop-profiler"
}

func (p *NoopProfiler) Run(_ context.Context) error {
	return nil
}

func (p *NoopProfiler) Stop() {
}

func (p *NoopProfiler) LastProfileStartedAt() time.Time {
	return time.Now()
}

func (p *NoopProfiler) LastError() error {
	return nil
}

func (p *NoopProfiler) ProcessLastErrors() map[int]error {
	return map[int]error{}
}
