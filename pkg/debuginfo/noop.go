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
package debuginfo

import (
	"context"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type NoopDebuginfoManager struct{}

func (NoopDebuginfoManager) ExtractOrFindDebugInfo(context.Context, string, *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	return nil, nil //nolint:nilnil
}

func (NoopDebuginfoManager) Upload(context.Context, *objectfile.ObjectFile) error { return nil }

func (NoopDebuginfoManager) Close() error { return nil }
