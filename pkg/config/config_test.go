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

package config_test

import (
	"testing"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/config"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	c, err := config.Load(`relabel_configs:
- source_labels: [systemd_unit]
  regex: ""
  action: drop
`)
	require.NoError(t, err)
	require.Equal(t, &config.Config{
		RelabelConfigs: []*relabel.Config{
			{
				SourceLabels: model.LabelNames{"systemd_unit"},
				Separator:    ";",
				Regex:        relabel.MustNewRegexp(``),
				Replacement:  "$1",
				Action:       relabel.Drop,
			},
		},
	}, c)
}
