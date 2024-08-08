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

package config

import (
	"testing"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    *Config
		wantErr bool
	}{
		{
			input:   ``,
			want:    nil,
			wantErr: true,
		},
		{
			input: `# comment`,
			want: &Config{
				RelabelConfigs: nil,
			},
		},
		{
			input: `relabel_configs: []`,
			want: &Config{
				RelabelConfigs: []*relabel.Config{},
			},
		},
		{
			input: `relabel_configs:
- source_labels: [systemd_unit]
  regex: ""
  action: drop
`,
			want: &Config{
				RelabelConfigs: []*relabel.Config{
					{
						SourceLabels: model.LabelNames{"systemd_unit"},
						Separator:    ";",
						Regex:        relabel.MustNewRegexp(``),
						Replacement:  "$1",
						Action:       relabel.Drop,
					},
				},
			},
		},
		{
			input: `relabel_configs:
- source_labels: [app]
  regex: coolaicompany-isolate-controller
  action: keep
`,
			want: &Config{
				RelabelConfigs: []*relabel.Config{
					{
						SourceLabels: model.LabelNames{"app"},
						Separator:    ";",
						Regex:        relabel.MustNewRegexp("coolaicompany-isolate-controller"),
						Replacement:  "$1",
						Action:       relabel.Keep,
					},
				},
			},
		},
		{
			input: `"relabel_configs":
- "action": "keep"
  "regex": "parca-agent"
  "source_labels":
  - "app_kubernetes_io_name"
`,
			want: &Config{
				RelabelConfigs: []*relabel.Config{
					{
						SourceLabels: model.LabelNames{"app_kubernetes_io_name"},
						Separator:    ";",
						Regex:        relabel.MustNewRegexp("parca-agent"),
						Replacement:  "$1",
						Action:       relabel.Keep,
					},
				},
			},
		},
		{
			input: `relabel_configs:
- action: keep
  regex: parca-agent
  source_labels:
    - app_kubernetes_io_name
`,
			want: &Config{
				RelabelConfigs: []*relabel.Config{
					{
						SourceLabels: model.LabelNames{"app_kubernetes_io_name"},
						Separator:    ";",
						Regex:        relabel.MustNewRegexp("parca-agent"),
						Replacement:  "$1",
						Action:       relabel.Keep,
					},
				},
			},
		},
		{
			input: `relabel_configs:
- action: keep
  regex: parca-agent
  source_labels:
  - app.kubernetes.io/name
`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
