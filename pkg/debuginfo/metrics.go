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

package debuginfo

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metrics struct {
	uploadSuccess prometheus.Counter
	uploadFailure prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	return &metrics{
		uploadSuccess: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "parca_agent_debuginfo_upload_total",
				Help: "Number of debuginfo successfully uploaded",
			},
		),
		uploadFailure: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "parca_agent_debuginfo_upload_failed_total",
				Help: "Number of failed debuginfo uploads",
			},
		),
	}
}
