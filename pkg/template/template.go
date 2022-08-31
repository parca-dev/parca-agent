// Copyright 2022 The Parca Authors
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

package template

import (
	// Enable go:embed.
	_ "embed"
	"html/template"
	"time"

	"github.com/prometheus/common/model"
)

//go:embed statuspage.html
var StatusPageTemplateBytes []byte

var StatusPageTemplate = template.Must(template.New("statuspage").Parse(string(StatusPageTemplateBytes)))

type ActiveProfiler struct {
	Name           string
	Interval       time.Duration
	NextStartedAgo time.Duration
	Error          error
}

type DiscoveredProcess struct {
	PID      int
	Labels   model.LabelSet
	Interval time.Duration
	Errors   map[string]error
	Links    map[string]string
}

type StatusPage struct {
	ActiveProfilers []ActiveProfiler
	GetProcesses    func() map[string][]DiscoveredProcess
}
