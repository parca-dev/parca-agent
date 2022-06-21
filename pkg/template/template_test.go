// Copyright 2021 The Parca Authors
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
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
)

func TestStatusPageTemplate(t *testing.T) {
	expected, err := os.ReadFile("testdata/statuspage.html")
	require.NoError(t, err)

	res := bytes.NewBuffer(nil)
	err = StatusPageTemplate.Execute(res, &StatusPage{
		ActiveProfilers: []ActiveProfiler{{
			Type: "test_profile_type",
			Labels: []labels.Label{{
				Name:  "name1",
				Value: "value1",
			}, {
				Name:  "name2",
				Value: "value2",
			}},
			Interval:       time.Second * 10,
			NextStartedAgo: time.Second * 3,
			Error:          errors.New("test"),
			Link:           "/test123",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, string(expected), res.String())
}
