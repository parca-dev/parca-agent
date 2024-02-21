// Copyright 2023-2024 The Parca Authors
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

package metadata

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHost(t *testing.T) {
	testData := `
# Kubernetes-managed hosts file.
127.0.0.1       localhost

10.14.218.32    parca-agent-25q5t
`
	result, err := parseHosts(strings.NewReader(testData))
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, []hostEntry{
		{
			ip:       "127.0.0.1",
			hostname: "localhost",
		},
		{
			ip:       "10.14.218.32",
			hostname: "parca-agent-25q5t",
		},
	}, result)
}
