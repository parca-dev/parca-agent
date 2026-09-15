// Copyright 2026 The Parca Authors
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
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCgroupString(t *testing.T) {
	t.Run("v2 unified hierarchy", func(t *testing.T) {
		cg, err := parseCgroupString("0::/system.slice/docker.service")
		require.NoError(t, err)
		require.Equal(t, 0, cg.hierarchyID)
		require.Empty(t, cg.controllers)
		require.Equal(t, "/system.slice/docker.service", cg.path)
	})

	t.Run("v1 with controllers", func(t *testing.T) {
		cg, err := parseCgroupString("4:cpu,cpuacct:/user.slice")
		require.NoError(t, err)
		require.Equal(t, 4, cg.hierarchyID)
		require.Equal(t, []string{"cpu", "cpuacct"}, cg.controllers)
		require.Equal(t, "/user.slice", cg.path)
	})

	t.Run("a path containing colons is not split further", func(t *testing.T) {
		cg, err := parseCgroupString("1:name=systemd:/foo:bar")
		require.NoError(t, err)
		require.Equal(t, "/foo:bar", cg.path)
	})

	t.Run("too few fields", func(t *testing.T) {
		_, err := parseCgroupString("0:/system.slice")
		require.ErrorIs(t, err, ErrFileParse)
	})

	// The error has to name the input that failed. It used to format the
	// parsed hierarchy ID, an int, with %q -- which renders as a rune literal
	// and, on this path, is always the zero value strconv.Atoi returned. Every
	// malformed line produced the same unusable "hierarchy ID: '\x00'".
	t.Run("non-numeric hierarchy ID", func(t *testing.T) {
		_, err := parseCgroupString("notanumber::/system.slice")
		require.ErrorIs(t, err, ErrFileParse)
		require.ErrorIs(t, err, strconv.ErrSyntax,
			"the cause from strconv must not be swallowed")
		require.Contains(t, err.Error(), `"notanumber"`,
			"the error must quote the offending input")
		require.NotContains(t, err.Error(), `\x00`)
	})
}

func TestParseCgroups(t *testing.T) {
	cgroups, err := parseCgroups([]byte("12:pids:/init.scope\n4:cpu,cpuacct:/user.slice\n0::/system.slice\n"))
	require.NoError(t, err)
	require.Len(t, cgroups, 3)
	require.Equal(t, 12, cgroups[0].hierarchyID)
	require.Equal(t, "/system.slice", cgroups[2].path)

	// One bad line fails the whole file rather than silently dropping a
	// hierarchy, so the error surfaces at the caller.
	_, err = parseCgroups([]byte("12:pids:/init.scope\nbad line\n"))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileParse))
}
