// Copyright 2024 The Parca Authors
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

package integration

import (
	"sort"
	"testing"

	pprofprofile "github.com/google/pprof/profile"
	"github.com/stretchr/testify/require"
)

// requireAnyStackContains asserts that the given stack is contained in any of the given stacks.
func requireAnyStackContains(t *testing.T, foundStacks [][]string, stack []string) {
	t.Helper()

	if !anyStackContains(foundStacks, stack) {
		t.Fatal("The stack", stack, "is not contained in any of", foundStacks)
	}
}

// anyStackContains returns whether the passed string slice is contained
// in any of the slice of string slices. This is used to ensure that a
// stacktrace is contained in a given profile.
func anyStackContains(foundStacks [][]string, stack []string) bool {
	foundEqualSubslice := false

	for _, foundStack := range foundStacks {
		if len(stack) > len(foundStack) {
			continue
		}

		for s := 0; s < len(foundStack)-len(stack)+1; s++ {
			equal := true
			subSlice := foundStack[s:]
			for i := range stack {
				if stack[i] != subSlice[i] {
					equal = false
					break
				}
			}
			if equal {
				foundEqualSubslice = true
				break
			}
		}
	}

	return foundEqualSubslice
}

// aggregateStacks aggregates the stacks of the given samples into a single slice.
func aggregateStacks(profile *pprofprofile.Profile) ([][]string, error) {
	aggregatedStacks := make([][]string, 0)

	if err := profile.Aggregate(true, true, false, false, false, false); err != nil {
		return nil, err
	}
	profile = profile.Compact()
	sort.Slice(profile.Sample, func(i, j int) bool {
		return profile.Sample[i].Value[0] > profile.Sample[j].Value[0]
	})
	for _, sample := range profile.Sample {
		var frames []string
		for i := range sample.Location {
			loc := sample.Location[len(sample.Location)-i-1]
			for j := range loc.Line {
				line := loc.Line[len(loc.Line)-j-1]
				name := line.Function.Name
				frames = append(frames, name)
			}
		}
		aggregatedStacks = append(aggregatedStacks, frames)
	}

	return aggregatedStacks, nil
}

func TestAnyStackContains(t *testing.T) {
	// Edge cases.
	require.True(t, anyStackContains([][]string{{"a", "b"}}, []string{}))
	require.False(t, anyStackContains([][]string{{}}, []string{"a", "b"}))

	// Equality and containment.
	require.True(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "b"}))
	require.True(t, anyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "b"}))
	require.True(t, anyStackContains([][]string{{"a", "b"}, {"a", "c"}}, []string{"a", "c"}))
	require.True(t, anyStackContains([][]string{{"main"}, {"a", "b"}}, []string{"a", "b"}))

	// Sad path.
	require.False(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "c"}))
	require.False(t, anyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "c"}))
	require.False(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "b", "c"}))
}
