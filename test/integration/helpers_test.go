package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
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

type convertConfig struct {
	lineNumbers, sampleTypes bool
}

func convertToFolded(profile *pprofprofile.Profile, cfgs ...*convertConfig) (string, error) {
	// Original code: https://github.com/felixge/pprofutils/blob/4ab5689918f23a12d358a09e89bd206b4e1dcb26/internal/legacy/protobuf.go
	// The MIT License (MIT)
	// Copyright © 2021 Felix Geisendörfer <felix@felixge.de>

	if len(cfgs) == 0 {
		cfgs = append(cfgs, &convertConfig{})
	}
	cfg := cfgs[0]

	var (
		in  bytes.Buffer
		out bytes.Buffer
	)
	if err := profile.Write(&in); err != nil {
		return "", err
	}

	w := bufio.NewWriter(&out)
	if cfg.sampleTypes {
		var sampleTypes []string
		for _, sampleType := range profile.SampleType {
			sampleTypes = append(sampleTypes, sampleType.Type+"/"+sampleType.Unit)
		}
		w.WriteString(strings.Join(sampleTypes, " ") + "\n")
	}
	if err := profile.Aggregate(true, true, false, cfg.lineNumbers, false, false); err != nil {
		return "", err
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
				if cfg.lineNumbers {
					name = name + ":" + strconv.FormatInt(line.Line, 10)
				}
				frames = append(frames, name)
			}
		}
		var values []string
		for _, val := range sample.Value {
			values = append(values, fmt.Sprintf("%d", val))
			if !cfg.sampleTypes {
				break
			}
		}
		fmt.Fprintf(
			w,
			"%s %s\n",
			strings.Join(frames, ";"),
			strings.Join(values, " "),
		)
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	return out.String(), nil
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
