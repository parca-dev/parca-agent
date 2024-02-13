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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnyStackContains(t *testing.T) {
	// Edge cases.
	require.True(t, AnyStackContains([][]string{{"a", "b"}}, []string{}))
	require.False(t, AnyStackContains([][]string{{}}, []string{"a", "b"}))

	// Equality and containment.
	require.True(t, AnyStackContains([][]string{{"a", "b"}}, []string{"a", "b"}))
	require.True(t, AnyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "b"}))
	require.True(t, AnyStackContains([][]string{{"a", "b"}, {"a", "c"}}, []string{"a", "c"}))
	require.True(t, AnyStackContains([][]string{{"main"}, {"a", "b"}}, []string{"a", "b"}))

	// Sad path.
	require.False(t, AnyStackContains([][]string{{"a", "b"}}, []string{"a", "c"}))
	require.False(t, AnyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "c"}))
	require.False(t, AnyStackContains([][]string{{"a", "b"}}, []string{"a", "b", "c"}))
}
