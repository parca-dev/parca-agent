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

package ksym

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptimizedSymbolizerWorks(t *testing.T) {
	file := path.Join(t.TempDir(), "parca-agent-kernel-symbols-tests")

	writer, err := NewWriter(file, 100)
	require.NoError(t, err)

	err = writer.addSymbol("first", 0x10)
	require.NoError(t, err)

	err = writer.addSymbol("mid", 0x50)
	require.NoError(t, err)

	err = writer.addSymbol("last", 0x1200)
	require.NoError(t, err)

	err = writer.Write()
	require.NoError(t, err)

	reader, err := NewReader(file)
	require.NoError(t, err)

	_, err = reader.symbolize(0x0)
	require.Error(t, err)

	symbol, err := reader.symbolize(0x10)
	require.NoError(t, err)
	require.Equal(t, "first", symbol)

	symbol, err = reader.symbolize(0x11)
	require.NoError(t, err)
	require.Equal(t, "first", symbol)

	symbol, err = reader.symbolize(0x50)
	require.NoError(t, err)
	require.Equal(t, "mid", symbol)

	symbol, err = reader.symbolize(0x3000)
	require.NoError(t, err)
	require.Equal(t, "last", symbol)
}

func TestOptimizedSymbolizerWithNoSymbolsWorks(t *testing.T) {
	file := path.Join(t.TempDir(), "parca-agent-kernel-symbols-tests")

	writer, err := NewWriter(file, 100)
	require.NoError(t, err)

	err = writer.Write()
	require.NoError(t, err)

	reader, err := NewReader(file)
	require.NoError(t, err)

	_, err = reader.symbolize(0x10)
	require.Error(t, err)
}

func TestOptimizedSymbolizerOverwrite(t *testing.T) {
	file := path.Join(t.TempDir(), "parca-agent-kernel-symbols-tests")

	{
		writer, err := NewWriter(file, 100)
		require.NoError(t, err)

		writer.addSymbol("first", 0x10)
		writer.addSymbol("mid", 0x50)
		writer.addSymbol("last", 0x1200)
		err = writer.Write()
		require.NoError(t, err)
	}

	{
		writer, err := NewWriter(file, 100)
		require.NoError(t, err)

		writer.addSymbol("first", 0x10)
		writer.addSymbol("mid", 0x50)
		writer.addSymbol("last", 0x1200)
		err = writer.Write()
		require.NoError(t, err)
	}
}

func BenchmarkOptimizedSymbolizerWrite(t *testing.B) {
	file := path.Join(t.TempDir(), "parca-agent-kernel-symbols-tests")
	t.ReportAllocs()

	for n := 0; n < t.N; n++ {
		writer, _ := NewWriter(file, 100)
		writer.addSymbol("first", 0x10)
		writer.Write()
	}
}

func BenchmarkOptimizedSymbolizerRead(t *testing.B) {
	file := path.Join(t.TempDir(), "parca-agent-kernel-symbols-tests")
	t.ReportAllocs()

	writer, err := NewWriter(file, 100)
	require.NoError(t, err)

	writer.addSymbol("first", 0x10)
	writer.addSymbol("mid", 0x50)
	writer.addSymbol("last", 0x1200)
	writer.Write()

	reader, err := NewReader(file)
	require.NoError(t, err)

	for n := 0; n < t.N; n++ {
		symbol, err := reader.symbolize(0x150)
		require.NoError(t, err)
		require.Equal(t, "mid", symbol)
	}
}
