// Copyright 2023 The Parca Authors
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

package js

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseJsSymbol(t *testing.T) {
	symbol := "JS:*o.fib testdata/external-sourcemap/index.js:1:114"
	jsSymbol, err := ParseJsSymbol(symbol)
	require.NoError(t, err)

	require.Equal(t, "JS:*o.fib", jsSymbol.FunctionName)
	require.Equal(t, "testdata/external-sourcemap/index.js", jsSymbol.File)
	require.Equal(t, 1, jsSymbol.LineNumber)
	require.Equal(t, 114, jsSymbol.ColumnNumber)
}

func TestParseJsSymbolError(t *testing.T) {
	symbol := "JS:*o.fib testdata/external-sourcemap/index.js"
	_, err := ParseJsSymbol(symbol)
	require.ErrorIs(t, err, ErrInvalidJsSymbol)
}
