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
	cases := []struct {
		name     string
		symbol   string
		expected JsSymbol
		err      error
	}{{
		name:   "internal",
		symbol: "JS:~Module.load node:internal/modules/cjs/loader:1079:33",
		expected: JsSymbol{
			FunctionName: "JS:~Module.load",
			JsLocation: JsLocation{
				File:         "node:internal/modules/cjs/loader",
				LineNumber:   1079,
				ColumnNumber: 33,
			},
		},
	}, {
		name:   "user-symbol",
		symbol: "JS:*o.fib testdata/external-sourcemap/index.js:1:114",
		expected: JsSymbol{
			FunctionName: "JS:*o.fib",
			JsLocation: JsLocation{
				File:         "testdata/external-sourcemap/index.js",
				LineNumber:   1,
				ColumnNumber: 114,
			},
		},
	}, {
		name:   "error",
		symbol: "JS:*o.fib testdata/external-sourcemap/index.js",
		err:    ErrInvalidJsSymbol,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			symbol, err := ParseJsSymbol(tc.symbol)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, symbol)
		})
	}
}

var err error

func BenchmarkParseJsSymbol(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err = ParseJsSymbol("JS:~Module.load node:internal/modules/cjs/loader:1079:33")
	}
	// Prevent the compiler from optimizing away benchmark code.
	_ = err
}
