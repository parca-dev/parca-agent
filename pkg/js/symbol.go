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
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidJsSymbol = errors.New("invalid JS symbol")

func IsJsSymbol(symbol string) bool {
	return strings.HasPrefix(symbol, "JS:") ||
		strings.HasPrefix(symbol, "Function:") ||
		strings.HasPrefix(symbol, "LazyCompile:")
}

type JsSymbol struct {
	FunctionName string
	JsLocation
}

type JsLocation struct {
	File         string
	LineNumber   int
	ColumnNumber int
}

func ParseJsSymbol(symbol string) (JsSymbol, error) {
	index := strings.IndexByte(symbol, ' ')
	if index == -1 {
		return JsSymbol{}, fmt.Errorf("invalid symbol not made of two parts: %w", ErrInvalidJsSymbol)
	}

	functionName := symbol[:index]
	rest := symbol[index+1:]

	index = strings.IndexByte(rest, ':')
	if index == -1 {
		return JsSymbol{}, fmt.Errorf("invalid location not made of two parts: %w", ErrInvalidJsSymbol)
	}

	if rest[:index] == "node" {
		// The "file" is of the form "node:internal/modules/cjs/loader.js"
		prevIndex := index
		index = strings.IndexByte(rest[index+1:], ':')
		if index == -1 {
			// No line or column number
			return JsSymbol{
				FunctionName: functionName,
				JsLocation: JsLocation{
					File: rest,
				},
			}, nil
		}

		// We need to set the index on the colon.
		index += prevIndex + 1
	}

	// We've got a filename of the form "file.js:123:456" or "file.js:123", and
	// the index is already set on the colon. If the filename started with
	// "node:", then the index is set on the second colon.
	file := rest[:index]

	// Rest is now either empty or ":123:456" or ":123"
	rest = rest[index+1:]
	if rest == "" {
		return JsSymbol{
			FunctionName: functionName,
			JsLocation: JsLocation{
				File: file,
			},
		}, nil
	}

	index = strings.IndexByte(rest, ':')

	var (
		lineNumber, columnNumber int
		err                      error
	)
	if index != -1 {
		lineNumber, err = parseBase10(rest[:index])
		if err != nil {
			return JsSymbol{}, fmt.Errorf("invalid line number: %w", ErrInvalidJsSymbol)
		}

		columnNumber, err = parseBase10(rest[index+1:])
		if err != nil {
			return JsSymbol{}, fmt.Errorf("invalid column number: %w", ErrInvalidJsSymbol)
		}
	} else {
		lineNumber, err = parseBase10(rest)
		if err != nil {
			return JsSymbol{}, fmt.Errorf("invalid line number (no column number, %q): %w", rest, ErrInvalidJsSymbol)
		}
	}

	return JsSymbol{
		FunctionName: functionName,
		JsLocation: JsLocation{
			File:         file,
			LineNumber:   lineNumber,
			ColumnNumber: columnNumber,
		},
	}, nil
}

const (
	zero = '0'
	nine = '9'
)

func parseBase10(s string) (int, error) {
	var result int

	for i := 0; i < len(s); i++ {
		if s[i] < zero || s[i] > nine {
			return 0, fmt.Errorf("invalid character at position %d: %c", i, s[i])
		}

		result = result*10 + int(s[i]-zero)
	}

	return result, nil
}
