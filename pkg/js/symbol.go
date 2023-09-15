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
	"strconv"
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
	parts := strings.Split(symbol, " ")
	if len(parts) != 2 {
		return JsSymbol{}, fmt.Errorf("invalid symbol not made of two parts: %w", ErrInvalidJsSymbol)
	}

	functionName := parts[0]
	location := parts[1]
	parts = strings.Split(location, ":")
	expectedMaxParts := 3
	file := parts[0]
	if strings.HasPrefix(location, "node:") {
		file += ":" + parts[1]
		expectedMaxParts = 4
	}

	if len(parts) < expectedMaxParts || len(parts) > expectedMaxParts {
		return JsSymbol{}, fmt.Errorf("invalid location unexpected number of parts: %w", ErrInvalidJsSymbol)
	}

	lineNumber, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil {
		return JsSymbol{}, fmt.Errorf("invalid line number: %w", ErrInvalidJsSymbol)
	}

	columnNumber := 0
	if len(parts) == expectedMaxParts {
		columnNumber, err = strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			return JsSymbol{}, fmt.Errorf("invalid column number: %w", ErrInvalidJsSymbol)
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
