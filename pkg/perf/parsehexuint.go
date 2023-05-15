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

package perf

import "errors"

func parseHexToUint64(hexStr []byte) (uint64, error) {
	length := len(hexStr)
	if length > 16 {
		return 0, errors.New("input too long")
	}

	var result uint64
	for i := 0; i < length; i++ {
		result <<= 4
		char := hexStr[i]
		switch {
		case char >= '0' && char <= '9':
			result |= uint64(char - '0')
		case char >= 'a' && char <= 'f':
			result |= uint64(char-'a') + 10
		case char >= 'A' && char <= 'F':
			result |= uint64(char-'A') + 10
		default:
			return 0, errors.New("invalid character")
		}
	}

	return result, nil
}
