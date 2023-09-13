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
//

package python

import (
	"testing"

	"github.com/Masterminds/semver/v3"
)

func Test_isPythonLib(t *testing.T) {
	tests := []struct {
		pathname string
		expected bool
	}{
		{"/tmp/_MEIOqzg01/libpython2.7.so.1.0", true},
		{"./libpython2.7.so", true},
		{"/usr/lib/libpython3.4d.so", true},
		{"/usr/local/lib/libpython3.8m.so", true},
		{"/usr/lib/libpython2.7u.so", true},
		{"/usr/lib/libboost_python.so", false},
		{"/usr/lib/x86_64-linux-gnu/libboost_python-py27.so.1.58.0", false},
		{"/usr/lib/libboost_python-py35.so", false},
	}

	for _, test := range tests {
		result := isPythonLib(test.pathname)
		if result != test.expected {
			t.Errorf("Expected isPythonLib(%s) to be %v, but got %v", test.pathname, test.expected, result)
		}
	}
}

func Test_interpreter_interpHeadOffset(t *testing.T) {
	tests := []struct {
		version  string
		expected uint64
		err      error
	}{
		{version: "3.7.0", expected: 24, err: nil},
		{version: "3.8.0", expected: 32, err: nil},
		{version: "3.8.5", expected: 32, err: nil},
		{version: "3.10.0", expected: 32, err: nil},
		{version: "3.11.0", expected: 40, err: nil},
		{version: "4.0.0", expected: 24, err: nil},
		{version: "2.7.0", expected: 24, err: nil},
	}

	for _, test := range tests {
		i := interpreter{version: semver.MustParse(test.version)}
		offset, err := i.interpHeadOffset()

		if err != nil && test.err == nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if err == nil && test.err != nil {
			t.Errorf("Expected error: %v", test.err)
		}
		if offset != test.expected {
			t.Errorf("Expected offset %d for version %s; got %d", test.expected, test.version, offset)
		}
	}
}

func Test_interpreter_tstateCurrentOffset(t *testing.T) {
	tests := []struct {
		version     string
		expected    uint64
		expectError bool
	}{
		{version: "3.7.0", expected: 1392, expectError: false},
		{version: "3.7.1", expected: 1392, expectError: false},
		{version: "3.7.2", expected: 1392, expectError: false},
		{version: "3.7.3", expected: 1392, expectError: false},
		{version: "3.7.4", expected: 1480, expectError: false},
		{version: "3.7.5", expected: 1480, expectError: false},
		{version: "3.8.0", expected: 1368, expectError: false},
		{version: "3.8.1", expected: 1368, expectError: false},
		{version: "3.8.2", expected: 1368, expectError: false},
		{version: "3.9.0", expected: 568, expectError: false},
		{version: "3.9.1", expected: 568, expectError: false},
		{version: "3.9.2", expected: 568, expectError: false},
		{version: "3.10.0", expected: 568, expectError: false},
		{version: "3.10.1", expected: 568, expectError: false},
		{version: "3.10.2", expected: 568, expectError: false},
		{version: "3.11.0", expected: 576, expectError: false},
		{version: "3.11.1", expected: 576, expectError: false},
		{version: "3.11.2", expected: 576, expectError: false},
	}

	for _, test := range tests {
		i := interpreter{version: semver.MustParse(test.version)}
		offset, err := i.tstateCurrentOffset()

		if test.expectError && err == nil {
			t.Errorf("Expected error for version %s", test.version)
		}
		if !test.expectError && err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if offset != test.expected {
			t.Errorf("Expected offset %d for version %s; got %d", test.expected, test.version, offset)
		}
	}
}

func Test_scanVersionBytes(t *testing.T) {
	testCases := []struct {
		input     []byte
		expected  string
		expectErr bool
	}{
		{
			input:     []byte("2.7.10 (default, Oct  6 2017, 22:29:07)"),
			expected:  "2.7.10",
			expectErr: false,
		},
		{
			input:     []byte("3.6.3 |Anaconda custom (64-bit)| (default, Oct  6 2017, 12:04:38)"),
			expected:  "3.6.3",
			expectErr: false,
		},
		{
			input:     []byte("Python 3.7.0rc1 (v3.7.0rc1:dfad352267, Jul 20 2018, 13:27:54)"),
			expected:  "3.7.0rc1",
			expectErr: false,
		},
		{
			input:     []byte("Python 3.10.0rc1 (tags/v3.10.0rc1, Aug 28 2021, 18:25:40)"),
			expected:  "3.10.0rc1",
			expectErr: false,
		},
		{
			input:     []byte("1.7.0rc1 (v1.7.0rc1:dfad352267, Jul 20 2018, 13:27:54)"),
			expectErr: true,
		},
		{
			input:     []byte("3.7 10 "),
			expectErr: true,
		},
		{
			input:     []byte("3.7.10fooboo "),
			expectErr: true,
		},
		{
			input:     []byte("2.7.15+ (default, Oct  2 2018, 22:12:08)"),
			expected:  "2.7.15",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		version, err := scanVersionBytes(tc.input)

		if tc.expectErr && err == nil {
			t.Errorf("Expected error for input '%s'", string(tc.input))
		}

		if !tc.expectErr && err != nil {
			t.Errorf("Unexpected error for input '%s': %s", string(tc.input), err.Error())
		}

		if !tc.expectErr && version != tc.expected {
			t.Errorf("Mismatched result for input '%s': expected %v, got %v", string(tc.input), tc.expected, version)
		}
	}
}

func Test_scanVersionPath(t *testing.T) {
	testCases := []struct {
		input     []byte
		expected  string
		expectErr bool
	}{
		{
			input:     []byte("/usr/local/bin/python3.7"),
			expected:  "3.7.0",
			expectErr: false,
		},
		{
			input:     []byte("/opt/anaconda3/bin/python3.8"),
			expected:  "3.8.0",
			expectErr: false,
		},
		{
			input:     []byte("/usr/bin/python2.7"),
			expected:  "2.7.0",
			expectErr: false,
		},
		{
			input:     []byte("/path/to/invalid/python"),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		version, err := scanVersionPath(tc.input)

		if tc.expectErr && err == nil {
			t.Errorf("Expected error for input '%s'", string(tc.input))
		}

		if !tc.expectErr && err != nil {
			t.Errorf("Unexpected error for input '%s': %s", string(tc.input), err.Error())
		}

		if !tc.expectErr && version != tc.expected {
			t.Errorf("Mismatched result for input '%s': expected %v, got %v", string(tc.input), tc.expected, version)
		}
	}
}
