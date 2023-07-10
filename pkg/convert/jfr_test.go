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

package convert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJFRtoPprof(t *testing.T) {
	f, err := os.Open("testdata/prof.jfr")
	require.NoError(t, err)
	defer f.Close()

	p, err := JfrToPprof(f)
	require.NoError(t, err)

	require.Equal(t, 1, len(p.SampleType))
	require.Equal(t, 248, len(p.Sample))
}

func TestGetFileName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"org/springframework/aop/framework/ReflectiveMethodInvocation",
			"org/springframework/aop/framework/ReflectiveMethodInvocation.java",
		},
		{
			"org/springframework/transaction/interceptor/TransactionInterceptor$$Lambda$1343/1301459501",
			"org/springframework/transaction/interceptor/TransactionInterceptor.java",
		},
		{
			"org/springframework/aop/framework/CglibAopProxy$DynamicAdvisedInterceptor",
			"org/springframework/aop/framework/CglibAopProxy.java",
		},
	}
	for _, test := range tests {
		result := getFileName(test.input)
		require.Equal(t, test.expected, result)
	}
}
