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

	"github.com/pyroscope-io/jfr-parser/parser"
)

func TestJFRtoPprof(t *testing.T) {
	f, err := os.Open("testdata/prof.jfr")
	require.NoError(t, err)
	defer f.Close()

	p, err := JfrToPprof(f)
	require.NoError(t, err)

	require.Equal(t, 1, len(p.SampleType))
	require.Equal(t, 260, len(p.Sample))
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
	b := newBuilder()
	for _, test := range tests {
		result := b.getFileName(test.input)
		require.Equal(t, test.expected, result)
	}
}

func TestParseObjectClass(t *testing.T) {
	testCases := []struct {
		in       string
		expected string
	}{
		{
			in:       "[C",
			expected: "char[]",
		},
		{
			in:       "java.nio.HeapCharBuffer",
			expected: "java.nio.HeapCharBuffer",
		},
		{
			in:       "[Ljava/lang/Object;",
			expected: "java/lang/Object[]",
		},
	}
	for _, testCase := range testCases {
		got := parseObjectClass(testCase.in)
		require.Equal(t, testCase.expected, got)
	}
}

func TestParseArgs(t *testing.T) {
	testCases := []struct {
		in       string
		expected string
	}{
		{
			in:       "(Ljava/util/concurrent/ThreadPoolExecutor$Worker;)V",
			expected: "(ThreadPoolExecutor$Worker)",
		},
		{
			in:       "(ZJ)V",
			expected: "(boolean, long)",
		},
		{
			in:       "(Lorg/apache/kafka/common/utils/Timer;Lorg/apache/kafka/clients/consumer/internals/ConsumerNetworkClient$PollCondition;Z)V",
			expected: "(Timer, ConsumerNetworkClient$PollCondition, boolean)",
		},
		{
			in:       "()V",
			expected: "()",
		},
		{
			in:       "([Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
			expected: "(String[], String, ClassLoader)",
		},
	}
	b := newBuilder()
	for _, testCase := range testCases {
		got := b.parseArgs(testCase.in)
		require.Equal(t, testCase.expected, got)
	}
}

func BenchmarkChunksToPprof(b *testing.B) {
	f, err := os.Open("./testdata/prof.jfr")
	if err != nil {
		b.Error(err)
	}
	chunks, _ := parser.Parse(f)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err = chunksToPprof(chunks)
		if err != nil {
			b.Error(err)
		}
	}
}
