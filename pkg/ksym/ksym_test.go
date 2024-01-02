// Copyright 2022-2024 The Parca Authors
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
	"bytes"
	"errors"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

// Prevent the compiler from optimizing the benchmark out.
var result string

func ParseFunctionNamesWithString(lines [][]byte) {
	// Prevent the compiler from optimizing the operation out.
	var r string
	for _, line := range lines {
		r = string(line[:16])
	}

	result = r
}

func ParseFunctionNamesWithUnsafe(lines [][]byte) {
	// Prevent the compiler from optimizing the operation out.
	var r string
	for _, line := range lines {
		r = unsafeString(line[:16])
	}

	result = r
}

func BenchmarkStringParsing(b *testing.B) {
	procKallSyms := []byte(`ffffffff8f6d1140 a udp_bpf_prots
	ffffffff8f6d1480 a udpv6_prot_lock
	ffffffff8f6d1488 a cipso_v4_rbm_optfmt
	ffffffff8f6d1490 a cipso_v4_cache
	ffffffff8f6d1498 a cipso_v4_doi_list_lock
	ffffffff8f6d149c b __key.2
	ffffffff8f6d14a0 a sock_id
	ffffffff8f6d14a4 a tcp_sock_id
	ffffffff8f6d14a8 a tcp_sock_type
	ffffffff8f6d14c0 a dummy.1
	ffffffff8f6d14c0 a __key.0
	ffffffff8f6d1510 a idx_generator.4
	ffffffff8f6d1520 a xfrm_policy_inexact_table
	ffffffff8f6d15a8 a xfrm_policy_afinfo_lock
	ffffffff8f6d15ac a xfrm_if_cb_lock
	ffffffff8f6d15c0 a acqseq.0
	ffffffff8f6d15d0 a saddr_wildcard.4
	ffffffff8f6d15e0 a xfrm_km_lock
	ffffffff8f6d15e4 a xfrm_state_gc_lock
	ffffffff8f6d1600 T xfrm_state_afinfo
	ffffffff8f6d1768 t xfrm_state_afinfo_lock
	ffffffff8f6d1770 b xfrm_state_gc_list
	ffffffff8f6d1780 D xfrm_napi_dev
	ffffffff8f6d15c4 a not_in_order`)

	lines := bytes.Split(procKallSyms, []byte("\n"))
	for n := 0; n < b.N; n++ {
		ParseFunctionNamesWithString(lines)
	}
}

func BenchmarkUnsafeString(b *testing.B) {
	procKallSyms := []byte(`ffffffff8f6d1140 a udp_bpf_prots
	ffffffff8f6d1480 a udpv6_prot_lock
	ffffffff8f6d1488 a cipso_v4_rbm_optfmt
	ffffffff8f6d1490 a cipso_v4_cache
	ffffffff8f6d1498 a cipso_v4_doi_list_lock
	ffffffff8f6d149c b __key.2
	ffffffff8f6d14a0 a sock_id
	ffffffff8f6d14a4 a tcp_sock_id
	ffffffff8f6d14a8 a tcp_sock_type
	ffffffff8f6d14c0 a dummy.1
	ffffffff8f6d14c0 a __key.0
	ffffffff8f6d1510 a idx_generator.4
	ffffffff8f6d1520 a xfrm_policy_inexact_table
	ffffffff8f6d15a8 a xfrm_policy_afinfo_lock
	ffffffff8f6d15ac a xfrm_if_cb_lock
	ffffffff8f6d15c0 a acqseq.0
	ffffffff8f6d15d0 a saddr_wildcard.4
	ffffffff8f6d15e0 a xfrm_km_lock
	ffffffff8f6d15e4 a xfrm_state_gc_lock
	ffffffff8f6d1600 T xfrm_state_afinfo
	ffffffff8f6d1768 t xfrm_state_afinfo_lock
	ffffffff8f6d1770 b xfrm_state_gc_list
	ffffffff8f6d1780 D xfrm_napi_dev
	ffffffff8f6d15c4 a not_in_order`)

	lines := bytes.Split(procKallSyms, []byte("\n"))
	for n := 0; n < b.N; n++ {
		ParseFunctionNamesWithUnsafe(lines)
	}
}

func TestKsym(t *testing.T) {
	c := NewKsym(
		log.NewNopLogger(),
		prometheus.NewRegistry(),
		t.TempDir(),
		testutil.NewFakeFS(
			map[string][]byte{
				"/proc/kallsyms": []byte(`
ffffffff8f6d1140 a udp_bpf_prots
ffffffff8f6d1480 a udpv6_prot_lock
ffffffff8f6d1488 a cipso_v4_rbm_optfmt
ffffffff8f6d1490 a cipso_v4_cache
ffffffff8f6d1498 a cipso_v4_doi_list_lock
ffffffff8f6d149c b __key.2
ffffffff8f6d14a0 a sock_id
ffffffff8f6d14a4 a tcp_sock_id
ffffffff8f6d14a8 a tcp_sock_type
ffffffff8f6d14c0 a dummy.1
ffffffff8f6d14c0 a __key.0
ffffffff8f6d1510 a idx_generator.4
ffffffff8f6d1520 a xfrm_policy_inexact_table
ffffffff8f6d15a8 a xfrm_policy_afinfo_lock
ffffffff8f6d15ac a xfrm_if_cb_lock
ffffffff8f6d15c0 a acqseq.0
ffffffff8f6d15d0 a saddr_wildcard.4
ffffffff8f6d15e0 a xfrm_km_lock
ffffffff8f6d15e4 a xfrm_state_gc_lock
ffffffff8f6d1600 T xfrm_state_afinfo
ffffffff8f6d1768 t xfrm_state_afinfo_lock
ffffffff8f6d1770 b xfrm_state_gc_list
ffffffff8f6d1780 D xfrm_napi_dev
ffffffff8f6d15c4 a not_in_order
		`),
			}))

	addr1 := uint64(0xffffffff8f6d14a4)
	addr2 := uint64(0xffffffff8f6d15e0)
	addr3 := uint64(0xffffffff8f6d1480)
	addrNotInOrder := uint64(0xffffffff8f6d15c4)
	addrFirst := uint64(0xffffffff8f6d1140)

	// Test addresses at function_start_addr + 1.
	syms, err := c.Resolve(map[uint64]struct{}{
		addr1 + 1: {},
		addr2 + 1: {},
	})
	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1 + 1: "tcp_sock_id",
		addr2 + 1: "xfrm_km_lock",
	}, syms)

	syms, err = c.Resolve(map[uint64]struct{}{
		addr1 + 1: {},
		addr2 + 1: {},
		addr3 + 1: {},
	})
	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1 + 1: "tcp_sock_id",
		addr2 + 1: "xfrm_km_lock",
		addr3 + 1: "udpv6_prot_lock",
	}, syms)

	// Test exact matches.
	syms, err = c.Resolve(map[uint64]struct{}{
		addr1: {},
		addr2: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
	}, syms)

	// Test first address.
	syms, err = c.Resolve(map[uint64]struct{}{
		addrFirst: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addrFirst: "udp_bpf_prots",
	}, syms)

	syms, err = c.Resolve(map[uint64]struct{}{
		addrFirst + 1: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addrFirst + 1: "udp_bpf_prots",
	}, syms)

	// Test address not in order.
	syms, err = c.Resolve(map[uint64]struct{}{
		addrNotInOrder: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addrNotInOrder: "not_in_order",
	}, syms)

	// Test address that doesn't belong to the address space.
	syms, err = c.Resolve(map[uint64]struct{}{
		0x1000: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{}, syms)

	// Test that the second time should be served from cache.
	c.fs = testutil.NewErrorFS(errors.New("not served from cache"))
	syms, err = c.Resolve(map[uint64]struct{}{
		addr1 + 1: {},
		addr2 + 1: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1 + 1: "tcp_sock_id",
		addr2 + 1: "xfrm_km_lock",
	}, syms)
}

var errLoadKsyms error

func BenchmarkLoadKernelSymbols(b *testing.B) {
	b.ReportAllocs()

	c := NewKsym(
		log.NewNopLogger(),
		prometheus.NewRegistry(),
		b.TempDir(),
	)

	for n := 0; n < b.N; n++ {
		errLoadKsyms = c.loadKsyms(
			func(addr uint64, symbol string) {
			},
		)
	}
}

var kallsymsResult uint64

func BenchmarkHashProcKallSyms(b *testing.B) {
	b.ReportAllocs()

	c := NewKsym(
		log.NewNopLogger(),
		prometheus.NewRegistry(),
		b.TempDir(),
	)

	for n := 0; n < b.N; n++ {
		kallsymsResult, _ = c.kallsymsHash()
	}
}
