// Copyright 2021 The Parca Authors
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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

func TestKsym(t *testing.T) {
	c := &Cache{
		logger: log.NewNopLogger(),
		fs: testutil.NewFakeFS(map[string][]byte{
			"/proc/kallsyms": []byte(`
ffffffff8f6d1140 b udp_bpf_prots
ffffffff8f6d1480 b udpv6_prot_lock
ffffffff8f6d1488 B cipso_v4_rbm_optfmt
ffffffff8f6d1490 b cipso_v4_cache
ffffffff8f6d1498 b cipso_v4_doi_list_lock
ffffffff8f6d149c b __key.2
ffffffff8f6d14a0 b sock_id
ffffffff8f6d14a4 b tcp_sock_id
ffffffff8f6d14a8 b tcp_sock_type
ffffffff8f6d14c0 b dummy.1
ffffffff8f6d14c0 b __key.0
ffffffff8f6d1510 b idx_generator.4
ffffffff8f6d1520 b xfrm_policy_inexact_table
ffffffff8f6d15a8 b xfrm_policy_afinfo_lock
ffffffff8f6d15ac b xfrm_if_cb_lock
ffffffff8f6d15c0 b acqseq.0
ffffffff8f6d15d0 b saddr_wildcard.4
ffffffff8f6d15e0 b xfrm_km_lock
ffffffff8f6d15e4 b xfrm_state_gc_lock
ffffffff8f6d1600 b xfrm_state_afinfo
ffffffff8f6d1768 b xfrm_state_afinfo_lock
ffffffff8f6d1770 b xfrm_state_gc_list
ffffffff8f6d1780 b xfrm_napi_dev
		`),
		}),
		fastCache:      make(map[uint64]string),
		updateDuration: time.Minute * 5,
		mtx:            &sync.RWMutex{},
	}

	addr1 := uint64(0xffffffff8f6d14a4) + 1
	addr2 := uint64(0xffffffff8f6d15e0) + 1
	addr3 := uint64(0xffffffff8f6d1480) + 1

	syms, err := c.Resolve(map[uint64]struct{}{
		addr1: {},
		addr2: {},
	})
	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
	}, syms)

	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
	}, c.fastCache)

	syms, err = c.Resolve(map[uint64]struct{}{
		addr1: {},
		addr2: {},
		addr3: {},
	})
	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
		addr3: "udpv6_prot_lock",
	}, syms)

	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
		addr3: "udpv6_prot_lock",
	}, c.fastCache)

	// Second time should be served from cache.
	c.fs = testutil.NewErrorFS(errors.New("not served from cache"))
	syms, err = c.Resolve(map[uint64]struct{}{
		addr1: {},
		addr2: {},
	})

	require.NoError(t, err)
	require.Equal(t, map[uint64]string{
		addr1: "tcp_sock_id",
		addr2: "xfrm_km_lock",
	}, syms)
}
