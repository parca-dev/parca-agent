// Copyright 2021 The Parca Authors
//
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

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

// See https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jit-interface.txt
const perfMap = `3ef414c0 398 RegExp:[{(]
3ef418a0 398 RegExp:[})]
59ed4102 26 LazyCompile:~REPLServer.self.writer repl.js:514
59ed44ea 146 LazyCompile:~inspect internal/util/inspect.js:152
59ed4e4a 148 LazyCompile:~formatValue internal/util/inspect.js:456
59ed558a 25f LazyCompile:~formatPrimitive internal/util/inspect.js:768
59ed5d62 35 LazyCompile:~formatNumber internal/util/inspect.js:761
59ed5fca 5d LazyCompile:~stylizeWithColor internal/util/inspect.js:267
4edd2e52 65 LazyCompile:~Domain.exit domain.js:284
4edd30ea 14b LazyCompile:~lastIndexOf native array.js:618
4edd3522 35 LazyCompile:~online internal/repl.js:157
4edd37f2 ec LazyCompile:~setTimeout timers.js:388
4edd3cca b0 LazyCompile:~Timeout internal/timers.js:55
4edd40ba 55 LazyCompile:~initAsyncResource internal/timers.js:45
4edd42da f LazyCompile:~exports.active timers.js:151
4edd457a cb LazyCompile:~insert timers.js:167
4edd4962 50 LazyCompile:~TimersList timers.js:195
4edd4cea 37 LazyCompile:~append internal/linkedlist.js:29
4edd4f12 35 LazyCompile:~remove internal/linkedlist.js:15
4edd5132 d LazyCompile:~isEmpty internal/linkedlist.js:44
4edd529a 21 LazyCompile:~ok assert.js:345
4edd555a 68 LazyCompile:~innerOk assert.js:317
4edd59a2 27 LazyCompile:~processTimers timers.js:220
4edd5d9a 197 LazyCompile:~listOnTimeout timers.js:226
4edd6352 15 LazyCompile:~peek internal/linkedlist.js:9
4edd66ca a1 LazyCompile:~tryOnTimeout timers.js:292
4edd6a02 86 LazyCompile:~ontimeout timers.js:429
4edd7132 d7 LazyCompile:~process.kill internal/process/per_thread.js:173`

const procStatus = `Name:	node
Umask:	0022
State:	S (sleeping)
Tgid:	25803
Ngid:	0
Pid:	25803
PPid:	25781
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0
FDSize:	64
Groups:	 
NStgid:	25803	1
NSpid:	25803	1
NSpgid:	25803	1
NSsid:	25803	1
VmPeak:	  595656 kB
VmSize:	  594380 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	   53328 kB
VmRSS:	   50024 kB
RssAnon:	   15196 kB
RssFile:	   34828 kB
RssShmem:	       0 kB
VmData:	   57152 kB
VmStk:	     132 kB
VmExe:	   67952 kB
VmLib:	    3480 kB
VmPTE:	     988 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
Threads:	7
SigQ:	0/22385
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000001001000
SigCgt:	0000000180004602
CapInh:	00000000a80425fb
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Speculation_Store_Bypass:	thread vulnerable
Cpus_allowed:	3
Cpus_allowed_list:	0-1
Mems_allowed:	00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	113
nonvoluntary_ctxt_switches:	1014
`

func TestPerfMapParse(t *testing.T) {
	fs := testutil.NewFakeFS(map[string][]byte{
		"/tmp/perf-123.map": []byte(perfMap),
	})

	res, err := PerfReadMap(fs, "/tmp/perf-123.map")
	require.NoError(t, err)
	require.Len(t, res.addrs, 28)
	// Check for 4edd3cca B0 LazyCompile:~Timeout internal/timers.js:55
	require.Equal(t, res.addrs[12], PerfMapAddr{0x4edd4f12, 0x4edd4f47, "LazyCompile:~remove internal/linkedlist.js:15"})

	// Look-up a symbol.
	sym, err := res.Lookup(0x4edd4f12 + 4)
	require.NoError(t, err)
	require.Equal(t, sym, "LazyCompile:~remove internal/linkedlist.js:15")

	_, err = res.Lookup(0xFFFFFFFF)
	require.ErrorIs(t, err, NoSymbolFound)
}

func BenchmarkPerfMapParse(b *testing.B) {
	fs := testutil.NewFakeFS(map[string][]byte{
		"/tmp/perf-123.map": []byte(perfMap),
	})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := PerfReadMap(fs, "/tmp/perf-123.map")
		require.NoError(b, err)
	}
}

func TestFindNSPid(t *testing.T) {
	fs := testutil.NewFakeFS(map[string][]byte{
		"/proc/25803/status": []byte(procStatus),
	})

	pid, err := findNSPids(fs, 25803)
	require.NoError(t, err)

	require.Equal(t, []uint32{25803, 1}, pid)
}

func TestExtractPidsFromLine(t *testing.T) {
	pid, err := extractPidsFromLine("NSpid:\t25803\t1")
	require.NoError(t, err)

	require.Equal(t, []uint32{25803, 1}, pid)
}
