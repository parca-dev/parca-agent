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

package process

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

func TestComputeBase(t *testing.T) {
	tinyExecFile := &elf.File{
		FileHeader: elf.FileHeader{Type: elf.ET_EXEC},
		Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_PHDR, Flags: elf.PF_R | elf.PF_X, Off: 0x40, Vaddr: 0x400040, Paddr: 0x400040, Filesz: 0x1f8, Memsz: 0x1f8, Align: 8}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_INTERP, Flags: elf.PF_R, Off: 0x238, Vaddr: 0x400238, Paddr: 0x400238, Filesz: 0x1c, Memsz: 0x1c, Align: 1}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0xc80, Memsz: 0xc80, Align: 0x200000}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Off: 0xc80, Vaddr: 0x200c80, Paddr: 0x200c80, Filesz: 0x1f0, Memsz: 0x1f0, Align: 0x200000}},
		},
	}
	tinyBadBSSExecFile := &elf.File{
		FileHeader: elf.FileHeader{Type: elf.ET_EXEC},
		Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_PHDR, Flags: elf.PF_R | elf.PF_X, Off: 0x40, Vaddr: 0x400040, Paddr: 0x400040, Filesz: 0x1f8, Memsz: 0x1f8, Align: 8}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_INTERP, Flags: elf.PF_R, Off: 0x238, Vaddr: 0x400238, Paddr: 0x400238, Filesz: 0x1c, Memsz: 0x1c, Align: 1}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0xc80, Memsz: 0xc80, Align: 0x200000}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Off: 0xc80, Vaddr: 0x200c80, Paddr: 0x200c80, Filesz: 0x100, Memsz: 0x1f0, Align: 0x200000}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Off: 0xd80, Vaddr: 0x400d80, Paddr: 0x400d80, Filesz: 0x90, Memsz: 0x90, Align: 0x200000}},
		},
	}

	for _, tc := range []struct {
		desc      string
		file      *elf.File
		mapping   *Mapping
		addr      uint64
		wantError bool
		wantBase  uint64
	}{
		{
			desc:     "no elf mapping, no error",
			mapping:  nil,
			addr:     0x1000,
			wantBase: 0,
		},
		{
			desc: "address outside mapping bounds means error",
			file: &elf.File{},
			mapping: &Mapping{
				PID: os.Getpid(),
				ProcMap: &procfs.ProcMap{
					StartAddr: 0x2000,
					EndAddr:   0x5000,
					Offset:    0x1000,
				},
			},
			addr:      0x1000,
			wantError: true,
		},
		{
			desc:     "no loadable segments, no error",
			file:     &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_EXEC}},
			mapping:  &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x2000, EndAddr: 0x5000, Offset: 0x1000}},
			addr:     0x4000,
			wantBase: 0,
		},
		{
			desc:      "unsupported executable type, Get Base returns error",
			file:      &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_NONE}},
			mapping:   &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x2000, EndAddr: 0x5000, Offset: 0x1000}},
			addr:      0x4000,
			wantError: true,
		},
		{
			desc:     "tiny ObjectFile select executable segment by offset",
			file:     tinyExecFile,
			mapping:  &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x5000000, EndAddr: 0x5001000, Offset: 0x0}},
			addr:     0x5000c00,
			wantBase: 0x5000000,
		},
		{
			desc:     "tiny ObjectFile select data segment by offset",
			file:     tinyExecFile,
			mapping:  &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x5200000, EndAddr: 0x5201000, Offset: 0x0}},
			addr:     0x5200c80,
			wantBase: 0x5000000,
		},
		{
			desc:      "tiny ObjectFile offset outside any segment means error",
			file:      tinyExecFile,
			mapping:   &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x5200000, EndAddr: 0x5201000, Offset: 0x0}},
			addr:      0x5200e70,
			wantError: true,
		},
		{
			desc:     "tiny ObjectFile with bad BSS segment selects data segment by offset in initialized section",
			file:     tinyBadBSSExecFile,
			mapping:  &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x5200000, EndAddr: 0x5201000, Offset: 0x0}},
			addr:     0x5200d79,
			wantBase: 0x5000000,
		},
		{
			desc:      "tiny ObjectFile with bad BSS segment with offset in uninitialized section means error",
			file:      tinyBadBSSExecFile,
			mapping:   &Mapping{ProcMap: &procfs.ProcMap{StartAddr: 0x5200000, EndAddr: 0x5201000, Offset: 0x0}},
			addr:      0x5200d80,
			wantError: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			dummyFile, err := os.CreateTemp("", "")
			require.NoError(t, err)
			t.Cleanup(func() {
				dummyFile.Close()
				os.Remove(dummyFile.Name())
			})

			base, err := tc.mapping.computeBase(tc.file, tc.addr)
			if (err != nil) != tc.wantError {
				t.Errorf("got error %v, want any error=%v", err, tc.wantError)
			}
			if err != nil {
				return
			}
			if base != tc.wantBase {
				t.Errorf("got base %x, want %x", base, tc.wantBase)
			}
		})
	}
}

//nolint:dupword
func TestELFObjAddr(t *testing.T) {
	t.Parallel()
	// The exe_linux_64 has two loadable program headers:
	//  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
	//                 0x00000000000006fc 0x00000000000006fc  R E    0x200000
	//  LOAD           0x0000000000000e10 0x0000000000600e10 0x0000000000600e10
	//                 0x0000000000000230 0x0000000000000238  RW     0x200000
	name := filepath.Join("./testdata", "exe_linux_64")

	fs, err := procfs.NewDefaultFS()
	if err != nil {
		t.Fatal(err)
	}
	ofp := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 10, 1)
	mm := NewMapManager(prometheus.NewRegistry(), fs, ofp, true)

	for _, tc := range []struct {
		desc                 string
		start, limit, offset uint64
		wantOpenError        bool
		addr                 uint64
		wantObjAddr          uint64
		wantAddrError        bool
	}{
		{"exec mapping, good address", 0x5400000, 0x5401000, 0, false, 0x5400400, 0x400400, false},
		{"exec mapping, address outside segment", 0x5400000, 0x5401000, 0, false, 0x5400800, 0, true},
		{"short data mapping, good address", 0x5600e00, 0x5602000, 0xe00, false, 0x5600e10, 0x600e10, false},
		{"short data mapping, address outside segment", 0x5600e00, 0x5602000, 0xe00, false, 0x5600e00, 0x600e00, false},
		{"page aligned data mapping, good address", 0x5600000, 0x5602000, 0, false, 0x5601000, 0x601000, false},
		{"page aligned data mapping, address outside segment", 0x5600000, 0x5602000, 0, false, 0x5601048, 0, true},
		{"bad ObjectFile offset, no matching segment", 0x5600000, 0x5602000, 0x2000, false, 0x5600e10, 0, true},
		{"large mapping size, match by sample offset", 0x5600000, 0x5603000, 0, false, 0x5600e10, 0x600e10, false},
	} {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			abs, err := filepath.Abs(name)
			if err != nil {
				t.Fatal(err)
			}

			m, err := mm.NewUserMapping(
				&procfs.ProcMap{
					StartAddr: uintptr(tc.start),
					EndAddr:   uintptr(tc.limit),
					Offset:    int64(tc.offset),
					Pathname:  abs,
					Perms: &procfs.ProcMapPermissions{
						Execute: true,
					},
				},
				os.Getpid(),
			)
			require.NoError(t, err)

			got, err := m.Normalize(tc.addr)
			if tc.wantAddrError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantObjAddr, got)
		})
	}
}

func TestELFObjAddrNoPIE(t *testing.T) {
	/* The sampled program below was compiled with gcc 11.3.0 on Ubuntu 22.04.
	gcc -Og -fno-pie -no-pie -fcf-protection=none -o fib-nopie main.c

	#include <stdio.h>

	long fibNaive(long n) {
		if (n <= 2) {
			return 1;
		}
		return fibNaive(n-2) + fibNaive(n-1);
	}

	int main() {
		long n = 50;
		long res = fibNaive(n);
		printf("Fibonacci number %li: %li\n", n, res);
		return 0;
	}

	See the following post to learn more about PIE
	https://marselester.com/diy-cpu-profiler-position-independent-executable.html.
	*/

	fs, err := procfs.NewDefaultFS()
	if err != nil {
		t.Fatal(err)
	}
	mm := NewMapManager(
		prometheus.NewRegistry(),
		fs,
		objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 10, 1),
		true,
	)

	const (
		mappingStart  = 0x401000
		mappingLimit  = 0x402000
		mappingOffset = 0x1000
		filename      = "testdata/fib-nopie"
	)

	abs, err := filepath.Abs(filename)
	if err != nil {
		t.Fatal(err)
	}

	m, err := mm.NewUserMapping(
		&procfs.ProcMap{
			StartAddr: mappingStart,
			EndAddr:   mappingLimit,
			Offset:    mappingOffset,
			Pathname:  abs,
			Perms: &procfs.ProcMapPermissions{
				Execute: true,
			},
		},
		os.Getpid(),
	)
	require.NoError(t, err)

	tests := []uint64{
		// fibNaive func exact address.
		0x401126,
		// fibNaive func non-exact addresses.
		0x40112a,
		0x40112c,
		0x401131,
		0x401132,
		0x401133,
		0x401134,
		0x401138,
		0x40113b,
		0x40113f,
		0x401144,
		0x401147,
		0x40114b,
		0x401150,
		0x401153,
		0x401157,
		0x401158,
		0x401159,
		// main func exact address.
		0x40115a,
		// main non-exact address.
		0x40115e,
		0x401163,
		0x401168,
		0x40116b,
		0x401170,
		0x401175,
		0x40117a,
		0x40117f,
		0x401184,
		0x401189,
		0x40118d,
	}

	for _, sampAddr := range tests {
		got, err := m.Normalize(sampAddr)
		if err != nil {
			t.Fatal(err)
		}

		if got != sampAddr {
			t.Errorf("expected normalized address 0x%x got 0x%x", sampAddr, got)
		}
	}
}

func TestELFObjAddrPIE(t *testing.T) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		t.Fatal(err)
	}
	mm := NewMapManager(
		prometheus.NewRegistry(),
		fs,
		objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 10, 1),
		true,
	)

	// The sampled program was compiled as follows:
	// gcc -o fib main.c
	const (
		mappingStart  = 0x5646e2188000
		mappingLimit  = 0x5646e2189000
		mappingOffset = 0x1000
		filename      = "testdata/fib"
	)

	abs, err := filepath.Abs(filename)
	if err != nil {
		t.Fatal(err)
	}

	m, err := mm.NewUserMapping(
		&procfs.ProcMap{
			StartAddr: mappingStart,
			EndAddr:   mappingLimit,
			Offset:    mappingOffset,
			Pathname:  abs,
			Perms: &procfs.ProcMapPermissions{
				Execute: true,
			},
		},
		os.Getpid(),
	)
	require.NoError(t, err)

	tests := map[uint64]uint64{
		// fibNaive func exact address.
		0x5646e2188149: 0x1149,
		// fibNaive func non-exact addresses.
		0x5646e218814d: 0x114d,
		0x5646e218814e: 0x114e,
		0x5646e2188151: 0x1151,
		0x5646e2188152: 0x1152,
		0x5646e2188156: 0x1156,
		0x5646e218815a: 0x115a,
		0x5646e218815f: 0x115f,
		0x5646e2188161: 0x1161,
		0x5646e2188166: 0x1166,
		0x5646e2188168: 0x1168,
		0x5646e218816c: 0x116c,
		0x5646e2188170: 0x1170,
		0x5646e2188173: 0x1173,
		0x5646e2188178: 0x1178,
		0x5646e218817b: 0x117b,
		0x5646e218817f: 0x117f,
		0x5646e2188183: 0x1183,
		0x5646e2188186: 0x1186,
		0x5646e218818b: 0x118b,
		0x5646e218818e: 0x118e,
		0x5646e2188192: 0x1192,
		0x5646e2188193: 0x1193,
		// main func exact address.
		0x5646e21881b4: 0x11b4,
	}

	for sampAddr, normAddr := range tests {
		got, err := m.Normalize(sampAddr)
		if err != nil {
			t.Fatal(err)
		}

		if got != normAddr {
			t.Errorf("expected normalized address 0x%x got 0x%x", normAddr, got)
		}
	}
}

// TODO(kakkoyun): Add real proc map examples.
func TestMapping_doesReferToFile(t *testing.T) {
	cases := []struct {
		path     string
		expected bool
	}{
		{"", false},
		{" [abc] ", false},
		{"[vdso]", false},
		{"[perf_event]", false},
		{"[vsyscall]", false},
		{"anon_inode:[perf_event]", false},
		{"def", true},
	}

	for _, c := range cases {
		got := doesReferToFile(c.path)
		if got != c.expected {
			t.Errorf("doesReferToFile(%q) == %t, want %t", c.path, got, c.expected)
		}
	}
}
