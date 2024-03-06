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
//

package java

import (
	"fmt"
	"os"
	goruntime "runtime"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type vm struct {
	pid int

	lib *runtime.ProcessMappedFile

	arch          string
	version       *semver.Version
	versionSource runtime.VersionSource
}

func newVM(proc procfs.Proc) (*vm, error) {
	lib, libStartAddr, err := findLibrary(proc)
	if err != nil {
		return nil, fmt.Errorf("find library: %w", err)
	}

	lf, err := os.Open(absolutePath(proc, lib))
	if err != nil {
		return nil, fmt.Errorf("open library: %w", err)
	}

	mf, err := runtime.NewProcessMappedFile(proc.PID, lf, libStartAddr)
	if err != nil {
		return nil, fmt.Errorf("new process mapped file: %w", err)
	}

	versionString, err := runtime.ScanRodataForVersion(mf, openJDKVersionRegex)
	if err != nil {
		return nil, fmt.Errorf("scan rodata for version: %w", err)
	}

	version, err := semver.NewVersion(versionString)
	if err != nil {
		return nil, fmt.Errorf("new version: %w", err)
	}

	return &vm{
		pid: proc.PID,
		lib: mf,

		arch:          goruntime.GOARCH,
		version:       version,
		versionSource: runtime.VersionSourceFile,
	}, nil
}

func (v *vm) Close() error {
	return v.lib.Close()
}

type codeCache struct {
	lowBound  uint64
	highBound uint64
}

func (v *vm) codeCacheAddress() (codeCache, error) {
	cc := codeCache{}
	lowAddr, err := v.lib.FindAddressOfUsingRegex(`.*CodeCache.*_low_bound`)
	if err != nil {
		return cc, fmt.Errorf("find address of JVM_CodeCache: %w", err)
	}
	cc.lowBound = lowAddr

	highAddr, err := v.lib.FindAddressOfUsingRegex(`.*CodeCache.*_high_bound`)
	if err != nil {
		return cc, fmt.Errorf("find address of JVM_CodeCache: %w", err)
	}
	cc.highBound = highAddr

	return cc, nil
}
