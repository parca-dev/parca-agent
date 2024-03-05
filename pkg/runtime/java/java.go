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
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

func isJVM(lib string) bool {
	return strings.Contains(lib, "libjvm.so")
}

func IsRuntime(proc procfs.Proc) (bool, error) {
	maps, err := proc.ProcMaps()
	if err != nil {
		return false, fmt.Errorf("error reading process maps: %w", err)
	}

	var found bool
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if m.Perms.Execute {
				if isJVM(pathname) {
					found = true
					break
				}
			}
		}
	}
	if !found {
		return false, nil
	}
	return true, nil
}

// NOTICE: We need to add more patterns to match all possible JVM vendors.

// e.g: OpenJDK 64-Bit Server VM (20.0.2+9-78) for linux-amd64 JRE (20.0.2+9-78),
// built on 2023-06-14T10:08:48Z by "mach5one" with gcc 1.2.0.
var openJDKVersionRegex = regexp.MustCompile(`(\d+\.\d+\.\d+(\+\d+)?(-\d+)?)`)

func RuntimeInfo(proc procfs.Proc) (*runtime.Runtime, error) {
	isJava, err := IsRuntime(proc)
	if err != nil {
		return nil, fmt.Errorf("failed to check if PID %d is a java runtime: %w", proc.PID, err)
	}
	if !isJava {
		return nil, nil //nolint:nilnil
	}

	rt := &runtime.Runtime{
		Name: "java",
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("error reading process maps: %w", err)
	}

	var (
		found           bool
		lib             string
		libStartAddress uint64
	)
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if m.Perms.Execute {
				if isJVM(pathname) {
					found = true
					lib = pathname
					libStartAddress = uint64(m.StartAddr)
					break
				}
			}
		}
	}
	if !found {
		return rt, fmt.Errorf("java library not found for (%d) in process maps", proc.PID)
	}

	lf, err := os.Open(absolutePath(proc, lib))
	if err != nil {
		return rt, fmt.Errorf("open library: %w", err)
	}
	defer lf.Close()

	mf, err := runtime.NewProcessMappedFile(proc.PID, lf, libStartAddress)
	if err != nil {
		return rt, fmt.Errorf("new process mapped file: %w", err)
	}

	// "JDK_Version::_java_version" is the symbol that contains the version string.
	// However, it's mangled, so we need to use a regex to find it.
	versionString, err := runtime.ScanRodataForVersion(mf, openJDKVersionRegex)
	if err != nil {
		return rt, fmt.Errorf("scan rodata for version: %w", err)
	}

	rt.Version = versionString
	return rt, nil
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}

type Info struct {
	rt     runtime.Runtime
	rtType runtime.UnwinderType

	CodeCacheAddress uint64
}

func (i *Info) Type() runtime.UnwinderType {
	return i.rtType
}

func (i *Info) Runtime() runtime.Runtime {
	return i.rt
}

func VMInfo(p procfs.Proc) (runtime.UnwinderInfo, error) {
	rt, err := RuntimeInfo(p)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch java runtime info: %w", err)
	}
	return &Info{
		rt:     *rt,
		rtType: runtime.UnwinderJava,
	}, nil
}
