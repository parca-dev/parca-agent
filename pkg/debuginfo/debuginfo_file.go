// Copyright 2022 The Parca Authors
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

package debuginfo

import (
	"debug/elf"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var dwarfSuffix = func(s *elf.Section) string {
	switch {
	case strings.HasPrefix(s.Name, ".debug_"):
		return s.Name[7:]
	case strings.HasPrefix(s.Name, ".zdebug_"):
		return s.Name[8:]
	case strings.HasPrefix(s.Name, "__debug_"): // macos
		return s.Name[8:]
	default:
		return ""
	}
}

type debugInfoFile struct {
	*objectfile.ObjectFile

	dbgOnce      sync.Once
	dbgErr       error
	hasDebugInfo bool

	localDbgOnce       sync.Once
	localDbgErr        error
	localDebugInfoPath string
}

func (f *debugInfoFile) LocalHostDebugInfoPath() (string, error) {
	f.localDbgOnce.Do(func() {
		f.localDebugInfoPath, f.localDbgErr = f.checkLocalHostDebugInfo()
	})
	return f.localDebugInfoPath, f.localDbgErr
}

func (f *debugInfoFile) checkLocalHostDebugInfo() (string, error) {
	var (
		found = false
		file  string
	)
	// TODO(kakkoyun): Distros may have different locations for debuginfo files.
	// Add support for all of them.
	err := filepath.Walk(path.Join(f.Root(), "/usr/lib/debug"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			buildID, err := buildid.BuildID(path)
			if err != nil {
				return fmt.Errorf("failed to extract elf build ID, %w", err)
			}
			if strings.EqualFold(buildID, f.BuildID) {
				found = true
				file = path
			}
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return "", errNotFound
		}

		return "", fmt.Errorf("failed to walk debug files: %w", err)
	}

	if !found {
		return "", errNotFound
	}
	return file, nil
}

func (f *debugInfoFile) HasDebugInfo() (bool, error) {
	f.dbgOnce.Do(func() { f.hasDebugInfo, f.dbgErr = checkDebugInfo(f.FullPath()) })

	return f.hasDebugInfo, f.dbgErr
}

func checkDebugInfo(path string) (bool, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer ef.Close()

	for _, section := range ef.Sections {
		if section.Type == elf.SHT_SYMTAB || // TODO: Consider moving this to a specific func.
			strings.HasPrefix(section.Name, ".debug_") ||
			strings.HasPrefix(section.Name, ".zdebug_") ||
			strings.HasPrefix(section.Name, "__debug_") || // macos
			section.Name == ".gopclntab" { // go
			return true, nil
		}
	}
	return false, nil
}
