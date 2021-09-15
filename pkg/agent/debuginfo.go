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

package agent

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/maps"
)

var errNotFound = errors.New("not found")

type DebugInfoClient interface {
	Exists(ctx context.Context, buildID string) (bool, error)
	Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error)
}

type NoopDebugInfoClient struct{}

func (c *NoopDebugInfoClient) Exists(ctx context.Context, buildID string) (bool, error) {
	return true, nil
}
func (c *NoopDebugInfoClient) Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error) {
	return 0, nil
}

func NewNoopDebugInfoClient() DebugInfoClient {
	return &NoopDebugInfoClient{}
}

type debugInfoExtractor struct {
	logger          log.Logger
	tmpDir          string
	debugInfoClient DebugInfoClient
}

func (di *debugInfoExtractor) ensureDebugInfoUploaded(ctx context.Context, buildIDFiles map[string]maps.BuildIDFile) {
	for buildID, buildIDFile := range buildIDFiles {
		exists, err := di.debugInfoClient.Exists(ctx, buildID)
		if err != nil {
			level.Error(di.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
			continue
		}

		if !exists {
			level.Debug(di.logger).Log("msg", "could not find symbols in server", "buildid", buildID)

			file := buildIDFile.FullPath()
			hasDebugInfo, err := hasDebugInfo(file)
			if err != nil {
				level.Error(di.logger).Log("msg", "failed to determine whether file has debug symbols", "file", file, "err", err)
				continue
			}

			if !hasDebugInfo {
				// The object does not have debug symbols, but maybe debuginfos
				// have been installed separately, typically in /usr/lib/debug, so
				// we try to discover if there is a debuginfo file, that has the
				// same build ID as the object.
				level.Debug(di.logger).Log("msg", "could not find symbols in binary, checking for additional debuginfo file", "buildid", buildID, "file", file)
				dbgInfo, err := di.findDebugInfo(buildID, buildIDFile)
				if err != nil {
					if !errors.Is(err, errNotFound) {
						level.Debug(di.logger).Log("msg", "failed to find additional debug information", "root", buildIDFile.Root(), "err", err)
					}
					continue
				}

				file = dbgInfo
			}

			debugInfoFile, err := di.extractDebugInfo(buildID, file)
			if err != nil {
				level.Error(di.logger).Log("msg", "failed to extract debug information", "buildid", buildID, "executable file", file, "err", err)
				continue
			}

			if err := di.uploadDebugInfo(ctx, buildID, debugInfoFile); err != nil {
				os.Remove(debugInfoFile)
				level.Error(di.logger).Log("msg", "failed to upload debug information", "buildid", buildID, "executable file", file, "err", err)
				continue
			}

			os.Remove(debugInfoFile)
			level.Debug(di.logger).Log("msg", "debug information uploaded successfully", "buildid", buildID, "file", file)
		}

		level.Debug(di.logger).Log("msg", "debug information already exist in server", "buildid", buildID)
	}
}

func (di *debugInfoExtractor) findDebugInfo(buildID string, buildIDFile maps.BuildIDFile) (string, error) {
	var (
		found = false
		file  string
	)
	err := filepath.Walk(path.Join(buildIDFile.Root(), "/usr/lib/debug"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			debugBuildId, err := buildid.ElfBuildID(path)
			if err != nil {
				return fmt.Errorf("failed to extract elf build ID, %w", err)
			}
			if debugBuildId == buildID {
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

func (di *debugInfoExtractor) extractDebugInfo(buildID string, file string) (string, error) {
	isGo, err := isSymbolizableGoBinary(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine if binary is a Go binary", "path", file, "err", err)
	}

	debugFile := path.Join(di.tmpDir, buildID)
	if isGo {
		// Go binaries has a special case. They use ".gopclntab" section to symbolize addresses.
		// We need to keep ".note.go.buildid", ".symtab" and ".gopclntab",
		// however it doesn't hurt to keep rather small sections.
		cmd := exec.Command("objcopy",
			"-R", ".zdebug_*",
			"-R", ".debug_*",
			"-R", ".text", // executable
			"-R", ".rodata*", // constants
			file,      // source
			debugFile, // destination
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
	} else {
		// Extract debug symbols.
		// If we have DWARF symbols, they are enough for us to symbolize the profiles.
		// We observed that having DWARF debug symbols and symbol table together caused us problem in certain cases.
		// As DWARF symbols enough on their own we just extract those.
		// eu-strip --strip-debug extracts the .debug/.zdebug sections from the object files.
		interimFile := path.Join(di.tmpDir, buildID+".stripped")
		cmd := exec.Command("eu-strip", "--strip-debug", "-f", debugFile, "-o", interimFile, file)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		defer func() {
			os.Remove(interimFile)
		}()
	}
	if err != nil {
		return "", err
	}
	return debugFile, nil
}

func (di *debugInfoExtractor) uploadDebugInfo(ctx context.Context, buildID string, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open temp file for build ID symbol source: %w", err)
	}

	if _, err := di.debugInfoClient.Upload(ctx, buildID, f); err != nil {
		return fmt.Errorf("failed to upload build ID symbol source: %w", err)
	}

	return nil
}

func hasDebugInfo(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer f.Close()

	for _, section := range f.Sections {
		if section.Type == elf.SHT_SYMTAB ||
			strings.HasPrefix(section.Name, ".debug_") ||
			strings.HasPrefix(section.Name, ".zdebug_") ||
			section.Name == ".gopclntab" {
			return true, nil
		}
	}
	return false, nil
}

func isSymbolizableGoBinary(path string) (bool, error) {
	// Checks ".note.go.buildid" sections and symtab better to keep those sections in object file.
	exe, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer exe.Close()

	isGo := false
	for _, s := range exe.Sections {
		if s.Name == ".note.go.buildid" {
			isGo = true
		}
	}

	syms, err := exe.Symbols()
	if err != nil {
		return false, fmt.Errorf("failed to read symbols: %w", err)
	}
	for _, sym := range syms {
		name := sym.Name
		if name == "runtime.main" || name == "main.main" {
			isGo = true
		}
		if name == "runtime.buildVersion" {
			isGo = true
		}
	}

	if !isGo {
		return false, nil
	}

	// Check if the Go binary symbolizable.
	// Go binaries has a special case. They use ".gopclntab" section to symbolize addresses.
	if sec := exe.Section(".gopclntab"); sec != nil {
		_, err := sec.Data()
		if err != nil {
			return false, fmt.Errorf("could not find .gopclntab section: %w", err)
		}
	}

	return true, nil
}
