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

package debuginfo

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

type Client interface {
	Exists(ctx context.Context, buildID string) (bool, error)
	Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error)
}

type NoopClient struct{}

func (c *NoopClient) Exists(ctx context.Context, buildID string) (bool, error) {
	return true, nil
}
func (c *NoopClient) Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error) {
	return 0, nil
}

func NewNoopClient() Client {
	return &NoopClient{}
}

type Extractor struct {
	logger log.Logger
	Client Client
	tmpDir string
}

func NewExtractor(logger log.Logger, Client Client, tmpDir string) *Extractor {
	return &Extractor{
		logger: logger,
		Client: Client,
		tmpDir: tmpDir,
	}
}

func (di *Extractor) Upload(ctx context.Context, buildIDFiles map[string]string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for buildID, file := range buildIDFiles {
		exists, err := di.Client.Exists(ctx, buildID)
		if err != nil {
			level.Error(di.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
			continue
		}

		if !exists {
			level.Debug(di.logger).Log("msg", "could not find symbols in server", "buildid", buildID)

			hasDebugInfo, err := hasDebugInfo(file)
			if err != nil {
				level.Debug(di.logger).Log("msg", "failed to determine whether file has debug symbols", "file", file, "err", err)
				continue
			}

			if !hasDebugInfo {
				level.Debug(di.logger).Log("msg", "file does not have debug information, skipping", "file", file, "err", err)
				continue
			}

			debugInfoFile, err := di.extract(ctx, buildID, file)
			if err != nil {
				level.Debug(di.logger).Log("msg", "failed to extract debug information", "buildid", buildID, "file", file, "err", err)
				continue
			}

			if err := di.uploadDebugInfo(ctx, buildID, debugInfoFile); err != nil {
				os.Remove(debugInfoFile)
				level.Error(di.logger).Log("msg", "failed to upload debug information", "buildid", buildID, "file", file, "err", err)
				continue
			}

			os.Remove(debugInfoFile)
			level.Info(di.logger).Log("msg", "debug information uploaded successfully", "buildid", buildID, "file", file)
			continue
		}

		level.Info(di.logger).Log("msg", "debug information already exist in server", "buildid", buildID)
	}

	return nil
}

func (di *Extractor) Extract(ctx context.Context, buildIDFiles map[string]string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files := []string{}
	for buildID, file := range buildIDFiles {
		debugInfoFile, err := di.extract(ctx, buildID, file)
		if err != nil {
			level.Error(di.logger).Log("msg", "failed to extract debug information", "buildid", buildID, "file", file, "err", err)
			continue
		}
		files = append(files, debugInfoFile)
	}

	return files, nil
}

func (di *Extractor) EnsureUploaded(ctx context.Context, buildIDFiles map[string]maps.BuildIDFile) {
	for buildID, buildIDFile := range buildIDFiles {
		exists, err := di.Client.Exists(ctx, buildID)
		if err != nil {
			level.Warn(di.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
			continue
		}

		if !exists {
			level.Debug(di.logger).Log("msg", "could not find symbols in server", "buildid", buildID)

			file := buildIDFile.FullPath()
			hasDebugInfo, err := hasDebugInfo(file)
			if err != nil {
				level.Debug(di.logger).Log("msg", "failed to determine whether file has debug symbols", "file", file, "err", err)
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

			debugInfoFile, err := di.extract(ctx, buildID, file)
			if err != nil {
				level.Debug(di.logger).Log("msg", "failed to extract debug information", "buildid", buildID, "file", file, "err", err)
				continue
			}

			if err := di.uploadDebugInfo(ctx, buildID, debugInfoFile); err != nil {
				os.Remove(debugInfoFile)
				level.Warn(di.logger).Log("msg", "failed to upload debug information", "buildid", buildID, "file", file, "err", err)
				continue
			}

			os.Remove(debugInfoFile)
			level.Debug(di.logger).Log("msg", "debug information uploaded successfully", "buildid", buildID, "file", file)
			continue
		}

		level.Debug(di.logger).Log("msg", "debug information already exist in server", "buildid", buildID)
	}
}

func (di *Extractor) findDebugInfo(buildID string, buildIDFile maps.BuildIDFile) (string, error) {
	var (
		found = false
		file  string
	)
	err := filepath.Walk(path.Join(buildIDFile.Root(), "/usr/lib/debug"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			debugBuildId, err := buildid.BuildID(path)
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

func (di *Extractor) extract(ctx context.Context, buildID string, file string) (string, error) {
	tmpDir := path.Join(di.tmpDir, buildID)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp dir for debug information extraction: %w", err)
	}

	hasDWARF, err := hasDWARF(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine if binary has DWARF sections", "path", file, "err", err)
	}

	isGo, err := isSymbolizableGoBinary(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine if binary is a Go binary", "path", file, "err", err)
	}

	toRemove, err := sectionsToRemove(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine sections to remove", "path", file, "err", err)
	}

	var debugInfoFile string
	switch {
	case hasDWARF:
		debugInfoFile, err = di.useStrip(ctx, tmpDir, file, toRemove)
	case isGo:
		debugInfoFile, err = di.useObjcopy(ctx, tmpDir, file, toRemove)
	default:
		debugInfoFile, err = di.useStrip(ctx, tmpDir, file, toRemove)
	}
	const msg = "external binary utility command failed to extract debug information from binary"
	if err != nil {
		return "", fmt.Errorf(msg+": %w", err)
	}

	// Check if the debug information file is actually created.
	if exists, err := exists(debugInfoFile); !exists {
		if err != nil {
			return "", fmt.Errorf(msg+": %w", err)
		}
		return "", fmt.Errorf(msg+": %s", "debug information file is not created")
	}
	return debugInfoFile, nil
}

func (di *Extractor) useStrip(ctx context.Context, dir string, file string, toRemove []string) (string, error) {
	level.Debug(di.logger).Log("msg", "using eu-strip", "file", file)
	// Extract debug symbols.
	// If we have DWARF symbols, they are enough for us to symbolize the profiles.
	// We observed that having DWARF debug symbols and symbol table together caused us problem in certain cases.
	// As DWARF symbols enough on their own we just extract those.
	// eu-strip --strip-debug extracts the .debug/.zdebug sections from the object files.
	args := []string{"--strip-debug"}
	for _, s := range toRemove {
		args = append(args, "--remove-section", s)
	}
	debugInfoFile := path.Join(dir, "debuginfo")
	interimFile := path.Join(dir, "binary.stripped")
	args = append(args, "-f", debugInfoFile, "-o", interimFile, file)
	cmd := exec.CommandContext(ctx, "eu-strip", args...)
	defer os.Remove(interimFile)

	if out, err := cmd.CombinedOutput(); err != nil {
		level.Debug(di.logger).Log(
			"msg", "external eu-strip command call failed",
			"output", strings.ReplaceAll(string(out), "\n", ""),
			"file", file,
		)
		return "", err
	}

	return debugInfoFile, nil
}

func (di *Extractor) useObjcopy(ctx context.Context, dir string, file string, toRemove []string) (string, error) {
	level.Debug(di.logger).Log("msg", "using objcopy", "file", file)
	// Go binaries has a special case. They use ".gopclntab" section to symbolize addresses.
	// We need to keep ".note.go.buildid", ".symtab" and ".gopclntab",
	// however it doesn't hurt to keep rather small sections.
	args := []string{}
	toRemove = append(toRemove, ".text", ".rodata*")
	for _, s := range toRemove {
		args = append(args, "--remove-section", s)
	}
	debugInfoFile := path.Join(dir, "debuginfo")
	args = append(args,
		file,          // source
		debugInfoFile, // destination
	)
	cmd := exec.CommandContext(ctx, "objcopy", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		level.Debug(di.logger).Log(
			"msg", "external objcopy command call failed",
			"output", strings.ReplaceAll(string(out), "\n", ""),
			"file", file,
		)
		return "", err
	}

	return debugInfoFile, nil
}

func (di *Extractor) uploadDebugInfo(ctx context.Context, buildID string, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open temp file for debug information: %w", err)
	}

	if _, err := di.Client.Upload(ctx, buildID, f); err != nil {
		return fmt.Errorf("failed to upload debug information: %w", err)
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

func hasDWARF(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer f.Close()

	data, err := dwarf(f)
	if err != nil {
		return false, fmt.Errorf("failed to read DWARF sections: %w", err)
	}

	return len(data) > 0, nil
}

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

// A simplified and modified version of debug/elf.DWARF().
func dwarf(f *elf.File) (map[string][]byte, error) {
	// There are many DWARf sections, but these are the ones
	// the debug/dwarf package started with "abbrev", "info", "str", "line", "ranges".
	// Possible canditates for future: "loc", "loclists", "rnglists"
	sections := map[string]*string{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	data := map[string][]byte{}
	for _, sec := range f.Sections {
		suffix := dwarfSuffix(sec)
		if suffix == "" {
			continue
		}
		if _, ok := sections[suffix]; !ok {
			continue
		}
		b, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read debug section: %w", err)
		}
		data[suffix] = b
	}

	return data, nil
}

func sectionsToRemove(path string) ([]string, error) {
	var sections []string
	f, err := elf.Open(path)
	if err != nil {
		return sections, fmt.Errorf("failed to open elf file: %w", err)
	}
	defer f.Close()

	for _, sec := range f.Sections {
		if dwarfSuffix(sec) != "" && sec.Type == elf.SHT_NOBITS { // causes some trouble when it's set to SHT_NOBITS
			sections = append(sections, sec.Name)
		}
	}
	return sections, nil
}

func isSymbolizableGoBinary(path string) (bool, error) {
	// Checks ".note.go.buildid" section and symtab better to keep those sections in object file.
	f, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer f.Close()

	isGo := false
	for _, sec := range f.Sections {
		if sec.Name == ".note.go.buildid" {
			isGo = true
		}
	}

	// In case ".note.go.buildid" section is stripped, check for symbols.
	if !isGo {
		syms, err := f.Symbols()
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
	}

	if !isGo {
		return false, nil
	}

	// Check if the Go binary symbolizable.
	// Go binaries has a special case. They use ".gopclntab" section to symbolize addresses.
	var pclntab []byte
	if sec := f.Section(".gopclntab"); sec != nil {
		pclntab, err = sec.Data()
		if err != nil {
			return false, fmt.Errorf("could not find .gopclntab section: %w", err)
		}
	}

	return len(pclntab) > 0, nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
