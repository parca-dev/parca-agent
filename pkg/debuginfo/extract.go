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
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/containerd/containerd/sys/reaper"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"
	"github.com/parca-dev/parca/pkg/symbol/elfutils"
)

// Extractor extracts debug information from a binary.
type Extractor struct {
	logger log.Logger
	client Client
	pool   sync.Pool

	tmpDir string
}

// NewExtractor creates a new Extractor.
func NewExtractor(logger log.Logger, client Client, tmpDir string) *Extractor {
	return &Extractor{
		logger: log.With(logger, "component", "extractor"),
		client: client,
		tmpDir: tmpDir,
		pool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(nil)
			},
		},
	}
}

// ExtractAll extracts debug information from the given executables.
// It consumes a map of build id to executable path and returns a map of build id to extracted debug information path.
func (e *Extractor) ExtractAll(ctx context.Context, objFilePaths map[string]string) (map[string]string, error) {
	files := map[string]string{}
	var result *multierror.Error
	for buildID, filePath := range objFilePaths {
		debugInfoFile, err := e.Extract(ctx, buildID, filePath)
		if err != nil {
			level.Warn(e.logger).Log(
				"msg", "failed to extract debug information",
				"buildid", buildID, "file", filePath, "err", err,
			)
			result = multierror.Append(result, err)
			files[buildID] = ""
		}
		files[buildID] = debugInfoFile
	}

	if len(result.Errors) == len(objFilePaths) {
		return nil, result.ErrorOrNil()
	}
	return files, nil
}

// Extract extracts debug information from the given executable.
// Cleaning up the temporary directory and the interim file is the caller's responsibility.
func (e *Extractor) Extract(ctx context.Context, buildID, filePath string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	tmpDir := path.Join(e.tmpDir, buildID)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create temp dir for debug information extraction: %w", err)
	}

	hasSymtab, err := hasSymbols(filePath)
	if err != nil {
		level.Debug(e.logger).Log(
			"msg", "failed to determine whether file has symbols",
			"file", filePath, "err", err,
		)
	}

	hasDWARF, err := elfutils.HasDWARF(filePath)
	if err != nil {
		level.Debug(e.logger).Log(
			"msg", "failed to determine if binary has DWARF sections",
			"path", filePath, "err", err,
		)
	}

	isGo, err := elfutils.IsSymbolizableGoObjFile(filePath)
	if err != nil {
		level.Debug(e.logger).Log("msg", "failed to determine if binary is a Go binary", "path", filePath, "err", err)
	}

	toRemove, err := sectionsToRemove(filePath)
	if err != nil {
		level.Debug(e.logger).Log("msg", "failed to determine sections to remove", "path", filePath, "err", err)
	}

	outFile := path.Join(tmpDir, "debuginfo")
	interimDir, err := ioutil.TempDir(e.tmpDir, "*")
	if err != nil {
		return "", err
	}
	defer func() { os.RemoveAll(interimDir) }()

	var cmd *exec.Cmd
	switch {
	case hasDWARF:
		cmd = e.strip(ctx, interimDir, filePath, outFile, toRemove)
	case isGo:
		cmd = e.objcopy(ctx, filePath, outFile, toRemove)
	case hasSymtab:
		cmd = e.objcopy(ctx, filePath, outFile, toRemove)
	default:
		cmd = e.strip(ctx, interimDir, filePath, outFile, toRemove)
	}
	const msg = "failed to extract debug information from binary"
	if err := e.run(cmd); err != nil {
		return "", fmt.Errorf(msg+": %w", err)
	}

	// Check if the debug information file is actually created.
	if exists, err := exists(outFile); !exists {
		if err != nil {
			return "", fmt.Errorf(msg+": %w", err)
		}
		return "", fmt.Errorf(msg+": %s", "debug information file is not created")
	}

	return outFile, nil
}

func (e *Extractor) run(cmd *exec.Cmd) error {
	level.Debug(e.logger).Log(
		"msg", "running external binary utility command", "cmd",
		strings.Join(cmd.Args, " "),
	)
	b := e.pool.Get().(*bytes.Buffer)
	defer func() {
		b.Reset()
		e.pool.Put(b)
	}()
	cmd.Stdout = b
	cmd.Stderr = b
	c, err := reaper.Default.Start(cmd)
	if err != nil {
		return err
	}
	const msg = "external binary utility command failed"
	status, err := reaper.Default.Wait(cmd, c)
	if err != nil {
		level.Debug(e.logger).Log("msg", msg, "cmd", cmd.Args, "output", b.String(), "err", err)
		return err
	}
	if status != 0 {
		level.Debug(e.logger).Log("msg", msg, "cmd", cmd.Args, "output", b.String())
		return errors.New(msg)
	}
	return nil
}

func (e *Extractor) strip(ctx context.Context, tmpDir, file, outFile string, toRemove []string) *exec.Cmd {
	level.Debug(e.logger).Log("msg", "using eu-strip", "file", file)
	// Extract debug symbols.
	// If we have DWARF symbols, they are enough for us to symbolize the profiles.
	// We observed that having DWARF debug symbols and symbol table together caused us problem in certain cases.
	// As DWARF symbols enough on their own we just extract those.
	// eu-strip --strip-debug extracts the .debug/.zdebug sections from the object files.
	args := []string{"--strip-debug"}
	for _, s := range toRemove {
		args = append(args, "--remove-section", s)
	}
	args = append(args,
		"-f", outFile,
		"-o", path.Join(tmpDir, "binary.stripped"),
		file,
	)
	return exec.CommandContext(ctx, "eu-strip", args...)
}

func (e *Extractor) objcopy(ctx context.Context, file, outFile string, toRemove []string) *exec.Cmd {
	level.Debug(e.logger).Log("msg", "using objcopy", "file", file)
	// Go binaries has a special case. They use ".gopclntab" section to symbolize addresses.
	// We need to keep ".note.go.buildid", ".symtab" and ".gopclntab",
	// however it doesn't hurt to keep rather small sections.
	args := []string{}
	toRemove = append(toRemove, ".text", ".rodata*")
	for _, s := range toRemove {
		args = append(args, "--remove-section", s)
	}
	args = append(args,
		file,    // source
		outFile, // destination
	)
	return exec.CommandContext(ctx, "objcopy", args...)
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

func hasSymbols(filePath string) (bool, error) {
	ef, err := elf.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open elf: %w", err)
	}
	defer ef.Close()

	for _, section := range ef.Sections {
		if section.Type == elf.SHT_SYMTAB {
			return true, nil
		}
	}
	return false, nil
}
