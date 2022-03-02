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
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lru "github.com/hashicorp/golang-lru"
	"github.com/parca-dev/parca/pkg/symbol/elfutils"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
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

	client       Client
	dbgFileCache *lru.ARCCache

	tmpDir string

	pool sync.Pool
}

// TODO(kakkoyun): Split extract and upload into separate layers.
// - Use debuginfo_file for extraction related operations.
func NewExtractor(logger log.Logger, client Client, tmpDir string) *Extractor {
	cache, err := lru.NewARC(128) // Arbitrary cache size.
	if err != nil {
		level.Warn(logger).Log("msg", "failed to initialize debug file cache", "err", err)
	}
	return &Extractor{
		logger:       logger,
		client:       client,
		tmpDir:       tmpDir,
		dbgFileCache: cache,
		pool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(nil)
			},
		},
	}
}

func (di *Extractor) Upload(ctx context.Context, objFilePaths map[string]string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for buildID, filePath := range objFilePaths {
		exists, err := di.client.Exists(ctx, buildID)
		if err != nil {
			level.Error(di.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
			continue
		}

		if !exists {
			level.Debug(di.logger).Log("msg", "could not find symbols in server", "buildid", buildID)

			hasDebugInfo, err := checkIfFileHasDebugInfo(filePath)
			if err != nil {
				level.Debug(di.logger).Log(
					"msg", "failed to determine whether file has debug symbols",
					"file", filePath, "err", err,
				)
				continue
			}

			if !hasDebugInfo {
				level.Debug(di.logger).Log(
					"msg", "file does not have debug information, skipping",
					"file", filePath, "err", err,
				)
				continue
			}

			debugInfoFile, err := di.extract(ctx, buildID, filePath)
			if err != nil {
				level.Debug(di.logger).Log(
					"msg", "failed to extract debug information",
					"buildid", buildID, "file", filePath, "err", err,
				)
				continue
			}

			if err := di.uploadDebugInfo(ctx, buildID, debugInfoFile); err != nil {
				os.Remove(debugInfoFile)
				level.Error(di.logger).Log(
					"msg", "failed to upload debug information",
					"buildid", buildID, "file", filePath, "err", err,
				)
				continue
			}

			os.Remove(debugInfoFile)
			level.Info(di.logger).Log(
				"msg", "debug information uploaded successfully",
				"buildid", buildID, "file", filePath,
			)
			continue
		}

		level.Info(di.logger).Log("msg", "debug information already exist in server", "buildid", buildID)
	}

	return nil
}

func (di *Extractor) Extract(ctx context.Context, objFilePaths map[string]string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	files := []string{}
	for buildID, filePath := range objFilePaths {
		debugInfoFile, err := di.extract(ctx, buildID, filePath)
		if err != nil {
			level.Error(di.logger).Log(
				"msg", "failed to extract debug information", "buildid",
				buildID, "file", filePath, "err", err)
			continue
		}
		files = append(files, debugInfoFile)
	}

	return files, nil
}

func (di *Extractor) EnsureUploaded(ctx context.Context, objFiles []*objectfile.MappedObjectFile) {
	for _, objFile := range objFiles {
		buildID := objFile.BuildID
		exists, err := di.client.Exists(ctx, buildID)
		if err != nil {
			level.Warn(di.logger).Log(
				"msg", "failed to check whether build ID symbol exists",
				"buildid", buildID, "err", err,
			)
			continue
		}

		if !exists {
			level.Debug(di.logger).Log("msg", "could not find symbols in server", "buildid", buildID)
			var dbgInfoFile *debugInfoFile
			if di.dbgFileCache != nil {
				if val, ok := di.dbgFileCache.Get(buildID); ok {
					dbgInfoFile = val.(*debugInfoFile)
				} else {
					f, err := newDebugInfoFile(objFile)
					if err != nil {
						level.Debug(di.logger).Log(
							"msg", "failed to create debug information file",
							"buildid", buildID, "err", err,
						)
						continue
					}
					di.dbgFileCache.Add(buildID, f)
					dbgInfoFile = f
				}
			}
			objFilePath := objFile.Path
			if !dbgInfoFile.hasDebugInfo {
				// The object does not have debug symbols, but maybe debuginfos
				// have been installed separately, typically in /usr/lib/debug, so
				// we try to discover if there is a debuginfo file, that has the
				// same build ID as the object.
				level.Debug(di.logger).Log(
					"msg", "could not find symbols in binary, checking for additional debug info files on the system",
					"buildid", objFile.BuildID, "file", objFilePath,
				)
				if dbgInfoFile.localDebugInfoPath == "" {
					// Binary does not have debug symbols, and we could not find any on the system. Nothing to do here.
					continue
				}
				objFilePath = dbgInfoFile.localDebugInfoPath
			}

			extractedDbgInfo, err := di.extract(ctx, buildID, objFilePath)
			if err != nil {
				level.Debug(di.logger).Log(
					"msg", "failed to extract debug information",
					"buildid", buildID, "file", objFilePath, "err", err,
				)
				continue
			}

			if err := di.uploadDebugInfo(ctx, buildID, extractedDbgInfo); err != nil {
				os.Remove(extractedDbgInfo)
				level.Warn(di.logger).Log(""+
					"msg", "failed to upload debug information",
					"buildid", buildID, "file", objFilePath, "err", err,
				)
				continue
			}

			os.Remove(extractedDbgInfo)
			level.Debug(di.logger).Log(
				"msg", "debug information uploaded successfully",
				"buildid", buildID, "file", objFilePath,
			)
			continue
		}

		level.Debug(di.logger).Log(
			"msg", "debug information already exist in server",
			"buildid", buildID,
		)
	}
}

func (di *Extractor) extract(ctx context.Context, buildID, file string) (string, error) {
	tmpDir := path.Join(di.tmpDir, buildID)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create temp dir for debug information extraction: %w", err)
	}

	hasDWARF, err := elfutils.HasDWARF(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine if binary has DWARF sections",
			"path", file, "err", err,
		)
	}

	isGo, err := elfutils.IsSymbolizableGoObjFile(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine if binary is a Go binary", "path", file, "err", err)
	}

	toRemove, err := sectionsToRemove(file)
	if err != nil {
		level.Debug(di.logger).Log("msg", "failed to determine sections to remove", "path", file, "err", err)
	}

	outFile := path.Join(tmpDir, "debuginfo")
	interimDir, err := ioutil.TempDir(di.tmpDir, "*")
	if err != nil {
		return "", err
	}
	defer func() { os.RemoveAll(interimDir) }()

	var cmd *exec.Cmd
	switch {
	case hasDWARF:
		cmd = di.strip(ctx, interimDir, file, outFile, toRemove)
	case isGo:
		cmd = di.objcopy(ctx, file, outFile, toRemove)
	default:
		cmd = di.strip(ctx, interimDir, file, outFile, toRemove)
	}
	const msg = "failed to extract debug information from binary"
	if err := di.run(cmd); err != nil {
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

func (di *Extractor) run(cmd *exec.Cmd) error {
	level.Debug(di.logger).Log(
		"msg", "running external binary utility command", "cmd",
		strings.Join(cmd.Args, " "),
	)
	b := di.pool.Get().(*bytes.Buffer)
	defer func() {
		b.Reset()
		di.pool.Put(b)
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
		level.Debug(di.logger).Log("msg", msg, "cmd", cmd.Args, "output", b.String(), "err", err)
		return err
	}
	if status != 0 {
		level.Debug(di.logger).Log("msg", msg, "cmd", cmd.Args, "output", b.String())
		return errors.New(msg)
	}
	return nil
}

func (di *Extractor) strip(ctx context.Context, tmpDir, file, outFile string, toRemove []string) *exec.Cmd {
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
	args = append(args,
		"-f", outFile,
		"-o", path.Join(tmpDir, "binary.stripped"),
		file,
	)
	return exec.CommandContext(ctx, "eu-strip", args...)
}

func (di *Extractor) objcopy(ctx context.Context, file, outFile string, toRemove []string) *exec.Cmd {
	level.Debug(di.logger).Log("msg", "using objcopy", "file", file)
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

func (di *Extractor) uploadDebugInfo(ctx context.Context, buildID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open temp file for debug information: %w", err)
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = time.Second
	expBackOff.MaxElapsedTime = time.Minute

	err = backoff.Retry(func() error {
		if _, err := di.client.Upload(ctx, buildID, f); err != nil {
			di.logger.Log(
				"msg", "failed to upload debug information",
				"buildid", buildID,
				"path", filePath,
				"retry", expBackOff.NextBackOff(),
				"err", err,
			)
		}
		return err
	}, expBackOff)
	if err != nil {
		return fmt.Errorf("failed to upload debug information: %w", err)
	}

	return nil
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
