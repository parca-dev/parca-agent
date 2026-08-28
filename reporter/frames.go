// Copyright 2026 The Parca Authors
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

package reporter

import (
	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// frameInfo is the backend-neutral description of one stack frame: everything
// an export encoding needs, with none of the encoding in it.
//
// It exists so the arrow writers and the OTLP pprofile builder classify frames
// through one function. libpf.Frame and libpf.FrameMapping are upstream types
// whose semantics can shift on a fork bump, so a second copy of this logic
// would drift silently. With one, a fork change produces one compile error.
type frameInfo struct {
	// FrameType is the libpf frame-type string ("native", "kernel",
	// "cuda-pc", "python", ...). Downstream symbolization gates on it, so
	// it is always set.
	FrameType string

	// Address is the frame's mapping-relative address, or a line number for
	// interpreted frames.
	Address uint64

	// MappingFile is the object file the frame belongs to, empty when the
	// frame has no meaningful mapping (interpreted frames).
	MappingFile string
	// HasMappingFile distinguishes an empty filename from an absent one.
	// The arrow writers append null in the absent case rather than "".
	HasMappingFile bool

	// BuildID identifies the object file for symbolization. It is the GNU
	// build ID when present, else the FileID hash ("htlhash"), and it is
	// what the debuginfo pipeline keys artifacts on. Empty means unknown.
	BuildID string
	// GNUBuildID and GoBuildID are the typed build IDs when known. OTLP
	// emits them under distinct semconv keys; arrow only carries the one
	// merged BuildID.
	GNUBuildID string
	GoBuildID  string

	// Function, when HasFunction, is the resolved symbol. Native frames
	// leave it unset and are symbolized server-side from BuildID+Address.
	Function    FunctionV2
	HasFunction bool
	Line        uint64
	Column      uint64
}

// classifyFrame renders one libpf.Frame into the neutral description above.
// executables supplies file names and build IDs for frames whose mapping the
// agent has already seen via ReportExecutable.
//
// The classification mirrors what the v2 arrow writer has always done, case
// for case, so the two backends cannot disagree about what a frame means.
func classifyFrame(frame libpf.Frame, executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]) frameInfo {
	fi := frameInfo{
		FrameType: frame.Type.String(),
		Address:   uint64(frame.AddressOrLineno),
	}

	// Error frames carry no mapping and no symbol; the sentinel file name is
	// what makes them visible in a flamegraph rather than silently absent.
	if frame.Type.IsAbort() {
		fi.MappingFile, fi.HasMappingFile = "agent-internal-error-frame", true
		fi.Function, fi.HasFunction = FunctionV2{SystemName: "aborted"}, true
		return fi
	}

	mf, hasMapping := frameMappingFile(frame)
	if hasMapping {
		fi.GNUBuildID = mf.GnuBuildID
		fi.GoBuildID = mf.GoBuildID
	}

	switch frame.Type {
	case libpf.NativeFrame:
		// Native frames are symbolized server-side, so they carry a
		// mapping and no lines. The build ID is the join key.
		if hasMapping {
			if execInfo, ok := executables.Get(mf.FileID); ok {
				fi.MappingFile, fi.HasMappingFile = execInfo.FileName, true
				if execInfo.BuildID != "" {
					fi.BuildID = execInfo.BuildID
				} else {
					fi.BuildID = mf.FileID.StringNoQuotes()
				}
				return fi
			}
		}
		// Mapping not yet reported: name it so the frame is still
		// countable, but leave the build ID empty rather than guess.
		fi.MappingFile, fi.HasMappingFile = "UNKNOWN", true

	case libpf.KernelFrame:
		fi.MappingFile, fi.HasMappingFile = "[kernel.kallsyms]", true

		moduleName := "vmlinux"
		if hasMapping {
			if execInfo, ok := executables.Get(mf.FileID); ok {
				moduleName = execInfo.FileName
			}
		}

		symbol, line := "UNKNOWN", uint64(0)
		if frame.FunctionName.String() != "" {
			symbol, line = frame.FunctionName.String(), uint64(frame.SourceLine)
		}
		fi.Function = FunctionV2{SystemName: symbol, Filename: moduleName}
		fi.HasFunction = true
		fi.Line = line

	case libpf.CUDAPCFrame:
		// CUDA PC sample: a function-relative kernel offset. One mapping
		// per cubin, keyed by the cubin CRC FileID (never a per-function
		// ID). The kernel's mangled name rides as the system name of a
		// placeholder line so the backend can derive its per-kernel
		// artifact key of (cubin CRC, hash(kernel name)); the real source
		// line is resolved downstream, gated on the "cuda-pc" frame type.
		if hasMapping {
			fi.MappingFile, fi.HasMappingFile = mf.FileName.String(), true
			fi.BuildID = mf.FileID.StringNoQuotes()
		}
		fi.Function = FunctionV2{SystemName: frame.FunctionName.String()}
		fi.HasFunction = true

	default:
		// Interpreted frames (Python, Ruby, V8, ...) arrive already
		// symbolized and never reach the debuginfo pipeline. Forward the
		// mapping's GNU build ID when present so the backend can still do
		// sourcemap resolution.
		if hasMapping && mf.GnuBuildID != "" {
			fi.BuildID = mf.GnuBuildID
		}

		functionName, filePath := "UNREPORTED", "UNREPORTED"
		if frame.FunctionName.String() != "" {
			functionName = frame.FunctionName.String()
			filePath = frame.SourceFile.String()
			fi.Line = uint64(frame.SourceLine)
		}
		// An empty path crashes the backend.
		if filePath == "" {
			filePath = "UNKNOWN"
		}
		fi.Function = FunctionV2{SystemName: functionName, Filename: filePath}
		fi.HasFunction = true
		fi.Column = uint64(frame.SourceColumn)
	}

	return fi
}

// frameMappingFile unwraps a frame's mapping file, if it has one.
func frameMappingFile(frame libpf.Frame) (libpf.FrameMappingFileData, bool) {
	if !frame.Mapping.Valid() {
		return libpf.FrameMappingFileData{}, false
	}
	m := frame.Mapping.Value()
	if m.File == (libpf.FrameMappingFile{}) {
		return libpf.FrameMappingFileData{}, false
	}
	return m.File.Value(), true
}
