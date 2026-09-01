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

// frameInfo describes one stack frame in terms every export encoding needs,
// with none of the encoding in it. The arrow writers and the OTLP pprofile
// builder share it so a fork bump that changes libpf.Frame breaks one place.
type frameInfo struct {
	// FrameType is the libpf frame-type string: "native", "kernel",
	// "cuda-pc", "python" and so on. Symbolization gates on it.
	FrameType string

	// Address is mapping-relative, or a line number for interpreted frames.
	Address uint64

	MappingFile string
	// HasMappingFile separates an empty filename from an absent one; the
	// arrow writers append null for absent rather than "".
	HasMappingFile bool

	// BuildID is the GNU build ID, or the FileID hash ("htlhash") when the
	// object has none. It is what the debuginfo pipeline keys artifacts on.
	// GNUBuildID and GoBuildID are the untangled forms, which OTLP emits
	// under distinct semconv keys and arrow does not carry.
	BuildID    string
	GNUBuildID string
	GoBuildID  string

	// Function is set only when the agent resolved the symbol. Native frames
	// leave it unset and are symbolized server-side from BuildID+Address.
	Function    FunctionV2
	HasFunction bool
	Line        uint64
	Column      uint64
}

// classifyFrame renders one libpf.Frame into the description above, case for
// case as the v2 arrow writer always has. executables supplies file names and
// build IDs for mappings already seen via ReportExecutable.
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
		// One mapping per cubin, keyed by the cubin CRC FileID rather than
		// anything per-function. The mangled kernel name rides as the system
		// name so the backend can key its artifact on (CRC, kernel name).
		if hasMapping {
			fi.MappingFile, fi.HasMappingFile = mf.FileName.String(), true
			fi.BuildID = mf.FileID.StringNoQuotes()
		}
		fi.Function = FunctionV2{SystemName: frame.FunctionName.String()}
		fi.HasFunction = true

	default:
		// Interpreted frames arrive already symbolized and never reach the
		// debuginfo pipeline, but forward a GNU build ID when there is one so
		// the backend can still do sourcemap resolution.
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
