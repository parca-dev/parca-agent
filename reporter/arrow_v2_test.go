package reporter

import (
	"testing"

	"github.com/apache/arrow/go/v18/arrow"
	"github.com/apache/arrow/go/v18/arrow/memory"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestFunctionDictBuilderV2_Deduplication(t *testing.T) {
	mem := memory.NewGoAllocator()
	builder := NewFunctionDictBuilderV2(mem)
	defer builder.Release()

	// Add first function
	f1 := FunctionV2{
		SystemName: "main",
		Filename:   "main.go",
		StartLine:  10,
	}
	idx1 := builder.AppendFunction(f1)
	require.Equal(t, uint32(0), idx1)
	require.Equal(t, 1, builder.Len())

	// Add same function again - should return same index
	idx2 := builder.AppendFunction(f1)
	require.Equal(t, uint32(0), idx2)
	require.Equal(t, 1, builder.Len()) // Still only 1 unique function

	// Add different function
	f2 := FunctionV2{
		SystemName: "helper",
		Filename:   "util.go",
		StartLine:  5,
	}
	idx3 := builder.AppendFunction(f2)
	require.Equal(t, uint32(1), idx3)
	require.Equal(t, 2, builder.Len())

	// Add first function again
	idx4 := builder.AppendFunction(f1)
	require.Equal(t, uint32(0), idx4)
	require.Equal(t, 2, builder.Len())
}

// makeAppendLocation creates a test appendLocation callback that writes native-style
// locations (no lines) directly to the builder, using the builder's LocationIndex for dedup.
func makeAppendLocation(b *StacktraceDictBuilderV2, mappingFile, mappingBuildID string) func(libpf.Frame) uint32 {
	return func(frame libpf.Frame) uint32 {
		if idx, ok := b.LocationIndex[frame]; ok {
			return idx
		}

		idx := uint32(len(b.LocationIndex))
		b.LocationIndex[frame] = idx

		b.lineListOffsets.Append(int32(b.lineNumber.Len()))
		b.locAddress.Append(uint64(frame.AddressOrLineno))
		b.locFrameType.AppendString(frame.Type.String())

		if mappingFile == "" {
			b.locMappingFile.AppendNull()
		} else {
			b.locMappingFile.AppendString(mappingFile)
		}

		if mappingBuildID == "" {
			b.locMappingID.AppendNull()
		} else {
			b.locMappingID.AppendString(mappingBuildID)
		}

		// No lines for native-style locations

		return idx
	}
}

// makeAppendLocationWithLines creates a test appendLocation callback that writes
// locations with dictionary-encoded function info.
func makeAppendLocationWithLines(b *StacktraceDictBuilderV2) func(libpf.Frame) uint32 {
	return func(frame libpf.Frame) uint32 {
		if idx, ok := b.LocationIndex[frame]; ok {
			return idx
		}

		idx := uint32(len(b.LocationIndex))
		b.LocationIndex[frame] = idx

		b.lineListOffsets.Append(int32(b.lineNumber.Len()))
		b.locAddress.Append(uint64(frame.AddressOrLineno))
		b.locFrameType.AppendString(frame.Type.String())

		switch frame.Type {
		case libpf.NativeFrame:
			b.locMappingFile.AppendString("/usr/bin/app")
			b.locMappingID.AppendString("build123")
			// No lines
		case libpf.KernelFrame:
			b.locMappingFile.AppendString("[kernel.kallsyms]")
			b.locMappingID.AppendNull()

			b.lineNumber.Append(int64(frame.SourceLine))
			b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
				SystemName: frame.FunctionName.String(),
				Filename:   "",
				StartLine:  0,
			}))
		case libpf.AbortFrame:
			b.locMappingFile.AppendString("agent-internal-error-frame")
			b.locMappingID.AppendNull()

			b.lineNumber.Append(0)
			b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
				SystemName: "aborted",
				Filename:   "",
				StartLine:  0,
			}))
		default:
			b.locMappingFile.AppendString(frame.Type.String())
			b.locMappingID.AppendNull()

			b.lineNumber.Append(int64(frame.SourceLine))
			b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
				SystemName: frame.FunctionName.String(),
				Filename:   frame.SourceFile.String(),
				StartLine:  0,
			}))
		}

		return idx
	}
}

func TestStacktraceDictBuilderV2_Deduplication(t *testing.T) {
	mem := memory.NewGoAllocator()
	builder := NewStacktraceDictBuilderV2(mem)
	defer builder.Release()

	// Create test frames
	frame1 := libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x1000,
	}
	frame2 := libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x2000,
	}

	appendLocation := makeAppendLocation(builder, "/usr/bin/test", "abc123")

	// Create frames for first stacktrace
	frames1 := libpf.Frames{}
	frames1.Append(&frame1)
	frames1.Append(&frame2)

	// Create a trace hash
	hash1 := libpf.NewTraceHash(1, 2)

	// Append first stacktrace
	builder.AppendStacktrace(hash1, frames1, appendLocation)
	require.Equal(t, 1, builder.Len())
	require.Equal(t, 1, builder.UniqueStacktraces())

	// Append same stacktrace again (same hash) - should reuse dimensions
	builder.AppendStacktrace(hash1, frames1, appendLocation)
	require.Equal(t, 2, builder.Len())               // Total appended
	require.Equal(t, 1, builder.UniqueStacktraces()) // Still only 1 unique

	// Create different stacktrace
	frame3 := libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x3000,
	}
	frames2 := libpf.Frames{}
	frames2.Append(&frame3)

	hash2 := libpf.NewTraceHash(3, 4)

	// Append different stacktrace
	builder.AppendStacktrace(hash2, frames2, appendLocation)
	require.Equal(t, 3, builder.Len())
	require.Equal(t, 2, builder.UniqueStacktraces())

	// Append first stacktrace again
	builder.AppendStacktrace(hash1, frames1, appendLocation)
	require.Equal(t, 4, builder.Len())
	require.Equal(t, 2, builder.UniqueStacktraces())

	// Build the array to verify it works
	arr := builder.NewArray()
	require.NotNil(t, arr)
	require.Equal(t, 4, arr.Len())
	arr.Release()
}

func TestSampleWriterV2_Basic(t *testing.T) {
	mem := memory.NewGoAllocator()
	writer := NewSampleWriterV2(mem)
	defer writer.Release()

	appendLocation := makeAppendLocation(writer.Stacktrace, "/usr/bin/test", "abc123")

	// Create a sample
	frame := libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x1000,
	}
	frames := libpf.Frames{}
	frames.Append(&frame)
	hash := libpf.NewTraceHash(1, 2)

	// Add labels
	writer.Label("service").AppendString("my-service")
	writer.Label("pod").AppendString("pod-1")

	// Add sample data
	writer.Stacktrace.AppendStacktrace(hash, frames, appendLocation)
	writer.Value.Append(1)
	writer.Producer.AppendString("parca_agent")
	writer.SampleType.AppendString("samples")
	writer.SampleUnit.AppendString("count")
	writer.PeriodType.AppendString("cpu")
	writer.PeriodUnit.AppendString("nanoseconds")
	writer.Temporality.AppendString("delta")
	writer.Period.Append(int64(1e9) / 19)
	writer.Duration.Append(int64(1e9))
	writer.Timestamp.Append(arrow.Timestamp(int64(1234567890)))

	// Build record
	record := writer.NewRecord()
	require.NotNil(t, record)
	require.Equal(t, int64(1), record.NumRows())

	// Verify schema
	schema := record.Schema()
	require.NotNil(t, schema)

	// Check metadata
	val, ok := schema.Metadata().GetValue(MetadataSchemaVersion)
	require.True(t, ok)
	require.Equal(t, MetadataSchemaVersionV2, val)

	record.Release()
}

func TestSampleWriterV2_MultipleFrameTypes(t *testing.T) {
	mem := memory.NewGoAllocator()
	writer := NewSampleWriterV2(mem)
	defer writer.Release()

	appendLocation := makeAppendLocationWithLines(writer.Stacktrace)

	// Test with native frame
	nativeFrame := libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0x1000,
	}
	nativeFrames := libpf.Frames{}
	nativeFrames.Append(&nativeFrame)
	nativeHash := libpf.NewTraceHash(1, 1)

	writer.Stacktrace.AppendStacktrace(nativeHash, nativeFrames, appendLocation)
	writer.Value.Append(1)
	writer.Producer.AppendString("parca_agent")
	writer.SampleType.AppendString("samples")
	writer.SampleUnit.AppendString("count")
	writer.PeriodType.AppendString("cpu")
	writer.PeriodUnit.AppendString("nanoseconds")
	writer.Temporality.AppendString("delta")
	writer.Period.Append(int64(1e9) / 19)
	writer.Duration.Append(int64(1e9))
	writer.Timestamp.Append(arrow.Timestamp(int64(1234567890)))

	// Test with kernel frame
	kernelFrame := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x2000,
		FunctionName:    libpf.Intern("do_syscall_64"),
		SourceLine:      100,
	}
	kernelFrames := libpf.Frames{}
	kernelFrames.Append(&kernelFrame)
	kernelHash := libpf.NewTraceHash(2, 2)

	writer.Stacktrace.AppendStacktrace(kernelHash, kernelFrames, appendLocation)
	writer.Value.Append(1)
	writer.Producer.AppendString("parca_agent")
	writer.SampleType.AppendString("samples")
	writer.SampleUnit.AppendString("count")
	writer.PeriodType.AppendString("cpu")
	writer.PeriodUnit.AppendString("nanoseconds")
	writer.Temporality.AppendString("delta")
	writer.Period.Append(int64(1e9) / 19)
	writer.Duration.Append(int64(1e9))
	writer.Timestamp.Append(arrow.Timestamp(int64(1234567891)))

	// Build and verify
	record := writer.NewRecord()
	require.NotNil(t, record)
	require.Equal(t, int64(2), record.NumRows())

	record.Release()
}

func TestFunctionDictBuilderV2_UsedInStacktrace(t *testing.T) {
	mem := memory.NewGoAllocator()
	builder := NewStacktraceDictBuilderV2(mem)
	defer builder.Release()

	// Create frames that share the same function at different addresses
	frame1 := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x1000,
		FunctionName:    libpf.Intern("do_syscall_64"),
		SourceLine:      100,
	}
	frame2 := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x2000,
		FunctionName:    libpf.Intern("do_syscall_64"), // same function, different address
		SourceLine:      200,
	}
	frame3 := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x3000,
		FunctionName:    libpf.Intern("sys_read"), // different function
		SourceLine:      50,
	}

	appendLocation := makeAppendLocationWithLines(builder)

	frames := libpf.Frames{}
	frames.Append(&frame1)
	frames.Append(&frame2)
	frames.Append(&frame3)

	hash := libpf.NewTraceHash(1, 1)
	builder.AppendStacktrace(hash, frames, appendLocation)

	// 3 unique locations (different addresses)
	require.Equal(t, 3, len(builder.LocationIndex))

	// But only 2 unique functions ("do_syscall_64" is deduplicated despite different lines)
	require.Equal(t, 2, builder.funcDict.Len())

	// Build the array to verify structure
	arr := builder.NewArray()
	require.NotNil(t, arr)
	require.Equal(t, 1, arr.Len())
	arr.Release()
}
