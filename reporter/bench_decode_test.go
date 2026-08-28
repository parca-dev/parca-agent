// SPDX-License-Identifier: Apache-2.0

// Row-to-event decoding for the encoder benchmarks. Splitting this from the
// file framing keeps the arrow-specific ugliness in one place.
package reporter

import (
	"fmt"
	"strconv"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/cespare/xxhash/v2"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// reeString reads a run-end-encoded string column at a logical row index.
// Every scalar column in the v2 schema is REE, so every read goes through here.
func reeString(col arrow.Array, row int) string {
	ree, ok := col.(*array.RunEndEncoded)
	if !ok {
		return ""
	}
	phys := ree.GetPhysicalIndex(row)
	switch vals := ree.Values().(type) {
	case *array.String:
		if vals.IsNull(phys) {
			return ""
		}
		return vals.Value(phys)
	case *array.Dictionary:
		if vals.IsNull(phys) {
			return ""
		}
		dict, ok := vals.Dictionary().(*array.String)
		if !ok {
			return ""
		}
		return dict.Value(vals.GetValueIndex(phys))
	default:
		return ""
	}
}

// dictString reads a plain (non-REE) dictionary-encoded string.
func dictString(col arrow.Array, row int) string {
	d, ok := col.(*array.Dictionary)
	if !ok || d.IsNull(row) {
		return ""
	}
	vals, ok := d.Dictionary().(*array.String)
	if !ok {
		return ""
	}
	return vals.Value(d.GetValueIndex(row))
}

// labelColumns indexes the labels struct once per record rather than per row.
type labelColumns struct {
	byName map[string]arrow.Array
}

func newLabelColumns(rec arrow.RecordBatch) (*labelColumns, error) {
	idx := rec.Schema().FieldIndices("labels")
	if len(idx) == 0 {
		return nil, fmt.Errorf("no labels column")
	}
	st, ok := rec.Column(idx[0]).(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("labels column is %T, want struct", rec.Column(idx[0]))
	}

	fields := rec.Schema().Field(idx[0]).Type.(*arrow.StructType).Fields()
	lc := &labelColumns{byName: make(map[string]arrow.Array, len(fields))}
	for i, f := range fields {
		lc.byName[f.Name] = st.Field(i)
	}
	return lc, nil
}

func (l *labelColumns) get(name string, row int) string {
	col, ok := l.byName[name]
	if !ok {
		return ""
	}
	return reeString(col, row)
}

func (l *labelColumns) uint32(name string, row int) uint32 {
	v, err := strconv.ParseUint(l.get(name, row), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// eventsFromRecord turns every row of a v2 sample record back into the
// ReportTraceEvent arguments that produced it.
func eventsFromRecord(rec arrow.RecordBatch, mappings map[string]libpf.FrameMapping) ([]traceEvent, error) {
	labelCols, err := newLabelColumns(rec)
	if err != nil {
		return nil, err
	}

	stackCol, err := column[*array.ListView](rec, "stacktrace")
	if err != nil {
		return nil, err
	}
	locations, ok := stackCol.ListValues().(*array.Dictionary)
	if !ok {
		return nil, fmt.Errorf("stacktrace values are %T, want dictionary", stackCol.ListValues())
	}
	locStruct, ok := locations.Dictionary().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("location dictionary is %T, want struct", locations.Dictionary())
	}

	locFields := locations.Dictionary().DataType().(*arrow.StructType)
	addrCol := locStruct.Field(fieldIndex(locFields, "address")).(*array.Uint64)
	typeCol := locStruct.Field(fieldIndex(locFields, "frame_type"))
	fileCol := locStruct.Field(fieldIndex(locFields, "mapping_file"))
	buildCol := locStruct.Field(fieldIndex(locFields, "mapping_build_id"))

	tsCol, err := column[*array.Timestamp](rec, "timestamp")
	if err != nil {
		return nil, err
	}
	sampleTypeIdx := rec.Schema().FieldIndices("sample_type")

	out := make([]traceEvent, 0, rec.NumRows())
	for row := 0; row < int(rec.NumRows()); row++ {
		trace := &libpf.Trace{}

		if !stackCol.IsNull(row) {
			start := int(stackCol.Offsets()[row])
			n := int(stackCol.Sizes()[row])
			for k := 0; k < n; k++ {
				li := locations.GetValueIndex(start + k)
				f := libpf.Frame{
					Type:            frameTypeFromString(dictString(typeCol, li)),
					AddressOrLineno: libpf.AddressOrLineno(addrCol.Value(li)),
					Mapping: internBenchMapping(mappings,
						dictString(fileCol, li), dictString(buildCol, li)),
				}
				trace.Frames.Append(&f)
			}
		}

		origin := libpf.Origin(support.TraceOriginSampling)
		if len(sampleTypeIdx) > 0 && reeString(rec.Column(sampleTypeIdx[0]), row) == "wallclock" {
			origin = support.TraceOriginOffCPU
		}

		out = append(out, traceEvent{
			trace: trace,
			meta: &samples.TraceEventMeta{
				Timestamp: libpf.UnixTime64(tsCol.Value(row)),
				Comm:      libpf.NewCommFromString(labelCols.get("comm", row)),
				PID:       libpf.PID(labelCols.uint32("pid", row)),
				TID:       libpf.PID(labelCols.uint32("thread_id", row)),
				CPU:       labelCols.uint32("cpu", row),
				Origin:    origin,
			},
		})
	}
	return out, nil
}

func column[T arrow.Array](rec arrow.RecordBatch, name string) (T, error) {
	var zero T
	idx := rec.Schema().FieldIndices(name)
	if len(idx) == 0 {
		return zero, fmt.Errorf("no %s column", name)
	}
	col, ok := rec.Column(idx[0]).(T)
	if !ok {
		return zero, fmt.Errorf("%s column is %T, want %T", name, rec.Column(idx[0]), zero)
	}
	return col, nil
}

func fieldIndex(st *arrow.StructType, name string) int {
	for i, f := range st.Fields() {
		if f.Name == name {
			return i
		}
	}
	return -1
}

// internBenchMapping rebuilds a FrameMapping from the only two things the arrow
// schema kept. See the FileID note in bench_corpus_test.go.
func internBenchMapping(cache map[string]libpf.FrameMapping, fileName, buildID string) libpf.FrameMapping {
	key := fileName + "\x00" + buildID
	if m, ok := cache[key]; ok {
		return m
	}

	h := xxhash.Sum64String(key)
	m := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:     libpf.NewFileID(h, h^0x9e3779b97f4a7c15),
			FileName:   libpf.Intern(fileName),
			GnuBuildID: buildID,
		}),
	})
	cache[key] = m
	return m
}

// frameTypeFromString is the inverse of libpf.FrameType.String() for the types
// the agent actually emits. An unknown string becomes a native frame rather
// than an error: a fork bump adding a type should not fail the benchmark.
func frameTypeFromString(s string) libpf.FrameType {
	switch s {
	case "native":
		return libpf.NativeFrame
	case "kernel":
		return libpf.KernelFrame
	case "python":
		return libpf.PythonFrame
	case "php":
		return libpf.PHPFrame
	case "ruby":
		return libpf.RubyFrame
	case "perl":
		return libpf.PerlFrame
	case "hotspot":
		return libpf.HotSpotFrame
	case "v8":
		return libpf.V8Frame
	case "dotnet":
		return libpf.DotnetFrame
	case "go":
		return libpf.GoFrame
	case "cuda-pc":
		return libpf.CUDAPCFrame
	default:
		return libpf.NativeFrame
	}
}
