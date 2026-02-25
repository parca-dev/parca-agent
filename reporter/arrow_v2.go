package reporter

import (
	"slices"

	"github.com/apache/arrow/go/v18/arrow"
	"github.com/apache/arrow/go/v18/arrow/array"
	"github.com/apache/arrow/go/v18/arrow/memory"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/exp/maps"
)

// V2 Schema Constants
const (
	MetadataSchemaVersionV2 = "v2"
)

// FunctionV2 represents a function for deduplication purposes.
type FunctionV2 struct {
	SystemName string
	Filename   string
	StartLine  int64
}

// listEntryRef stores the offset and size for ListView deduplication.
type listEntryRef struct {
	offset   int
	listSize int
}

// V2 Schema Field Definitions using StringView for better memory efficiency

var (
	// FunctionFieldTypeV2 defines the function struct type for v2.
	FunctionFieldTypeV2 = arrow.StructOf(
		arrow.Field{Name: "system_name", Type: arrow.BinaryTypes.StringView, Nullable: true},
		arrow.Field{Name: "filename", Type: arrow.BinaryTypes.StringView, Nullable: true},
		arrow.Field{Name: "start_line", Type: arrow.PrimitiveTypes.Int64, Nullable: false},
	)

	// FunctionDictTypeV2 is a dictionary of functions for efficient storage.
	FunctionDictTypeV2 = &arrow.DictionaryType{
		IndexType: arrow.PrimitiveTypes.Uint32,
		ValueType: FunctionFieldTypeV2,
	}

	// LineFieldTypeV2 defines the line struct type for v2.
	LineFieldTypeV2 = arrow.StructOf(
		arrow.Field{Name: "line", Type: arrow.PrimitiveTypes.Int64, Nullable: false},
		arrow.Field{Name: "function", Type: FunctionDictTypeV2, Nullable: false},
	)

	// LocationTypeV2 defines the location struct type for v2.
	LocationTypeV2 = arrow.StructOf(
		arrow.Field{Name: "address", Type: arrow.PrimitiveTypes.Uint64, Nullable: false},
		arrow.Field{Name: "frame_type", Type: arrow.BinaryTypes.StringView, Nullable: false},
		arrow.Field{Name: "mapping_file", Type: arrow.BinaryTypes.StringView, Nullable: true},
		arrow.Field{Name: "mapping_build_id", Type: arrow.BinaryTypes.StringView, Nullable: true},
		arrow.Field{Name: "lines", Type: arrow.ListOf(LineFieldTypeV2), Nullable: false},
	)

	// LocationDictTypeV2 is a dictionary of locations for efficient storage.
	LocationDictTypeV2 = &arrow.DictionaryType{
		IndexType: arrow.PrimitiveTypes.Uint32,
		ValueType: LocationTypeV2,
	}

	// StacktraceTypeV2 is a ListView of dictionary-encoded locations.
	// - Dictionary deduplicates individual locations
	// - ListView allows reusing offset/size for identical stacktraces
	StacktraceTypeV2 = arrow.ListViewOf(LocationDictTypeV2)

	// StacktraceFieldV2 is the field definition for stacktraces in the v2 sample schema.
	StacktraceFieldV2 = arrow.Field{
		Name:     "stacktrace",
		Type:     StacktraceTypeV2,
		Nullable: false,
	}

	TimestampFieldV2 = arrow.Field{
		Name: "timestamp",
		Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"},
	}

	ProducerFieldV2 = arrow.Field{
		Name: "producer",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}

	SampleTypeFieldV2 = arrow.Field{
		Name: "sample_type",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}

	SampleUnitFieldV2 = arrow.Field{
		Name: "sample_unit",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}

	PeriodTypeFieldV2 = arrow.Field{
		Name: "period_type",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}

	PeriodUnitFieldV2 = arrow.Field{
		Name: "period_unit",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}

	TemporalityFieldV2 = arrow.Field{
		Name:     "temporality",
		Nullable: true,
		Type:     arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.BinaryTypes.String),
	}
)

// FunctionDictBuilderV2 deduplicates functions using a map.
type FunctionDictBuilderV2 struct {
	mem      memory.Allocator
	index    map[FunctionV2]uint32
	builder  *array.StructBuilder
	sysName  *array.StringViewBuilder
	filename *array.StringViewBuilder
	startLn  *array.Int64Builder
}

// NewFunctionDictBuilderV2 creates a new FunctionDictBuilderV2.
func NewFunctionDictBuilderV2(mem memory.Allocator) *FunctionDictBuilderV2 {
	builder := array.NewStructBuilder(mem, FunctionFieldTypeV2)
	return &FunctionDictBuilderV2{
		mem:      mem,
		index:    make(map[FunctionV2]uint32),
		builder:  builder,
		sysName:  builder.FieldBuilder(0).(*array.StringViewBuilder),
		filename: builder.FieldBuilder(1).(*array.StringViewBuilder),
		startLn:  builder.FieldBuilder(2).(*array.Int64Builder),
	}
}

// AppendFunction adds a function and returns its dictionary index.
func (b *FunctionDictBuilderV2) AppendFunction(f FunctionV2) uint32 {
	if idx, ok := b.index[f]; ok {
		return idx
	}

	idx := uint32(len(b.index))
	b.index[f] = idx

	b.builder.Append(true)
	if f.SystemName == "" {
		b.sysName.AppendNull()
	} else {
		b.sysName.AppendString(f.SystemName)
	}
	if f.Filename == "" {
		b.filename.AppendNull()
	} else {
		b.filename.AppendString(f.Filename)
	}
	b.startLn.Append(f.StartLine)

	return idx
}

// Len returns the number of unique functions.
func (b *FunctionDictBuilderV2) Len() int {
	return len(b.index)
}

// Release releases the builder resources.
func (b *FunctionDictBuilderV2) Release() {
	b.builder.Release()
}

// StacktraceDictBuilderV2 deduplicates stacktraces using TraceHash and ListView.
// Structure: ListView[Dictionary[Uint32, LocationTypeV2]]
// - Dictionary handles location-level deduplication (manual construction)
// - ListView handles stacktrace-level deduplication via offset/size reuse
// - Functions within lines are dictionary-encoded for deduplication
//
// Since Arrow v16 doesn't have StructDictionaryBuilder, we build the dictionaries
// manually: separate arrays for values, uint32 arrays for indices.
type StacktraceDictBuilderV2 struct {
	mem   memory.Allocator
	index map[libpf.TraceHash]listEntryRef

	// ListView components (built manually)
	offsets *array.Int32Builder
	sizes   *array.Int32Builder

	// Dictionary indices for locations (what the ListView values reference)
	indices *array.Uint32Builder

	// Location fields (individual builders, composed into struct at build time)
	locAddress     *array.Uint64Builder
	locFrameType   *array.StringViewBuilder
	locMappingFile *array.StringViewBuilder
	locMappingID   *array.StringViewBuilder

	// Lines list: offsets track where each location's lines start
	lineListOffsets *array.Int32Builder

	// Line fields
	lineNumber *array.Int64Builder

	// Function dictionary encoding
	funcIndices *array.Uint32Builder
	funcDict    *FunctionDictBuilderV2

	// Track locations for deduplication: frame -> dictionary index
	LocationIndex map[libpf.Frame]uint32

	// Number of ListView entries
	length int
}

// NewStacktraceDictBuilderV2 creates a new StacktraceDictBuilderV2.
func NewStacktraceDictBuilderV2(mem memory.Allocator) *StacktraceDictBuilderV2 {
	return &StacktraceDictBuilderV2{
		mem:             mem,
		index:           make(map[libpf.TraceHash]listEntryRef),
		offsets:         array.NewInt32Builder(mem),
		sizes:           array.NewInt32Builder(mem),
		indices:         array.NewUint32Builder(mem),
		locAddress:      array.NewUint64Builder(mem),
		locFrameType:    array.NewBuilder(mem, arrow.BinaryTypes.StringView).(*array.StringViewBuilder),
		locMappingFile:  array.NewBuilder(mem, arrow.BinaryTypes.StringView).(*array.StringViewBuilder),
		locMappingID:    array.NewBuilder(mem, arrow.BinaryTypes.StringView).(*array.StringViewBuilder),
		lineListOffsets: array.NewInt32Builder(mem),
		lineNumber:      array.NewInt64Builder(mem),
		funcIndices:     array.NewUint32Builder(mem),
		funcDict:        NewFunctionDictBuilderV2(mem),
		LocationIndex:   make(map[libpf.Frame]uint32),
		length:          0,
	}
}

// AppendStacktrace appends a stacktrace, reusing ListView dimensions for duplicates.
// The appendLocation callback is called for each frame; it handles dedup, frame
// resolution, and writing to the arrow builders, returning the dictionary index.
func (b *StacktraceDictBuilderV2) AppendStacktrace(
	traceHash libpf.TraceHash,
	frames libpf.Frames,
	appendLocation func(frame libpf.Frame) uint32,
) {
	if entry, ok := b.index[traceHash]; ok {
		// Reuse existing ListView dimensions
		b.offsets.Append(int32(entry.offset))
		b.sizes.Append(int32(entry.listSize))
		b.length++
		return
	}

	// New stacktrace - resolve and append each frame
	startOffset := b.indices.Len()
	listSize := 0

	for _, frameHandle := range frames {
		frame := frameHandle.Value()
		idx := appendLocation(frame)
		b.indices.Append(idx)
		listSize++
	}

	// Record the entry for future deduplication
	b.index[traceHash] = listEntryRef{
		offset:   startOffset,
		listSize: listSize,
	}

	// Append the dimensions for this new entry
	b.offsets.Append(int32(startOffset))
	b.sizes.Append(int32(listSize))
	b.length++
}

// AppendNull appends a null stacktrace.
// For ListView, null is represented by size=0 with any offset.
func (b *StacktraceDictBuilderV2) AppendNull() {
	b.offsets.Append(0)
	b.sizes.Append(0)
	b.length++
}

// Len returns the number of stacktraces appended.
func (b *StacktraceDictBuilderV2) Len() int {
	return b.length
}

// UniqueStacktraces returns the number of unique stacktraces.
func (b *StacktraceDictBuilderV2) UniqueStacktraces() int {
	return len(b.index)
}

// NewArray builds and returns the ListView[Dictionary[Uint32, LocationTypeV2]] array.
// This manually constructs the full array hierarchy since Arrow v16 lacks StructDictionaryBuilder.
// The hierarchy is: ListView → Dict[Uint32, LocationStruct] → ... → lines list → Dict[Uint32, FunctionStruct].
func (b *StacktraceDictBuilderV2) NewArray() arrow.Array {
	numLocations := b.locAddress.Len()

	// Build stacktrace ListView components
	stOffsets := b.offsets.NewArray()
	defer stOffsets.Release()
	stSizes := b.sizes.NewArray()
	defer stSizes.Release()
	locIndices := b.indices.NewArray()
	defer locIndices.Release()

	// Build function dictionary: Dict[Uint32, FunctionStruct]
	funcValues := b.funcDict.builder.NewArray()
	defer funcValues.Release()
	funcIdxArr := b.funcIndices.NewArray()
	defer funcIdxArr.Release()
	funcDictArr := array.NewDictionaryArray(FunctionDictTypeV2, funcIdxArr, funcValues)
	defer funcDictArr.Release()

	// Build line number array
	lineNumArr := b.lineNumber.NewArray()
	defer lineNumArr.Release()
	numLines := lineNumArr.Len()

	// Build line struct: {line: Int64, function: Dict[Uint32, FunctionStruct]}
	lineStructData := array.NewData(
		LineFieldTypeV2,
		numLines,
		[]*memory.Buffer{nil}, // validity (all lines valid)
		[]arrow.ArrayData{lineNumArr.Data(), funcDictArr.Data()},
		0, 0,
	)
	defer lineStructData.Release()

	// Build line list offsets (add final offset for Arrow List format: n+1 offsets for n entries)
	b.lineListOffsets.Append(int32(numLines))
	lineOffsetsArr := b.lineListOffsets.NewArray()
	defer lineOffsetsArr.Release()

	// Build lines list: List[LineStruct]
	linesListData := array.NewData(
		arrow.ListOf(LineFieldTypeV2),
		numLocations,
		[]*memory.Buffer{
			nil,                                // validity (no nulls)
			lineOffsetsArr.Data().Buffers()[1], // offsets buffer
		},
		[]arrow.ArrayData{lineStructData},
		0, 0,
	)
	defer linesListData.Release()

	// Build location field arrays
	addrArr := b.locAddress.NewArray()
	defer addrArr.Release()
	ftArr := b.locFrameType.NewArray()
	defer ftArr.Release()
	mfArr := b.locMappingFile.NewArray()
	defer mfArr.Release()
	midArr := b.locMappingID.NewArray()
	defer midArr.Release()

	// Build location struct from individual field arrays
	locStructData := array.NewData(
		LocationTypeV2,
		numLocations,
		[]*memory.Buffer{nil}, // validity (all locations valid)
		[]arrow.ArrayData{
			addrArr.Data(),
			ftArr.Data(),
			mfArr.Data(),
			midArr.Data(),
			linesListData,
		},
		0, 0,
	)
	defer locStructData.Release()
	locStructArr := array.MakeFromData(locStructData)
	defer locStructArr.Release()

	// Build location dictionary: Dict[Uint32, LocationStruct]
	locDictArr := array.NewDictionaryArray(LocationDictTypeV2, locIndices, locStructArr)
	defer locDictArr.Release()

	// Build ListView
	listViewData := array.NewData(
		StacktraceTypeV2,
		b.length,
		[]*memory.Buffer{
			nil,                           // validity bitmap (no nulls)
			stOffsets.Data().Buffers()[1], // offsets buffer
			stSizes.Data().Buffers()[1],   // sizes buffer
		},
		[]arrow.ArrayData{locDictArr.Data()},
		0, 0,
	)
	defer listViewData.Release()

	return array.NewListViewData(listViewData)
}

// Release releases all builder resources.
func (b *StacktraceDictBuilderV2) Release() {
	b.offsets.Release()
	b.sizes.Release()
	b.indices.Release()
	b.locAddress.Release()
	b.locFrameType.Release()
	b.locMappingFile.Release()
	b.locMappingID.Release()
	b.lineListOffsets.Release()
	b.lineNumber.Release()
	b.funcIndices.Release()
	b.funcDict.Release()
}

// SampleWriterV2 writes samples with inline stacktraces using the v2 schema.
type SampleWriterV2 struct {
	mem memory.Allocator

	labelBuilders map[string]*BinaryDictionaryRunEndBuilder

	// Stacktrace with deduplication
	Stacktrace *StacktraceDictBuilderV2

	// Sample data fields (same as v1)
	Value       *array.Int64Builder
	Producer    *StringRunEndBuilder
	SampleType  *StringRunEndBuilder
	SampleUnit  *StringRunEndBuilder
	PeriodType  *StringRunEndBuilder
	PeriodUnit  *StringRunEndBuilder
	Temporality *StringRunEndBuilder
	Period      *Int64RunEndBuilder
	Duration    *Int64RunEndBuilder
	Timestamp   *array.TimestampBuilder
}

// NewSampleWriterV2 creates a new SampleWriterV2.
func NewSampleWriterV2(mem memory.Allocator) *SampleWriterV2 {
	return &SampleWriterV2{
		mem:           mem,
		labelBuilders: make(map[string]*BinaryDictionaryRunEndBuilder),
		Stacktrace:    NewStacktraceDictBuilderV2(mem),
		Value:         array.NewInt64Builder(mem),
		Producer:      stringRunEndBuilder(array.NewBuilder(mem, ProducerFieldV2.Type)),
		SampleType:    stringRunEndBuilder(array.NewBuilder(mem, SampleTypeFieldV2.Type)),
		SampleUnit:    stringRunEndBuilder(array.NewBuilder(mem, SampleUnitFieldV2.Type)),
		PeriodType:    stringRunEndBuilder(array.NewBuilder(mem, PeriodTypeFieldV2.Type)),
		PeriodUnit:    stringRunEndBuilder(array.NewBuilder(mem, PeriodUnitFieldV2.Type)),
		Temporality:   stringRunEndBuilder(array.NewBuilder(mem, TemporalityFieldV2.Type)),
		Period:        int64RunEndBuilder(array.NewBuilder(mem, PeriodField.Type)),
		Duration:      int64RunEndBuilder(array.NewBuilder(mem, DurationField.Type)),
		Timestamp:     array.NewBuilder(mem, TimestampFieldV2.Type).(*array.TimestampBuilder),
	}
}

// Label returns the label builder for the given label name, creating it if necessary.
func (w *SampleWriterV2) Label(labelName string) *BinaryDictionaryRunEndBuilder {
	b, ok := w.labelBuilders[labelName]
	if !ok {
		b = binaryDictionaryRunEndBuilder(array.NewBuilder(w.mem, labelArrowType))
		w.labelBuilders[labelName] = b
	}

	b.EnsureLength(w.Value.Len())
	return b
}

// LabelAll sets a label value for all samples in the current batch.
func (w *SampleWriterV2) LabelAll(labelName, labelValue string) {
	b, ok := w.labelBuilders[labelName]
	if !ok {
		b = binaryDictionaryRunEndBuilder(array.NewBuilder(w.mem, labelArrowType))
		w.labelBuilders[labelName] = b
	}

	b.ree.Append(uint64(w.Value.Len() - b.ree.Len()))
	b.bd.AppendString(labelValue)
}

// labelField returns the Arrow field definition for a label.
func (w *SampleWriterV2) labelField(labelName string) arrow.Field {
	return arrow.Field{
		Name:     ColumnLabelsPrefix + labelName,
		Type:     labelArrowType,
		Nullable: true,
	}
}

// SampleSchemaV2 creates the v2 sample schema with the given label fields.
func SampleSchemaV2(profileLabelFields []arrow.Field) *arrow.Schema {
	return arrow.NewSchema(ArrowSamplesFieldV2(profileLabelFields), newV2Metadata())
}

// ArrowSamplesFieldV2 returns the fields for the v2 sample schema.
func ArrowSamplesFieldV2(profileLabelFields []arrow.Field) []arrow.Field {
	// +11 for stacktrace, value, producer, sample_type, sample_unit, period_type, period_unit, temporality, period, duration, timestamp
	numFields := len(profileLabelFields) + 11
	fields := make([]arrow.Field, numFields)
	copy(fields, profileLabelFields)

	fields[numFields-11] = StacktraceFieldV2
	fields[numFields-10] = ValueField
	fields[numFields-9] = ProducerFieldV2
	fields[numFields-8] = SampleTypeFieldV2
	fields[numFields-7] = SampleUnitFieldV2
	fields[numFields-6] = PeriodTypeFieldV2
	fields[numFields-5] = PeriodUnitFieldV2
	fields[numFields-4] = TemporalityFieldV2
	fields[numFields-3] = PeriodField
	fields[numFields-2] = DurationField
	fields[numFields-1] = TimestampFieldV2

	return fields
}

func newV2Metadata() *arrow.Metadata {
	m := arrow.NewMetadata([]string{MetadataSchemaVersion}, []string{MetadataSchemaVersionV2})
	return &m
}

// NewRecord builds and returns an Arrow record with all samples.
func (w *SampleWriterV2) NewRecord() arrow.Record {
	labelNames := maps.Keys(w.labelBuilders)
	slices.Sort(labelNames)

	labelArrays := make([]arrow.Array, 0, len(labelNames))
	labelFields := make([]arrow.Field, 0, len(labelNames))

	length := w.Value.Len()
	for _, labelName := range labelNames {
		b := w.labelBuilders[labelName]

		// Ensure all label arrays are backfilled to match the length
		b.EnsureLength(length)
		labelFields = append(labelFields, w.labelField(labelName))
		labelArrays = append(labelArrays, b.NewArray())
	}

	return array.NewRecord(
		SampleSchemaV2(labelFields),
		append(
			labelArrays,
			w.Stacktrace.NewArray(),
			w.Value.NewArray(),
			w.Producer.NewArray(),
			w.SampleType.NewArray(),
			w.SampleUnit.NewArray(),
			w.PeriodType.NewArray(),
			w.PeriodUnit.NewArray(),
			w.Temporality.NewArray(),
			w.Period.NewArray(),
			w.Duration.NewArray(),
			w.Timestamp.NewArray(),
		),
		int64(length),
	)
}

// Release releases all builder resources.
func (w *SampleWriterV2) Release() {
	for _, b := range w.labelBuilders {
		b.Release()
	}
	w.Stacktrace.Release()
	w.Value.Release()
	w.Producer.Release()
	w.SampleType.Release()
	w.SampleUnit.Release()
	w.PeriodType.Release()
	w.PeriodUnit.Release()
	w.Temporality.Release()
	w.Period.Release()
	w.Duration.Release()
	w.Timestamp.Release()
}
