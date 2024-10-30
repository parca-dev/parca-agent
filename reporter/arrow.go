package reporter

import (
	"bytes"
	"slices"
	"unsafe"

	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/memory"
	"golang.org/x/exp/maps"
)

func binaryDictionaryRunEndBuilder(arr array.Builder) *BinaryDictionaryRunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	bd := ree.ValueBuilder().(*array.BinaryDictionaryBuilder)
	idx := bd.IndexBuilder().Builder.(*array.Uint32Builder)
	return &BinaryDictionaryRunEndBuilder{
		ree: ree,
		bd:  ree.ValueBuilder().(*array.BinaryDictionaryBuilder),
		idx: idx,
	}
}

type BinaryDictionaryRunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	bd  *array.BinaryDictionaryBuilder
	idx *array.Uint32Builder
}

func (b *BinaryDictionaryRunEndBuilder) Release() {
	b.ree.Release()
}

func (b *BinaryDictionaryRunEndBuilder) NewArray() arrow.Array {
	return b.ree.NewArray()
}

func (b *BinaryDictionaryRunEndBuilder) Append(v []byte) {
	if b.idx.Len() > 0 &&
		!b.idx.IsNull(b.idx.Len()-1) &&
		bytes.Equal(v, b.bd.Value(int(b.idx.Value(b.idx.Len()-1)))) {
		b.ree.ContinueRun(1)
		return
	}
	b.ree.Append(1)
	b.bd.Append(v)
}

func (b *BinaryDictionaryRunEndBuilder) AppendN(v []byte, n uint64) {
	if b.idx.Len() > 0 &&
		!b.idx.IsNull(b.idx.Len()-1) &&
		bytes.Equal(v, b.bd.Value(int(b.idx.Value(b.idx.Len()-1)))) {
		b.ree.ContinueRun(n)
		return
	}
	b.ree.Append(n)
	b.bd.Append(v)
}

func (b *BinaryDictionaryRunEndBuilder) Len() int {
	return b.ree.Len()
}

func (b *BinaryDictionaryRunEndBuilder) EnsureLength(l int) {
	for b.ree.Len() < l {
		b.AppendNull()
	}
}

func (b *BinaryDictionaryRunEndBuilder) AppendNull() {
	b.ree.AppendNull()
}

func (b *BinaryDictionaryRunEndBuilder) AppendString(v string) {
	b.Append(unsafeStringToBytes(v))
}

func (b *BinaryDictionaryRunEndBuilder) AppendStringN(v string, n uint64) {
	b.AppendN(unsafeStringToBytes(v), n)
}

func unsafeStringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func uint64RunEndBuilder(arr array.Builder) *Uint64RunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	return &Uint64RunEndBuilder{
		ree: ree,
		ub:  ree.ValueBuilder().(*array.Uint64Builder),
	}
}

type Uint64RunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	ub  *array.Uint64Builder
}

func (b *Uint64RunEndBuilder) Release() {
	b.ree.Release()
}

func (b *Uint64RunEndBuilder) NewArray() arrow.Array {
	return b.ree.NewArray()
}

func (b *Uint64RunEndBuilder) AppendN(v uint64, n uint64) {
	if b.ub.Len() > 0 && v == b.ub.Value(b.ub.Len()-1) {
		b.ree.ContinueRun(n)
		return
	}
	b.ree.Append(n)
	b.ub.Append(v)
}

type Int64RunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	ib  *array.Int64Builder
}

func (b *Int64RunEndBuilder) Release() {
	b.ree.Release()
}

func (b *Int64RunEndBuilder) NewArray() arrow.Array {
	return b.ree.NewArray()
}

func int64RunEndBuilder(arr array.Builder) *Int64RunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	return &Int64RunEndBuilder{
		ree: ree,
		ib:  ree.ValueBuilder().(*array.Int64Builder),
	}
}

func (b *Int64RunEndBuilder) Append(v int64) {
	if b.ib.Len() > 0 && v == b.ib.Value(b.ib.Len()-1) {
		b.ree.ContinueRun(1)
		return
	}
	b.ree.Append(1)
	b.ib.Append(v)
}

type LocationsWriter struct {
	IsComplete         *array.BooleanBuilder
	LocationsList      *array.ListBuilder
	Locations          *array.StructBuilder
	Address            *array.Uint64Builder
	FrameType          *BinaryDictionaryRunEndBuilder
	MappingStart       *Uint64RunEndBuilder
	MappingLimit       *Uint64RunEndBuilder
	MappingOffset      *Uint64RunEndBuilder
	MappingFile        *BinaryDictionaryRunEndBuilder
	MappingBuildID     *BinaryDictionaryRunEndBuilder
	Lines              *array.ListBuilder
	Line               *array.StructBuilder
	LineNumber         *array.Int64Builder
	FunctionName       *array.BinaryDictionaryBuilder
	FunctionSystemName *array.BinaryDictionaryBuilder
	FunctionFilename   *BinaryDictionaryRunEndBuilder
	FunctionStartLine  *array.Int64Builder
}

func (w *LocationsWriter) NewRecord(stacktraceIDs *array.Binary) arrow.Record {
	numMappings := uint64(w.MappingFile.Len())

	// Setting mapping start, limit and offset to 0 signals to the backend that
	// in the case of a native frame the address no longer has to be adjusted
	// to the symbol table address.
	w.MappingStart.AppendN(0, numMappings)
	w.MappingLimit.AppendN(0, numMappings)
	w.MappingOffset.AppendN(0, numMappings)
	return array.NewRecord(
		arrow.NewSchema([]arrow.Field{{
			Name: "stacktrace_id",
			Type: arrow.BinaryTypes.Binary,
		}, {
			Name: "is_complete",
			Type: arrow.FixedWidthTypes.Boolean,
		}, LocationsField}, newV1Metadata()),
		[]arrow.Array{
			stacktraceIDs,
			w.IsComplete.NewArray(),
			w.LocationsList.NewArray(),
		},
		int64(stacktraceIDs.Len()),
	)
}

func (w *LocationsWriter) Release() {
	w.LocationsList.Release()
}

type SampleWriter struct {
	mem memory.Allocator

	labelBuilders map[string]*BinaryDictionaryRunEndBuilder

	StacktraceID *BinaryDictionaryRunEndBuilder
	Value        *array.Int64Builder
	Producer     *BinaryDictionaryRunEndBuilder
	SampleType   *BinaryDictionaryRunEndBuilder
	SampleUnit   *BinaryDictionaryRunEndBuilder
	PeriodType   *BinaryDictionaryRunEndBuilder
	PeriodUnit   *BinaryDictionaryRunEndBuilder
	Temporality  *BinaryDictionaryRunEndBuilder
	Period       *Int64RunEndBuilder
	Duration     *Int64RunEndBuilder
	Timestamp    *Int64RunEndBuilder
}

func (w *SampleWriter) NewRecord() arrow.Record {
	labelNames := maps.Keys(w.labelBuilders)
	slices.Sort(labelNames)

	labelArrays := make([]arrow.Array, 0, len(labelNames))
	labelFields := make([]arrow.Field, 0, len(labelNames))

	length := w.Value.Len()
	for _, labelName := range labelNames {
		b := w.labelBuilders[labelName]

		// Need to ensure that all label arrays are backfilled to match the
		// length of the rest of the arrays, the value array taken as the most
		// reliabile reference.
		b.EnsureLength(length)
		labelFields = append(labelFields, w.labelField(labelName))
		labelArrays = append(labelArrays, b.NewArray())
	}

	return array.NewRecord(
		SampleSchema(labelFields),
		append(
			labelArrays,
			w.StacktraceID.NewArray(),
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

func (w *SampleWriter) Release() {
	for _, b := range w.labelBuilders {
		b.Release()
	}
	w.StacktraceID.Release()
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

var (
	LocationsField = arrow.Field{
		Name: "locations",
		Type: arrow.ListOf(arrow.StructOf([]arrow.Field{{
			Name: "address",
			Type: arrow.PrimitiveTypes.Uint64,
		}, {
			Name: "frame_type",
			Type: arrow.RunEndEncodedOf(
				arrow.PrimitiveTypes.Int32,
				&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			),
		}, {
			Name: "mapping_start",
			Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
		}, {
			Name: "mapping_limit",
			Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
		}, {
			Name: "mapping_offset",
			Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
		}, {
			Name: "mapping_file",
			Type: arrow.RunEndEncodedOf(
				arrow.PrimitiveTypes.Int32,
				&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			),
		}, {
			Name: "mapping_build_id",
			Type: arrow.RunEndEncodedOf(
				arrow.PrimitiveTypes.Int32,
				&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			),
		}, {
			Name: "lines",
			Type: arrow.ListOf(arrow.StructOf([]arrow.Field{{
				Name: "line",
				Type: arrow.PrimitiveTypes.Int64,
			}, {
				Name: "function_name",
				Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			}, {
				Name: "function_system_name",
				Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			}, {
				Name: "function_filename",
				Type: arrow.RunEndEncodedOf(
					arrow.PrimitiveTypes.Int32,
					&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
				),
			}, {
				Name: "function_start_line",
				Type: arrow.PrimitiveTypes.Int64,
			}}...)),
		}}...)),
	}

	StacktraceIDField = arrow.Field{
		Name: "stacktrace_id",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	ValueField = arrow.Field{
		Name: "value",
		Type: arrow.PrimitiveTypes.Int64,
	}

	ProducerField = arrow.Field{
		Name: "producer",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	SampleTypeField = arrow.Field{
		Name: "sample_type",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	SampleUnitField = arrow.Field{
		Name: "sample_unit",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	PeriodTypeField = arrow.Field{
		Name: "period_type",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	PeriodUnitField = arrow.Field{
		Name: "period_unit",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	TemporalityField = arrow.Field{
		Name: "temporality",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}

	PeriodField = arrow.Field{
		Name: "period",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}

	DurationField = arrow.Field{
		Name: "duration",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}

	TimestampField = arrow.Field{
		Name: "timestamp",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}

	labelArrowType = arrow.RunEndEncodedOf(
		arrow.PrimitiveTypes.Int32,
		&arrow.DictionaryType{
			IndexType: arrow.PrimitiveTypes.Uint32,
			ValueType: arrow.BinaryTypes.Binary,
		},
	)
)

const (
	MetadataSchemaVersion   = "parca_write_schema_version"
	MetadataSchemaVersionV1 = "v1"
	ColumnLabelsPrefix      = "labels."
)

func ArrowSamplesField(profileLabelFields []arrow.Field) []arrow.Field {
	// +11 for stacktrace IDs, value, producer, sample_type, sample_unit, period_type, period_unit, temporality, period, duration, timestamp
	numFields := len(profileLabelFields) + 11
	fields := make([]arrow.Field, numFields)
	copy(fields, profileLabelFields)

	fields[numFields-11] = StacktraceIDField
	fields[numFields-10] = ValueField
	fields[numFields-9] = ProducerField
	fields[numFields-8] = SampleTypeField
	fields[numFields-7] = SampleUnitField
	fields[numFields-6] = PeriodTypeField
	fields[numFields-5] = PeriodUnitField
	fields[numFields-4] = TemporalityField
	fields[numFields-3] = PeriodField
	fields[numFields-2] = DurationField
	fields[numFields-1] = TimestampField

	return fields
}

func newV1Metadata() *arrow.Metadata {
	m := arrow.NewMetadata([]string{MetadataSchemaVersion}, []string{MetadataSchemaVersionV1})
	return &m
}

func SampleSchema(profileLabelFields []arrow.Field) *arrow.Schema {
	return arrow.NewSchema(ArrowSamplesField(profileLabelFields), newV1Metadata())
}

func (w *SampleWriter) labelField(labelName string) arrow.Field {
	return arrow.Field{
		Name:     ColumnLabelsPrefix + labelName,
		Type:     labelArrowType,
		Nullable: true,
	}
}

func (w *SampleWriter) Label(labelName string) *BinaryDictionaryRunEndBuilder {
	b, ok := w.labelBuilders[labelName]
	if !ok {
		b = binaryDictionaryRunEndBuilder(array.NewBuilder(w.mem, labelArrowType))
		w.labelBuilders[labelName] = b
	}

	b.EnsureLength(w.Value.Len())
	return b
}

func (w *SampleWriter) LabelAll(labelName, labelValue string) {
	b, ok := w.labelBuilders[labelName]
	if !ok {
		b = binaryDictionaryRunEndBuilder(array.NewBuilder(w.mem, labelArrowType))
		w.labelBuilders[labelName] = b
	}

	b.ree.Append(uint64(w.Value.Len() - b.ree.Len()))
	b.bd.AppendString(labelValue)
}

func NewLocationsWriter(mem memory.Allocator) *LocationsWriter {
	isComplete := array.NewBuilder(mem, arrow.FixedWidthTypes.Boolean).(*array.BooleanBuilder)

	locationsList := array.NewBuilder(mem, LocationsField.Type).(*array.ListBuilder)
	locations := locationsList.ValueBuilder().(*array.StructBuilder)

	addresses := locations.FieldBuilder(0).(*array.Uint64Builder)
	frameType := binaryDictionaryRunEndBuilder(locations.FieldBuilder(1))

	mappingStart := uint64RunEndBuilder(locations.FieldBuilder(2))
	mappingLimit := uint64RunEndBuilder(locations.FieldBuilder(3))
	mappingOffset := uint64RunEndBuilder(locations.FieldBuilder(4))
	mappingFile := binaryDictionaryRunEndBuilder(locations.FieldBuilder(5))
	mappingBuildID := binaryDictionaryRunEndBuilder(locations.FieldBuilder(6))

	lines := locations.FieldBuilder(7).(*array.ListBuilder)
	line := lines.ValueBuilder().(*array.StructBuilder)
	lineNumber := line.FieldBuilder(0).(*array.Int64Builder)
	functionName := line.FieldBuilder(1).(*array.BinaryDictionaryBuilder)
	functionSystemName := line.FieldBuilder(2).(*array.BinaryDictionaryBuilder)
	functionFilename := binaryDictionaryRunEndBuilder(line.FieldBuilder(3))
	functionStartLine := line.FieldBuilder(4).(*array.Int64Builder)

	return &LocationsWriter{
		IsComplete:         isComplete,
		LocationsList:      locationsList,
		Locations:          locations,
		Address:            addresses,
		FrameType:          frameType,
		MappingStart:       mappingStart,
		MappingLimit:       mappingLimit,
		MappingOffset:      mappingOffset,
		MappingFile:        mappingFile,
		MappingBuildID:     mappingBuildID,
		Lines:              lines,
		Line:               line,
		LineNumber:         lineNumber,
		FunctionName:       functionName,
		FunctionSystemName: functionSystemName,
		FunctionFilename:   functionFilename,
		FunctionStartLine:  functionStartLine,
	}
}

func NewSampleWriter(mem memory.Allocator) *SampleWriter {
	stacktraceID := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, StacktraceIDField.Type))
	value := array.NewBuilder(mem, ValueField.Type).(*array.Int64Builder)
	producer := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, ProducerField.Type))
	sampleType := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, SampleTypeField.Type))
	sampleUnit := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, SampleUnitField.Type))
	periodType := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, PeriodTypeField.Type))
	periodUnit := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, PeriodUnitField.Type))
	temporality := binaryDictionaryRunEndBuilder(array.NewBuilder(mem, TemporalityField.Type))
	period := int64RunEndBuilder(array.NewBuilder(mem, PeriodField.Type))
	duration := int64RunEndBuilder(array.NewBuilder(mem, DurationField.Type))
	timestamp := int64RunEndBuilder(array.NewBuilder(mem, TimestampField.Type))

	return &SampleWriter{
		mem: mem,

		labelBuilders: map[string]*BinaryDictionaryRunEndBuilder{},

		StacktraceID: stacktraceID,
		Value:        value,
		Producer:     producer,
		SampleType:   sampleType,
		SampleUnit:   sampleUnit,
		PeriodType:   periodType,
		PeriodUnit:   periodUnit,
		Temporality:  temporality,
		Period:       period,
		Duration:     duration,
		Timestamp:    timestamp,
	}
}
