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

package main

import (
	"fmt"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
)

// decodeArrowV2 turns one v2 sample record into canonical samples.
//
// Every scalar column is run-end encoded and most are dictionary encoded on top
// of that, so reading row i means resolving a run index and then a dictionary
// index. reeResolver does that once per column rather than per row, which
// matters at ~200k rows per batch.
func decodeArrowV2(rec arrow.Record) ([]canonSample, error) {
	n := int(rec.NumRows())
	out := make([]canonSample, n)

	col := func(name string) (arrow.Array, error) {
		for i, f := range rec.Schema().Fields() {
			if f.Name == name {
				return rec.Column(i), nil
			}
		}
		return nil, fmt.Errorf("column %q not found", name)
	}

	// Labels: a struct whose children are one run-end/dictionary column each.
	labelsArr, err := col("labels")
	if err != nil {
		return nil, err
	}
	labelStruct, ok := labelsArr.(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("labels column is %T, want *array.Struct", labelsArr)
	}
	labelType := labelStruct.DataType().(*arrow.StructType)
	labelResolvers := make([]*reeStringResolver, labelStruct.NumField())
	for i := 0; i < labelStruct.NumField(); i++ {
		r, err := newREEStringResolver(labelStruct.Field(i))
		if err != nil {
			return nil, fmt.Errorf("label %s: %w", labelType.Field(i).Name, err)
		}
		labelResolvers[i] = r
	}

	strCols := map[string]*reeStringResolver{}
	for _, name := range []string{"producer", "sample_type", "sample_unit", "period_type", "period_unit", "temporality"} {
		a, err := col(name)
		if err != nil {
			return nil, err
		}
		r, err := newREEStringResolver(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		strCols[name] = r
	}

	valueArr, err := col("value")
	if err != nil {
		return nil, err
	}
	valueRes, err := newREEIntResolver(valueArr)
	if err != nil {
		return nil, fmt.Errorf("value: %w", err)
	}

	periodArr, err := col("period")
	if err != nil {
		return nil, err
	}
	periodRes, err := newREEIntResolver(periodArr)
	if err != nil {
		return nil, fmt.Errorf("period: %w", err)
	}

	durationArr, err := col("duration")
	if err != nil {
		return nil, err
	}
	durationRes, err := newREEIntResolver(durationArr)
	if err != nil {
		return nil, fmt.Errorf("duration: %w", err)
	}

	tsArr, err := col("timestamp")
	if err != nil {
		return nil, err
	}
	ts, ok := tsArr.(*array.Timestamp)
	if !ok {
		return nil, fmt.Errorf("timestamp column is %T", tsArr)
	}

	sidArr, err := col("stacktrace_id")
	if err != nil {
		return nil, err
	}
	sidBytes, err := fixedSizeBinaryOf(sidArr)
	if err != nil {
		return nil, fmt.Errorf("stacktrace_id: %w", err)
	}

	stackArr, err := col("stacktrace")
	if err != nil {
		return nil, err
	}
	stacks, err := newStackDecoder(stackArr)
	if err != nil {
		return nil, fmt.Errorf("stacktrace: %w", err)
	}

	for i := 0; i < n; i++ {
		s := canonSample{
			Value:       valueRes.at(i),
			Period:      periodRes.at(i),
			Duration:    uint64(durationRes.at(i)),
			Timestamp:   uint64(ts.Value(i)),
			Producer:    strCols["producer"].at(i),
			SampleType:  strCols["sample_type"].at(i),
			SampleUnit:  strCols["sample_unit"].at(i),
			PeriodType:  strCols["period_type"].at(i),
			PeriodUnit:  strCols["period_unit"].at(i),
			Temporality: strCols["temporality"].at(i),
		}

		if sidBytes != nil && !sidArr.IsNull(i) {
			s.StacktraceID = hexOrEmpty(sidBytes.Value(i))
		}

		lbls := make(map[string]string)
		for j, r := range labelResolvers {
			if v := r.at(i); v != "" {
				lbls[labelType.Field(j).Name] = v
			}
		}
		if len(lbls) > 0 {
			s.Labels = lbls
		}

		st, err := stacks.at(i)
		if err != nil {
			return nil, fmt.Errorf("row %d stacktrace: %w", i, err)
		}
		s.Stack = st

		out[i] = s
	}

	return out, nil
}

// reeStringResolver reads a run-end encoded column whose values are either
// strings or dictionary-encoded strings.
type reeStringResolver struct {
	runEnds []int32
	// values is indexed by run, already resolved to a string.
	values []string
	// cursor caches the last run found, since reads are sequential.
	cursor int
}

func newREEStringResolver(a arrow.Array) (*reeStringResolver, error) {
	ree, ok := a.(*array.RunEndEncoded)
	if !ok {
		return nil, fmt.Errorf("expected run-end encoded, got %T", a)
	}
	runEnds, err := runEndsOf(ree)
	if err != nil {
		return nil, err
	}

	vals := ree.Values()
	out := make([]string, len(runEnds))

	switch v := vals.(type) {
	case *array.Dictionary:
		dict, ok := v.Dictionary().(*array.String)
		if !ok {
			return nil, fmt.Errorf("dictionary values are %T, want *array.String", v.Dictionary())
		}
		for i := range runEnds {
			if v.IsNull(i) {
				continue
			}
			out[i] = dict.Value(v.GetValueIndex(i))
		}
	case *array.String:
		for i := range runEnds {
			if v.IsNull(i) {
				continue
			}
			out[i] = v.Value(i)
		}
	default:
		return nil, fmt.Errorf("unsupported ree value type %T", vals)
	}

	return &reeStringResolver{runEnds: runEnds, values: out}, nil
}

func (r *reeStringResolver) at(row int) string {
	i := r.findRun(row)
	if i < 0 {
		return ""
	}
	return r.values[i]
}

// findRun locates the run containing row, scanning forward from the cached
// cursor because callers read rows in order.
func (r *reeStringResolver) findRun(row int) int {
	if r.cursor >= len(r.runEnds) || int(r.runEnds[r.cursor]) <= row {
		for r.cursor < len(r.runEnds) && int(r.runEnds[r.cursor]) <= row {
			r.cursor++
		}
	} else {
		for r.cursor > 0 && int(r.runEnds[r.cursor-1]) > row {
			r.cursor--
		}
	}
	if r.cursor >= len(r.runEnds) {
		return -1
	}
	return r.cursor
}

// reeIntResolver is the integer twin of reeStringResolver.
type reeIntResolver struct {
	runEnds []int32
	values  []int64
	cursor  int

	// Set instead of the run-end fields when the column is a plain array.
	plainInt64  *array.Int64
	plainUint64 *array.Uint64
}

func newREEIntResolver(a arrow.Array) (*reeIntResolver, error) {
	// value and period are written as plain arrays; duration is run-end
	// encoded. Accept both so callers do not have to care which.
	switch v := a.(type) {
	case *array.Int64:
		return &reeIntResolver{plainInt64: v}, nil
	case *array.Uint64:
		return &reeIntResolver{plainUint64: v}, nil
	}

	ree, ok := a.(*array.RunEndEncoded)
	if !ok {
		return nil, fmt.Errorf("expected run-end encoded or plain int, got %T", a)
	}
	runEnds, err := runEndsOf(ree)
	if err != nil {
		return nil, err
	}

	out := make([]int64, len(runEnds))
	switch v := ree.Values().(type) {
	case *array.Int64:
		for i := range runEnds {
			if !v.IsNull(i) {
				out[i] = v.Value(i)
			}
		}
	case *array.Uint64:
		for i := range runEnds {
			if !v.IsNull(i) {
				out[i] = int64(v.Value(i))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported ree int value type %T", ree.Values())
	}

	return &reeIntResolver{runEnds: runEnds, values: out}, nil
}

func (r *reeIntResolver) at(row int) int64 {
	if r.plainInt64 != nil {
		if r.plainInt64.IsNull(row) {
			return 0
		}
		return r.plainInt64.Value(row)
	}
	if r.plainUint64 != nil {
		if r.plainUint64.IsNull(row) {
			return 0
		}
		return int64(r.plainUint64.Value(row))
	}
	if r.cursor >= len(r.runEnds) || int(r.runEnds[r.cursor]) <= row {
		for r.cursor < len(r.runEnds) && int(r.runEnds[r.cursor]) <= row {
			r.cursor++
		}
	} else {
		for r.cursor > 0 && int(r.runEnds[r.cursor-1]) > row {
			r.cursor--
		}
	}
	if r.cursor >= len(r.runEnds) {
		return 0
	}
	return r.values[r.cursor]
}

func runEndsOf(ree *array.RunEndEncoded) ([]int32, error) {
	re, ok := ree.RunEndsArr().(*array.Int32)
	if !ok {
		return nil, fmt.Errorf("run ends are %T, want *array.Int32", ree.RunEndsArr())
	}
	return re.Int32Values(), nil
}

// fixedSizeBinaryOf unwraps the UUID extension array the stacktrace_id column
// uses, so the 16 raw bytes can be read.
func fixedSizeBinaryOf(a arrow.Array) (*array.FixedSizeBinary, error) {
	switch v := a.(type) {
	case *array.FixedSizeBinary:
		return v, nil
	case array.ExtensionArray:
		fsb, ok := v.Storage().(*array.FixedSizeBinary)
		if !ok {
			return nil, fmt.Errorf("extension storage is %T", v.Storage())
		}
		return fsb, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", a)
	}
}

// stackDecoder walks the ListView(Dictionary(Location)) column. Locations are
// decoded once into a table and rows index into it, which is what makes the
// dictionary worth having on the read side too.
type stackDecoder struct {
	lv        *array.ListView
	locDict   *array.Dictionary
	locations []canonLocation
}

func newStackDecoder(a arrow.Array) (*stackDecoder, error) {
	lv, ok := a.(*array.ListView)
	if !ok {
		return nil, fmt.Errorf("expected list view, got %T", a)
	}

	locDict, ok := lv.ListValues().(*array.Dictionary)
	if !ok {
		return nil, fmt.Errorf("list values are %T, want *array.Dictionary", lv.ListValues())
	}

	locStruct, ok := locDict.Dictionary().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("location dictionary is %T, want *array.Struct", locDict.Dictionary())
	}

	locs, err := decodeLocations(locStruct)
	if err != nil {
		return nil, err
	}

	return &stackDecoder{lv: lv, locDict: locDict, locations: locs}, nil
}

func (d *stackDecoder) at(row int) ([]canonLocation, error) {
	if d.lv.IsNull(row) {
		return nil, nil
	}
	offset := int(d.lv.Offsets()[row])
	size := int(d.lv.Sizes()[row])

	out := make([]canonLocation, 0, size)
	for i := offset; i < offset+size; i++ {
		if d.locDict.IsNull(i) {
			out = append(out, canonLocation{})
			continue
		}
		idx := d.locDict.GetValueIndex(i)
		if idx < 0 || idx >= len(d.locations) {
			return nil, fmt.Errorf("location index %d out of range", idx)
		}
		out = append(out, d.locations[idx])
	}
	return out, nil
}

// decodeLocations materializes the whole location dictionary.
func decodeLocations(locStruct *array.Struct) ([]canonLocation, error) {
	st := locStruct.DataType().(*arrow.StructType)
	fieldIdx := func(name string) int {
		for i, f := range st.Fields() {
			if f.Name == name {
				return i
			}
		}
		return -1
	}

	addrCol, ok := locStruct.Field(fieldIdx("address")).(*array.Uint64)
	if !ok {
		return nil, fmt.Errorf("address column is %T", locStruct.Field(fieldIdx("address")))
	}
	frameType, err := dictStringsOf(locStruct.Field(fieldIdx("frame_type")))
	if err != nil {
		return nil, fmt.Errorf("frame_type: %w", err)
	}
	mappingFile, err := dictStringsOf(locStruct.Field(fieldIdx("mapping_file")))
	if err != nil {
		return nil, fmt.Errorf("mapping_file: %w", err)
	}
	mappingBuildID, err := dictStringsOf(locStruct.Field(fieldIdx("mapping_build_id")))
	if err != nil {
		return nil, fmt.Errorf("mapping_build_id: %w", err)
	}

	lines, err := newLineDecoder(locStruct.Field(fieldIdx("lines")))
	if err != nil {
		return nil, fmt.Errorf("lines: %w", err)
	}

	n := locStruct.Len()
	out := make([]canonLocation, n)
	for i := 0; i < n; i++ {
		loc := canonLocation{
			Address:        addrCol.Value(i),
			FrameType:      frameType(i),
			MappingFile:    mappingFile(i),
			MappingBuildID: mappingBuildID(i),
		}
		ls, err := lines.at(i)
		if err != nil {
			return nil, err
		}
		loc.Lines = ls
		out[i] = loc
	}
	return out, nil
}

// dictStringsOf returns a row accessor for a dictionary-encoded string column.
func dictStringsOf(a arrow.Array) (func(int) string, error) {
	d, ok := a.(*array.Dictionary)
	if !ok {
		return nil, fmt.Errorf("expected dictionary, got %T", a)
	}
	dict, ok := d.Dictionary().(*array.String)
	if !ok {
		return nil, fmt.Errorf("dictionary values are %T", d.Dictionary())
	}
	return func(i int) string {
		if d.IsNull(i) {
			return ""
		}
		return dict.Value(d.GetValueIndex(i))
	}, nil
}

// lineDecoder walks the per-location ListView of line structs, each of which
// points into a function dictionary.
type lineDecoder struct {
	lv       *array.ListView
	lineCol  *array.Uint64
	colCol   *array.Uint64
	funcDict *array.Dictionary
	funcs    []canonLine
}

func newLineDecoder(a arrow.Array) (*lineDecoder, error) {
	lv, ok := a.(*array.ListView)
	if !ok {
		return nil, fmt.Errorf("expected list view, got %T", a)
	}
	lineStruct, ok := lv.ListValues().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("line values are %T", lv.ListValues())
	}

	st := lineStruct.DataType().(*arrow.StructType)
	idx := func(name string) int {
		for i, f := range st.Fields() {
			if f.Name == name {
				return i
			}
		}
		return -1
	}

	lineCol, _ := lineStruct.Field(idx("line")).(*array.Uint64)
	colCol, _ := lineStruct.Field(idx("column")).(*array.Uint64)
	funcDict, ok := lineStruct.Field(idx("function")).(*array.Dictionary)
	if !ok {
		return nil, fmt.Errorf("function column is %T, want *array.Dictionary", lineStruct.Field(idx("function")))
	}

	funcs, err := decodeFunctions(funcDict)
	if err != nil {
		return nil, err
	}

	return &lineDecoder{lv: lv, lineCol: lineCol, colCol: colCol, funcDict: funcDict, funcs: funcs}, nil
}

func (d *lineDecoder) at(locRow int) ([]canonLine, error) {
	if d.lv.IsNull(locRow) {
		return nil, nil
	}
	offset := int(d.lv.Offsets()[locRow])
	size := int(d.lv.Sizes()[locRow])
	if size == 0 {
		return nil, nil
	}

	out := make([]canonLine, 0, size)
	for i := offset; i < offset+size; i++ {
		l := canonLine{}
		if d.lineCol != nil && !d.lineCol.IsNull(i) {
			l.Line = d.lineCol.Value(i)
		}
		if d.colCol != nil && !d.colCol.IsNull(i) {
			l.Column = d.colCol.Value(i)
		}
		if !d.funcDict.IsNull(i) {
			fi := d.funcDict.GetValueIndex(i)
			if fi < 0 || fi >= len(d.funcs) {
				return nil, fmt.Errorf("function index %d out of range", fi)
			}
			f := d.funcs[fi]
			l.SystemName = f.SystemName
			l.Filename = f.Filename
			l.StartLine = f.StartLine
		}
		out = append(out, l)
	}
	return out, nil
}

// decodeFunctions materializes the function dictionary. Only the name, file,
// and start line matter; line and column live on the referencing line.
func decodeFunctions(funcDict *array.Dictionary) ([]canonLine, error) {
	fs, ok := funcDict.Dictionary().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("function dictionary is %T", funcDict.Dictionary())
	}
	st := fs.DataType().(*arrow.StructType)
	idx := func(name string) int {
		for i, f := range st.Fields() {
			if f.Name == name {
				return i
			}
		}
		return -1
	}

	sysNames, err := stringViewOf(fs.Field(idx("system_name")))
	if err != nil {
		return nil, fmt.Errorf("system_name: %w", err)
	}
	filenames, err := dictStringsOf(fs.Field(idx("filename")))
	if err != nil {
		return nil, fmt.Errorf("filename: %w", err)
	}
	startLine, _ := fs.Field(idx("start_line")).(*array.Uint64)

	n := fs.Len()
	out := make([]canonLine, n)
	for i := 0; i < n; i++ {
		out[i] = canonLine{
			SystemName: sysNames(i),
			Filename:   filenames(i),
		}
		if startLine != nil && !startLine.IsNull(i) {
			out[i].StartLine = startLine.Value(i)
		}
	}
	return out, nil
}

func stringViewOf(a arrow.Array) (func(int) string, error) {
	switch v := a.(type) {
	case *array.StringView:
		return func(i int) string {
			if v.IsNull(i) {
				return ""
			}
			return v.Value(i)
		}, nil
	case *array.String:
		return func(i int) string {
			if v.IsNull(i) {
				return ""
			}
			return v.Value(i)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported string type %T", a)
	}
}
