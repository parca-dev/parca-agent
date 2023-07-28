// Copyright 2023 The Parca Authors
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

package convert

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/pprof/profile"
	"github.com/pyroscope-io/jfr-parser/parser"
)

type builder struct {
	profile       *profile.Profile
	locationTable map[uint64]*profile.Location
	functionTable map[string]*profile.Function
	sampleTable   map[string]*profile.Sample

	// below fields used to reduce allocation
	classNameCache map[string]string
	argCache       map[string]string
	pidCache       map[int64]string
	b              bytes.Buffer
	locationIDBuf  []byte
	locationKeys   []string
	args           []string
}

func newBuilder() *builder {
	return &builder{
		profile:        &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "samples"}}},
		locationTable:  map[uint64]*profile.Location{},
		functionTable:  map[string]*profile.Function{},
		sampleTable:    map[string]*profile.Sample{},
		classNameCache: map[string]string{},
		argCache:       map[string]string{},
		pidCache:       map[int64]string{},
	}
}

func chunksToPprof(chunks []parser.Chunk) (*profile.Profile, error) {
	b := newBuilder()
	for _, c := range chunks {
		b.addJFRChunk(c)
	}

	return b.profile, nil
}

func JfrToPprof(r io.Reader) (*profile.Profile, error) {
	chunks, err := parser.Parse(r)
	if err != nil {
		return nil, err
	}
	return chunksToPprof(chunks)
}

func (b *builder) addJFRChunk(c parser.Chunk) {
	var event string
	for _, e := range c.Events {
		if as, ok := e.(*parser.ActiveSetting); ok {
			// Extract the event name from the active setting.
			if as.Name == "event" {
				event = as.Value
			}
		}
	}
	if event != "cpu" {
		return
	}

	for _, event := range extractExecutionSampleEvents(c.Events) {
		if event.State.Name == "STATE_RUNNABLE" {
			increaseSample(b.getOrCreateSample(event.StackTrace, event.SampledThread, nil))
		}
	}
}

func increaseSample(s *profile.Sample) {
	if s == nil {
		return
	}

	s.Value[0]++
}

type label struct {
	key   string
	value string
}

func (b *builder) getPid(javaThreadID int64) string {
	result, ok := b.pidCache[javaThreadID]
	if !ok {
		result = strconv.Itoa(int(javaThreadID))
		b.pidCache[javaThreadID] = result
	}
	return result
}

func (b *builder) getOrCreateSample(st *parser.StackTrace, thread *parser.Thread, labels []label) *profile.Sample {
	if st == nil || thread == nil {
		return nil
	}

	b.locationKeys = b.locationKeys[:0]
	b.locationIDBuf = b.locationIDBuf[:0]
	for _, frame := range st.Frames {
		fun := b.getOrCreateFunction(frame)
		if fun == nil {
			continue
		}
		loc := b.getOrCreateLocation(fun, frame.LineNumber)
		b.locationIDBuf = binary.AppendUvarint(b.locationIDBuf, loc.ID)
	}
	for _, l := range labels {
		b.locationKeys = append(b.locationKeys, l.value)
	}
	javaThreadID := b.getPid(thread.JavaThreadID)
	javaName := thread.JavaName
	b.locationKeys = append(b.locationKeys, BytesToString(b.locationIDBuf), javaThreadID, javaName)

	b.b.Reset()
	for _, locationKey := range b.locationKeys {
		b.b.WriteString(locationKey)
	}
	sampleKey := BytesToString(b.b.Bytes())
	s, ok := b.sampleTable[sampleKey]
	if !ok {
		locations := make([]*profile.Location, 0, len(b.locationIDBuf))
		for _, locationID := range b.locationIDBuf {
			locations = append(locations, b.profile.Location[locationID-1])
		}
		sampleKey = b.b.String()
		s = &profile.Sample{
			Location: locations,
			Value:    []int64{0, 0},
			Label:    make(map[string][]string, len(labels)+2),
		}

		s.Label["java_thread_id"] = []string{javaThreadID}
		s.Label["java_name"] = []string{javaName}
		for _, l := range labels {
			s.Label[l.key] = []string{l.value}
		}

		b.profile.Sample = append(b.profile.Sample, s)
		b.sampleTable[sampleKey] = s
	}

	return s
}

func (b *builder) getOrCreateFunction(f *parser.StackFrame) *profile.Function {
	if f.Method == nil || f.Method.Name == nil {
		return nil
	}

	var className string
	if f.Method.Type != nil && f.Method.Type.Name != nil {
		className = f.Method.Type.Name.String
	}

	var (
		name         string
		filename     string
		isNameUnsafe bool
	)
	//	 void writeFrameTypes(Buffer* buf) {
	//	    buf->putVar32(T_FRAME_TYPE);
	//	    buf->putVar32(7);
	//	    buf->putVar32(FRAME_INTERPRETED);  buf->putUtf8("Interpreted");
	//	    buf->putVar32(FRAME_JIT_COMPILED); buf->putUtf8("JIT compiled");
	//	    buf->putVar32(FRAME_INLINED);      buf->putUtf8("Inlined");
	//	    buf->putVar32(FRAME_NATIVE);       buf->putUtf8("Native");
	//	    buf->putVar32(FRAME_CPP);          buf->putUtf8("C++");
	//	    buf->putVar32(FRAME_KERNEL);       buf->putUtf8("Kernel");
	//	    buf->putVar32(FRAME_C1_COMPILED);  buf->putUtf8("C1 compiled");
	//	}
	if (f.Type.Description == "Native" || f.Type.Description == "C++" || f.Type.Description == "Kernel") ||
		className == "" {
		// Native method
		if className == "libasyncProfiler.so" {
			return nil
		}
		name = f.Method.Name.String
	} else {
		// JVM method
		isNameUnsafe = true
		b.b.Reset()
		b.b.WriteString(className)
		b.b.WriteString(".")
		b.b.WriteString(f.Method.Name.String)
		if f.Method.Descriptor != nil {
			if args := b.parseArgs(f.Method.Descriptor.String); args != "()" {
				b.b.WriteString(args)
			}
		}
		name = BytesToString(b.b.Bytes())
		filename = b.getFileName(className)
	}
	result, ok := b.functionTable[name]
	if !ok {
		if isNameUnsafe {
			name = b.b.String()
		}
		result = &profile.Function{
			ID:       uint64(len(b.functionTable) + 1),
			Name:     name,
			Filename: filename,
		}
		b.profile.Function = append(b.profile.Function, result)
		b.functionTable[name] = result
	}
	return result
}

func (b *builder) getFileName(s string) string {
	k := s
	res, ok := b.classNameCache[k]
	if !ok {
		if i := strings.Index(s, "$"); i != -1 {
			s = s[:i]
		}
		res = s + ".java"
		b.classNameCache[k] = s
	}
	return res
}

const (
	maxLineNumber = 10000
)

func (b *builder) getOrCreateLocation(fun *profile.Function, line int32) *profile.Location {
	key := fun.ID*maxLineNumber + uint64(line)
	l, ok := b.locationTable[key]
	if !ok {
		l = &profile.Location{
			ID:   uint64(len(b.locationTable) + 1),
			Line: []profile.Line{{Function: fun, Line: int64(line)}},
		}
		b.profile.Location = append(b.profile.Location, l)
		b.locationTable[key] = l
	}
	return l
}

func extractExecutionSampleEvents(events []parser.Parseable) []*parser.ExecutionSample {
	res := []*parser.ExecutionSample{}
	for _, e := range events {
		// There are a lot of events that we don't care about. We only care about on-CPU samples.
		if es, ok := e.(*parser.ExecutionSample); ok {
			res = append(res, es)
		}
	}
	return res
}

func (b *builder) parseArgs(s string) string {
	k := s
	result, ok := b.argCache[k]
	if !ok {
		if i := strings.Index(s, "("); i+1 < len(s) {
			s = s[i+1:]
		}
		if i := strings.LastIndex(s, ")"); i != -1 {
			s = s[:i]
		}
		b.args = b.args[:0]
		for {
			arg, i := parseReferenceTypeSignature(s)
			if j := strings.LastIndex(arg, "/"); j+1 < len(arg) {
				arg = arg[j+1:]
			}
			b.args = append(b.args, arg)
			if i >= len(s) {
				break
			}
			s = s[i:]
		}
		result = "(" + strings.Join(b.args, ",") + ")"
		b.argCache[k] = result
	}
	return result
}

func parseObjectClass(s string) string {
	res, _ := parseReferenceTypeSignature(s)
	return res
}

func parseReferenceTypeSignature(s string) (string, int) {
	if len(s) == 0 {
		return "", 0
	}
	var (
		i         int
		dimension int
		name      string
	)
	for ; s[i] == '['; i++ {
		dimension++
	}
	switch s[i] {
	case 'B':
		i++
		name = "byte"
	case 'C':
		i++
		name = "char"
	case 'D':
		i++
		name = "double"
	case 'F':
		i++
		name = "float"
	case 'I':
		i++
		name = "int"
	case 'J':
		i++
		name = "long"
	case 'L':
		i++
		// skip ;
		var j int
		for j = i; j < len(s) && s[j] != ';'; j++ {
		}
		name = s[i:j]
		i = j + 1
	case 'S':
		i++
		name = "short"
	case 'Z':
		i++
		name = "boolean"
	default:
		name = s[i:]
		i = len(s)
	}
	name += getDimension(dimension)
	return name, i
}

var dimensions = []string{"", "[]", "[][]", "[][][]"}

func getDimension(dimension int) string {
	if dimension < len(dimensions) {
		return dimensions[dimension]
	}
	return strings.Repeat("[]", dimension)
}

// BytesToString converts byte slice to string without a memory allocation.
func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
