package convert

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/google/pprof/profile"
)

const (
	stateHeader = iota
	stateFuncHeader
	stateFunc
)

type profilerType string

const (
	cpu       profilerType = "cpu"
	inuseHeap              = "heap"
	allocs                 = "allocs"
)

var (
	errUnknownProfilerType = errors.New("unknown profiler type")
	errCorrupted           = errors.New("corrupted file")
)

// CollapsedAsyncProfilerToPprof convert collapsed format of async profiler to pprof
func CollapsedAsyncProfilerToPprof(r io.Reader, profiler profilerType) (*profile.Profile, error) {
	s := bufio.NewScanner(r)
	var (
		state          int
		callChainNums  []int
		callChainNum   int
		funcNameSlices byteStrSlice
		valueSlices    byteStrSlice
		sampleSlices   byteStrSlice
	)
loop:
	for s.Scan() {
		line := s.Bytes()
		switch state {
		case stateFunc:
			if len(line) == 0 {
				state = stateFuncHeader
				if callChainNum != 0 {
					callChainNums = append(callChainNums, callChainNum)
					callChainNum = 0
				}
				continue
			}
			if i := bytes.IndexByte(line, ']'); i+2 < len(line) {
				funcName := line[i+2:]
				funcNameSlices.Add(funcName)
				callChainNum++
			} else {
				return nil, errCorrupted
			}
		case stateFuncHeader:
			if !bytes.HasPrefix(line, []byte("-")) {
				// top
				break loop
			}
			var (
				value  []byte
				sample []byte
			)
			// get value
			if i := bytes.IndexByte(line, ' '); i+1 < len(line) {
				line = line[i+1:]
				if i = bytes.IndexByte(line, ' '); i != -1 {
					value = line[:i]
				}
			}
			// get sample
			if i := bytes.LastIndexByte(line, ' '); i != -1 {
				line = line[:i]
				if i = bytes.LastIndexByte(line, ' '); i+1 < len(line) {
					sample = line[i+1:]
				}
			}
			if len(value) == 0 || len(sample) == 0 {
				return nil, errCorrupted
			}
			valueSlices.Add(value)
			sampleSlices.Add(sample)
			state = stateFunc
		case stateHeader:
			// skip header
			if len(line) == 0 {
				state = stateFuncHeader
				continue
			}
		}
	}
	funcNames := funcNameSlices.Strings()
	funcNameCache := make(map[string]struct{})
	for _, funcName := range funcNames {
		funcNameCache[funcName] = struct{}{}
	}
	distinctFunctionNums := len(funcNameCache)

	strsToInts := func(strs []string) ([]int, error) {
		results := make([]int, 0, len(strs))
		for _, str := range strs {
			if result, err := strconv.Atoi(str); err != nil {
				return nil, err
			} else {
				results = append(results, result)
			}
		}
		return results, nil
	}

	valueStrs := valueSlices.Strings()
	sampleStrs := sampleSlices.Strings()

	values, err := strsToInts(valueStrs)
	if err != nil {
		return nil, err
	}
	samples, err := strsToInts(sampleStrs)
	if err != nil {
		return nil, err
	}

	var sampleType []*profile.ValueType
	switch profiler {
	case cpu:
		sampleType = []*profile.ValueType{{
			Type: "cpu",
			Unit: "nanoseconds",
		}, {
			Type: "samples",
			Unit: "count",
		}}
	case allocs:
		sampleType = []*profile.ValueType{{
			Type: "alloc_space",
			Unit: "bytes",
		}, {
			Type: "alloc_objects",
			Unit: "count",
		}}
	case inuseHeap:
		sampleType = []*profile.ValueType{{
			Type: "inuse_space",
			Unit: "bytes",
		}, {
			Type: "inuse_objects",
			Unit: "count",
		}}
	default:
		return nil, errUnknownProfilerType
	}
	var (
		p = &profile.Profile{
			SampleType:    sampleType,
			TimeNanos:     time.Now().UnixMilli(),
			DurationNanos: int64(time.Minute),

			// We sample at 100Hz, which is every 10 Million nanoseconds.
			PeriodType: &profile.ValueType{
				Type: "cpu",
				Unit: "nanoseconds",
			},
			Period:   10000000,
			Sample:   make([]*profile.Sample, 0, len(callChainNums)),
			Location: make([]*profile.Location, 0, distinctFunctionNums),
			Function: make([]*profile.Function, 0, distinctFunctionNums),
		}
	)

	var (
		locationIndex uint64
		allLocations  = make([]profile.Location, distinctFunctionNums)
		allFunctions  = make([]profile.Function, distinctFunctionNums)
		allLines      = make([]profile.Line, distinctFunctionNums)
		locationCache = make(map[string]*profile.Location, distinctFunctionNums)
	)
	// batch allocate
	createOrGetLocation := func(name string) *profile.Location {
		if l, ok := locationCache[name]; ok {
			return l
		}
		idx := locationIndex + 1

		f := &allFunctions[locationIndex]
		f.ID = idx
		f.Name = name

		allLines[locationIndex].Function = f

		l := &allLocations[locationIndex]
		l.ID = idx
		l.Line = allLines[locationIndex : locationIndex+1]
		locationCache[name] = l
		locationIndex++

		p.Location = append(p.Location, l)
		p.Function = append(p.Function, f)
		return l
	}

	if len(values) != len(callChainNums) {
		return nil, errCorrupted
	}

	for i := 0; i < len(values); i++ {
		value, sample := values[i], samples[i]

		if callChainNum = callChainNums[i]; callChainNum > len(funcNames) {
			return nil, errCorrupted
		}
		callStacks := funcNames[:callChainNum]
		funcNames = funcNames[callChainNum:]

		locations := make([]*profile.Location, 0, len(callStacks))
		for _, callStack := range callStacks {
			locations = append(locations, createOrGetLocation(callStack))
		}

		p.Sample = append(p.Sample, &profile.Sample{
			Location: locations,
			Value:    []int64{int64(value), int64(sample)},
			Label:    nil,
			NumLabel: nil,
			NumUnit:  nil,
		})
	}

	return p, p.CheckValid()
}

// byteStrSlice is slice of []byte
type byteStrSlice struct {
	recordBuffer []byte
	indexes      []int
	pos          int
}

func (b *byteStrSlice) Add(data []byte) {
	b.recordBuffer = append(b.recordBuffer, data...)
	b.pos += len(data)
	b.indexes = append(b.indexes, b.pos)
}

func (b *byteStrSlice) Strings() []string {
	// Create a single string and create slices out of it.
	// This pins the memory of the fields together, but allocates once.
	str := string(b.recordBuffer) // Convert to string once to batch allocations
	dst := make([]string, len(b.indexes))
	var preIdx int
	for i, idx := range b.indexes {
		dst[i] = str[preIdx:idx]
		preIdx = idx
	}
	return dst
}
