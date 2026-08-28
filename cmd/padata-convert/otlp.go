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
	"sort"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
)

// Attribute keys. The first three carry fields OTLP/profiles has no native slot
// for; without them the conversion is lossy, which is the point of naming them
// here rather than burying them.
const (
	// attrProducer: Arrow's per-sample "producer" column. A parca concept
	// with no OTLP equivalent.
	attrProducer = "parca.producer"
	// attrTemporality: Arrow's per-sample "temporality". pprofile v0.154
	// declares AggregationTemporality but attaches it to no type -- the
	// dictionary redesign dropped it from Profile -- so it has nowhere to go.
	attrTemporality = "parca.temporality"
	// attrStacktraceID: Arrow's 16-byte trace hash. OTLP identifies stacks by
	// dictionary index, so the hash itself is not representable.
	attrStacktraceID = "parca.stacktrace_id"

	attrThreadName = "thread.name"
	attrThreadID   = "thread.id"
	attrCPUNumber  = "cpu.logical_number"
	attrLabelPrefix = "process.context.label."
)

// perSampleLabels are the labels the agent patches per sample rather than per
// process, so they belong on the Sample and everything else on the Resource.
// The split has to be by a fixed rule, not by inspection, or the round trip
// cannot reassemble the flat Arrow label map.
var perSampleLabels = map[string]string{
	"cpu":         attrCPUNumber,
	"thread_id":   attrThreadID,
	"thread_name": attrThreadName,
}

var perSampleLabelsInverse = map[string]string{
	attrCPUNumber:  "cpu",
	attrThreadID:   "thread_id",
	attrThreadName: "thread_name",
}

// profileKey is everything OTLP stores once per Profile that Arrow stores once
// per sample. Any difference in these fields forces a separate Profile, which
// is the structural cost of the model change.
type profileKey struct {
	sampleType  string
	sampleUnit  string
	periodType  string
	periodUnit  string
	period      int64
	duration    uint64
	producer    string
	temporality string
}

// sampleKey groups rows that differ only in value and timestamp. OTLP's Sample
// carries parallel timestamp and value arrays, so those rows collapse into one
// Sample -- this is where OTLP can win on size.
type sampleKey struct {
	stackIdx     int32
	stacktraceID string
	sampleAttrs  string
}

// encodeOTLP converts canonical samples into one OTLP profiles batch.
func encodeOTLP(samples []canonSample) (pprofile.Profiles, error) {
	profiles := pprofile.NewProfiles()
	dict := profiles.Dictionary()

	b := &otlpBuilder{
		dict:      dict,
		profiles:  profiles,
		strings:   map[string]int32{},
		attrs:     map[attrPair]int32{},
		functions: map[canonLine]int32{},
		mappings:  map[string]int32{},
		locations: map[string]int32{},
		stacks:    map[string]int32{},
		resources: map[string]*otlpResource{},
	}
	b.intern("") // OTLP reserves string index 0 for the empty string.

	// pprofile.Location.MappingIndex is a bare int32 with no presence flag, so
	// index 0 cannot be distinguished from "no mapping". Burn entry 0 on an
	// empty mapping and treat it as the absent sentinel, which is what makes
	// the decode unambiguous.
	b.mappingIndex("", "")

	for i := range samples {
		if err := b.add(&samples[i]); err != nil {
			return profiles, fmt.Errorf("sample %d: %w", i, err)
		}
	}
	b.flush()

	return profiles, nil
}

type attrPair struct {
	key   string
	value string
}

type otlpResource struct {
	scope   pprofile.ScopeProfiles
	byKey   map[profileKey]pprofile.Profile
	samples map[profileKey]map[sampleKey]pprofile.Sample
}

type otlpBuilder struct {
	dict     pprofile.ProfilesDictionary
	profiles pprofile.Profiles

	strings   map[string]int32
	attrs     map[attrPair]int32
	functions map[canonLine]int32
	mappings  map[string]int32
	locations map[string]int32
	stacks    map[string]int32
	resources map[string]*otlpResource
}

func (b *otlpBuilder) intern(s string) int32 {
	if idx, ok := b.strings[s]; ok {
		return idx
	}
	idx := int32(b.dict.StringTable().Len())
	b.dict.StringTable().Append(s)
	b.strings[s] = idx
	return idx
}

func (b *otlpBuilder) attrIndex(key, value string) int32 {
	p := attrPair{key: key, value: value}
	if idx, ok := b.attrs[p]; ok {
		return idx
	}
	idx := int32(b.dict.AttributeTable().Len())
	a := b.dict.AttributeTable().AppendEmpty()
	a.SetKeyStrindex(b.intern(key))
	a.Value().SetStr(value)
	b.attrs[p] = idx
	return idx
}

func (b *otlpBuilder) functionIndex(l canonLine) int32 {
	key := canonLine{SystemName: l.SystemName, Filename: l.Filename, StartLine: l.StartLine}
	if idx, ok := b.functions[key]; ok {
		return idx
	}
	idx := int32(b.dict.FunctionTable().Len())
	f := b.dict.FunctionTable().AppendEmpty()
	f.SetNameStrindex(b.intern(key.SystemName))
	f.SetSystemNameStrindex(b.intern(key.SystemName))
	f.SetFilenameStrindex(b.intern(key.Filename))
	f.SetStartLine(int64(key.StartLine))
	b.functions[key] = idx
	return idx
}

func (b *otlpBuilder) mappingIndex(file, buildID string) int32 {
	key := file + "\x00" + buildID
	if idx, ok := b.mappings[key]; ok {
		return idx
	}
	idx := int32(b.dict.MappingTable().Len())
	m := b.dict.MappingTable().AppendEmpty()
	m.SetFilenameStrindex(b.intern(file))
	if buildID != "" {
		m.AttributeIndices().Append(b.attrIndex(attrBuildIDHtlhash, buildID))
	}
	b.mappings[key] = idx
	return idx
}

// attrBuildIDHtlhash matches what the production converter emits, so an
// artifact keyed on it resolves the same either way.
const attrBuildIDHtlhash = "process.executable.build_id.htlhash"

func (b *otlpBuilder) locationIndex(loc canonLocation) int32 {
	key := locationKeyOf(loc)
	if idx, ok := b.locations[key]; ok {
		return idx
	}

	idx := int32(b.dict.LocationTable().Len())
	l := b.dict.LocationTable().AppendEmpty()
	l.SetAddress(loc.Address)
	if loc.MappingFile != "" || loc.MappingBuildID != "" {
		l.SetMappingIndex(b.mappingIndex(loc.MappingFile, loc.MappingBuildID))
	}
	for _, cl := range loc.Lines {
		line := l.Lines().AppendEmpty()
		line.SetFunctionIndex(b.functionIndex(cl))
		line.SetLine(int64(cl.Line))
		line.SetColumn(int64(cl.Column))
	}
	if loc.FrameType != "" {
		l.AttributeIndices().Append(b.attrIndex("profile.frame.type", loc.FrameType))
	}
	b.locations[key] = idx
	return idx
}

func locationKeyOf(loc canonLocation) string {
	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(loc.Address, 16))
	sb.WriteByte(0)
	sb.WriteString(loc.FrameType)
	sb.WriteByte(0)
	sb.WriteString(loc.MappingFile)
	sb.WriteByte(0)
	sb.WriteString(loc.MappingBuildID)
	for _, l := range loc.Lines {
		sb.WriteByte(1)
		sb.WriteString(strconv.FormatUint(l.Line, 10))
		sb.WriteByte(0)
		sb.WriteString(strconv.FormatUint(l.Column, 10))
		sb.WriteByte(0)
		sb.WriteString(l.SystemName)
		sb.WriteByte(0)
		sb.WriteString(l.Filename)
		sb.WriteByte(0)
		sb.WriteString(strconv.FormatUint(l.StartLine, 10))
	}
	return sb.String()
}

func (b *otlpBuilder) stackIndex(stack []canonLocation) int32 {
	indices := make([]int32, len(stack))
	var sb strings.Builder
	for i, loc := range stack {
		indices[i] = b.locationIndex(loc)
		sb.WriteString(strconv.FormatInt(int64(indices[i]), 10))
		sb.WriteByte(',')
	}
	key := sb.String()
	if idx, ok := b.stacks[key]; ok {
		return idx
	}
	idx := int32(b.dict.StackTable().Len())
	s := b.dict.StackTable().AppendEmpty()
	for _, li := range indices {
		s.LocationIndices().Append(li)
	}
	b.stacks[key] = idx
	return idx
}

// splitLabels applies the fixed resource/sample rule.
func splitLabels(labels map[string]string) (resource, sample map[string]string) {
	resource = map[string]string{}
	sample = map[string]string{}
	for k, v := range labels {
		if otlpKey, ok := perSampleLabels[k]; ok {
			sample[otlpKey] = v
			continue
		}
		resource[k] = v
	}
	return resource, sample
}

func mapKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte(0)
		sb.WriteString(m[k])
		sb.WriteByte(0)
	}
	return sb.String()
}

func (b *otlpBuilder) resourceFor(resLabels map[string]string) *otlpResource {
	key := mapKey(resLabels)
	if r, ok := b.resources[key]; ok {
		return r
	}

	rp := b.profiles.ResourceProfiles().AppendEmpty()
	attrs := rp.Resource().Attributes()
	names := make([]string, 0, len(resLabels))
	for k := range resLabels {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		attrs.PutStr(k, resLabels[k])
	}

	scope := rp.ScopeProfiles().AppendEmpty()
	scope.Scope().SetName("parca-agent")

	r := &otlpResource{
		scope:   scope,
		byKey:   map[profileKey]pprofile.Profile{},
		samples: map[profileKey]map[sampleKey]pprofile.Sample{},
	}
	b.resources[key] = r
	return r
}

func (b *otlpBuilder) profileFor(r *otlpResource, pk profileKey) pprofile.Profile {
	if p, ok := r.byKey[pk]; ok {
		return p
	}

	p := r.scope.Profiles().AppendEmpty()
	p.SampleType().SetTypeStrindex(b.intern(pk.sampleType))
	p.SampleType().SetUnitStrindex(b.intern(pk.sampleUnit))
	if pk.periodType != "" || pk.periodUnit != "" {
		p.PeriodType().SetTypeStrindex(b.intern(pk.periodType))
		p.PeriodType().SetUnitStrindex(b.intern(pk.periodUnit))
	}
	p.SetPeriod(pk.period)
	p.SetDurationNano(pk.duration)

	// Fields with no native slot ride as profile attributes.
	if pk.producer != "" {
		p.AttributeIndices().Append(b.attrIndex(attrProducer, pk.producer))
	}
	if pk.temporality != "" {
		p.AttributeIndices().Append(b.attrIndex(attrTemporality, pk.temporality))
	}

	r.byKey[pk] = p
	r.samples[pk] = map[sampleKey]pprofile.Sample{}
	return p
}

func (b *otlpBuilder) add(s *canonSample) error {
	resLabels, sampleLabels := splitLabels(s.Labels)

	r := b.resourceFor(resLabels)
	pk := profileKey{
		sampleType:  s.SampleType,
		sampleUnit:  s.SampleUnit,
		periodType:  s.PeriodType,
		periodUnit:  s.PeriodUnit,
		period:      s.Period,
		duration:    s.Duration,
		producer:    s.Producer,
		temporality: s.Temporality,
	}
	profile := b.profileFor(r, pk)

	stackIdx := b.stackIndex(s.Stack)
	sk := sampleKey{
		stackIdx:     stackIdx,
		stacktraceID: s.StacktraceID,
		sampleAttrs:  mapKey(sampleLabels),
	}

	// Fold rows that differ only in value and timestamp into one Sample.
	if existing, ok := r.samples[pk][sk]; ok {
		existing.TimestampsUnixNano().Append(s.Timestamp)
		existing.Values().Append(s.Value)
		return nil
	}

	sample := profile.Samples().AppendEmpty()
	sample.SetStackIndex(stackIdx)
	sample.TimestampsUnixNano().Append(s.Timestamp)
	sample.Values().Append(s.Value)

	names := make([]string, 0, len(sampleLabels))
	for k := range sampleLabels {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		sample.AttributeIndices().Append(b.attrIndex(k, sampleLabels[k]))
	}
	if s.StacktraceID != "" {
		sample.AttributeIndices().Append(b.attrIndex(attrStacktraceID, s.StacktraceID))
	}

	r.samples[pk][sk] = sample
	return nil
}

func (b *otlpBuilder) flush() {}

// marshalOTLP serializes a profiles batch as an OTLP ExportProfilesServiceRequest.
func marshalOTLP(p pprofile.Profiles) ([]byte, error) {
	req := pprofileotlp.NewExportRequestFromProfiles(p)
	return req.MarshalProto()
}

// decodeOTLP is the inverse of encodeOTLP: it flattens an OTLP batch back into
// canonical samples, expanding the folded timestamp and value arrays.
func decodeOTLP(p pprofile.Profiles) ([]canonSample, error) {
	dict := p.Dictionary()
	str := func(i int32) string {
		if i < 0 || int(i) >= dict.StringTable().Len() {
			return ""
		}
		return dict.StringTable().At(int(i))
	}

	resolveAttrs := func(indices pcommon.Int32Slice) map[string]string {
		out := map[string]string{}
		for i := range indices.Len() {
			idx := indices.At(i)
			if idx < 0 || int(idx) >= dict.AttributeTable().Len() {
				continue
			}
			a := dict.AttributeTable().At(int(idx))
			out[str(a.KeyStrindex())] = a.Value().Str()
		}
		return out
	}

	// Locations and stacks are decoded once; samples index into them.
	locs := make([]canonLocation, dict.LocationTable().Len())
	for i := range dict.LocationTable().Len() {
		l := dict.LocationTable().At(i)
		loc := canonLocation{Address: l.Address()}

		locAttrs := resolveAttrs(l.AttributeIndices())
		loc.FrameType = locAttrs["profile.frame.type"]

		// Index 0 is the reserved "no mapping" sentinel; see encodeOTLP.
		if l.MappingIndex() > 0 {
			m := dict.MappingTable().At(int(l.MappingIndex()))
			loc.MappingFile = str(m.FilenameStrindex())
			loc.MappingBuildID = resolveAttrs(m.AttributeIndices())[attrBuildIDHtlhash]
		}

		for j := range l.Lines().Len() {
			ln := l.Lines().At(j)
			f := dict.FunctionTable().At(int(ln.FunctionIndex()))
			loc.Lines = append(loc.Lines, canonLine{
				Line:       uint64(ln.Line()),
				Column:     uint64(ln.Column()),
				SystemName: str(f.SystemNameStrindex()),
				Filename:   str(f.FilenameStrindex()),
				StartLine:  uint64(f.StartLine()),
			})
		}
		locs[i] = loc
	}

	stacks := make([][]canonLocation, dict.StackTable().Len())
	for i := range dict.StackTable().Len() {
		st := dict.StackTable().At(i)
		out := make([]canonLocation, 0, st.LocationIndices().Len())
		for j := range st.LocationIndices().Len() {
			li := st.LocationIndices().At(j)
			if li < 0 || int(li) >= len(locs) {
				return nil, fmt.Errorf("stack %d references location %d", i, li)
			}
			out = append(out, locs[li])
		}
		stacks[i] = out
	}

	var samples []canonSample
	for ri := range p.ResourceProfiles().Len() {
		rp := p.ResourceProfiles().At(ri)

		resLabels := map[string]string{}
		rp.Resource().Attributes().Range(func(k string, v pcommon.Value) bool {
			resLabels[k] = v.Str()
			return true
		})

		for si := range rp.ScopeProfiles().Len() {
			sp := rp.ScopeProfiles().At(si)
			for pi := range sp.Profiles().Len() {
				profile := sp.Profiles().At(pi)

				profAttrs := resolveAttrs(profile.AttributeIndices())

				for smi := range profile.Samples().Len() {
					sample := profile.Samples().At(smi)
					sampleAttrs := resolveAttrs(sample.AttributeIndices())

					labels := map[string]string{}
					for k, v := range resLabels {
						labels[k] = v
					}
					for k, v := range sampleAttrs {
						if orig, ok := perSampleLabelsInverse[k]; ok {
							labels[orig] = v
							continue
						}
						if strings.HasPrefix(k, attrLabelPrefix) {
							labels[strings.TrimPrefix(k, attrLabelPrefix)] = v
						}
					}
					if len(labels) == 0 {
						labels = nil
					}

					stackIdx := int(sample.StackIndex())
					if stackIdx < 0 || stackIdx >= len(stacks) {
						return nil, fmt.Errorf("sample references stack %d", stackIdx)
					}

					// Expand the folded arrays back into one canonical
					// sample per (timestamp, value) pair.
					n := sample.TimestampsUnixNano().Len()
					for k := range n {
						var value int64
						if k < sample.Values().Len() {
							value = sample.Values().At(k)
						}
						samples = append(samples, canonSample{
							Labels:       labels,
							Stack:        stacks[stackIdx],
							StacktraceID: sampleAttrs[attrStacktraceID],
							Value:        value,
							Timestamp:    sample.TimestampsUnixNano().At(k),
							SampleType:   str(profile.SampleType().TypeStrindex()),
							SampleUnit:   str(profile.SampleType().UnitStrindex()),
							PeriodType:   str(profile.PeriodType().TypeStrindex()),
							PeriodUnit:   str(profile.PeriodType().UnitStrindex()),
							Period:       profile.Period(),
							Duration:     profile.DurationNano(),
							Producer:     profAttrs[attrProducer],
							Temporality:  profAttrs[attrTemporality],
						})
					}
				}
			}
		}
	}

	return samples, nil
}
