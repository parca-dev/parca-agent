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
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// Attribute keys, matching what upstream's OTLP reporter emits. They are the
// join keys the debuginfo pipeline symbolizes on, so they are spelled out here
// rather than pulled from semconv, where a bump could rename one silently.
const (
	attrBuildIDGNU      = "process.executable.build_id.gnu"
	attrBuildIDGo       = "process.executable.build_id.go"
	attrBuildIDHtlhash  = "process.executable.build_id.htlhash"
	profileFrameTypeKey = "profile.frame.type"

	attrThreadName = "thread.name"
	attrThreadID   = "thread.id"
	attrCPUNumber  = "cpu.logical_number"

	// attrProcessLabelPrefix namespaces parca-agent's per-sample labels.
	// Upstream uses the same prefix for custom labels, so both land in one
	// namespace a collector can filter on.
	attrProcessLabelPrefix = "process.context.label."

	attrServiceName    = "service.name"
	attrProcessPID     = "process.pid"
	attrProcessExePath = "process.executable.path"
	attrContainerID    = "container.id"
	attrHostName       = "host.name"
)

// sampleType names one profile's value axis. pprofile.Profile carries exactly
// one SampleType, so each distinct type becomes its own Profile within a
// resource -- which is why memory, with four value axes, needs four.
type sampleType struct {
	Type string
	Unit string

	PeriodType string
	PeriodUnit string
	Period     int64
}

// Sample types, one per origin plus the four memory axes. Names follow
// upstream's OTLP reporter where it has one, and the arrow backends where it
// does not (GPU and memory, which upstream cannot represent). The vocabulary
// is therefore mixed: off-CPU is "wallclock" on arrow and "off_cpu" here, and
// a query written against one backend will not match the other.
func cpuSampleType(samplesPerSecond int64) sampleType {
	period := int64(0)
	if samplesPerSecond > 0 {
		period = 1e9 / samplesPerSecond
	}
	return sampleType{
		Type: "samples", Unit: "count",
		PeriodType: "cpu", PeriodUnit: "nanoseconds", Period: period,
	}
}

var (
	offCPUSampleType = sampleType{Type: "off_cpu", Unit: "nanoseconds"}
	probeSampleType  = sampleType{Type: "events", Unit: "count"}

	gpuKernelSampleType = sampleType{Type: "gpu_kernel_time", Unit: "nanoseconds"}
	gpuMergedSampleType = sampleType{Type: "gpu_time", Unit: "nanoseconds"}

	memInuseObjects = sampleType{Type: "inuse_objects", Unit: "count", Period: memorySamplePeriod}
	memInuseSpace   = sampleType{Type: "inuse_space", Unit: "bytes", Period: memorySamplePeriod}
	memAllocObjects = sampleType{Type: "alloc_objects", Unit: "count", Period: memorySamplePeriod}
	memAllocSpace   = sampleType{Type: "alloc_space", Unit: "bytes", Period: memorySamplePeriod}
)

func gpuPCSampleType(nsPerSample int64) sampleType {
	return sampleType{Type: "gpu_pcsample", Unit: "count", Period: nsPerSample}
}

// sampleData is one row to emit: a stack, a value, a timestamp, and the
// per-sample attributes.
type sampleData struct {
	Frames    libpf.Frames
	TraceHash libpf.TraceHash
	Timestamp uint64
	Value     int64

	// SampleLabels are the per-sample labels (cpu, thread_id, thread_name).
	SampleLabels labels.Labels
	// CustomLabels are the trace's own custom labels.
	CustomLabels map[libpf.String]libpf.String
	// ExtraAttrs are literal key/value attributes the caller wants on this
	// sample, used for the gpu_view marker.
	ExtraAttrs map[string]string

	// Memory samples synthesize frames whose build ID and executable path
	// are stashed on the frame rather than reachable through a mapping.
	// See classifyMemoryFrame.
	SyntheticMemoryFrames bool
	MemoryBuildID         string
	MemoryExecPath        string
}

// pprofileBuilder accumulates samples across a flush interval and renders them
// as one OTLP ProfilesData.
//
// The dictionary is global to the request, so interning happens once here no
// matter how many resources or sample types the batch spans. The maps index
// into its tables; upstream's orderedset does the same job but is internal.
type pprofileBuilder struct {
	profiles pprofile.Profiles
	dict     pprofile.ProfilesDictionary

	strings   map[string]int32
	functions map[FunctionV2]int32
	mappings  map[mappingKey]int32
	locations map[locationKey]int32
	stacks    map[stackKey]int32
	attrs     map[attrKey]int32

	// resources indexes ResourceProfiles by the hash of their label set, and
	// each carries its own per-sample-type Profile index.
	resources map[uint64]*resourceProfileSet

	executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]
	nodeName    string
	sampleCount int
}

type resourceProfileSet struct {
	scope  pprofile.ScopeProfiles
	byType map[sampleType]pprofile.Profile
}

type mappingKey struct {
	filename   string
	buildID    string
	gnuBuildID string
	goBuildID  string
}

type locationKey struct {
	mappingIndex int32
	address      uint64
	frameType    string
	functionIdx  int32
	hasFunction  bool
	line         uint64
	column       uint64
}

type stackKey struct {
	hash libpf.TraceHash
	// synthetic distinguishes a memory stack from a sampling stack that
	// happens to hash the same; they classify frames differently.
	synthetic bool
}

type attrKey struct {
	key   string
	value string
}

func newPprofileBuilder(executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo], nodeName string) *pprofileBuilder {
	b := &pprofileBuilder{executables: executables, nodeName: nodeName}
	b.reset()
	return b
}

// reset starts a fresh batch. Called after every flush, so the dictionary does
// not grow without bound across the process lifetime.
func (b *pprofileBuilder) reset() {
	b.profiles = pprofile.NewProfiles()
	b.dict = b.profiles.Dictionary()
	b.strings = make(map[string]int32)
	b.functions = make(map[FunctionV2]int32)
	b.mappings = make(map[mappingKey]int32)
	b.locations = make(map[locationKey]int32)
	b.stacks = make(map[stackKey]int32)
	b.attrs = make(map[attrKey]int32)
	b.resources = make(map[uint64]*resourceProfileSet)
	b.sampleCount = 0

	// The OTLP string table reserves index 0 for the empty string.
	b.internString("")
}

func (b *pprofileBuilder) internString(s string) int32 {
	if idx, ok := b.strings[s]; ok {
		return idx
	}
	idx := int32(b.dict.StringTable().Len())
	b.dict.StringTable().Append(s)
	b.strings[s] = idx
	return idx
}

// appendAttr interns one string attribute and appends its index to attrs.
// Empty values are skipped: an absent attribute is cheaper than an empty one,
// and it matches what upstream does.
func (b *pprofileBuilder) appendAttr(attrs pcommon.Int32Slice, key, value string) {
	if value == "" {
		return
	}
	k := attrKey{key: key, value: value}
	if idx, ok := b.attrs[k]; ok {
		attrs.Append(idx)
		return
	}
	idx := int32(b.dict.AttributeTable().Len())
	a := b.dict.AttributeTable().AppendEmpty()
	a.SetKeyStrindex(b.internString(key))
	a.Value().SetStr(value)
	b.attrs[k] = idx
	attrs.Append(idx)
}

func (b *pprofileBuilder) internFunction(fn FunctionV2) int32 {
	if idx, ok := b.functions[fn]; ok {
		return idx
	}
	idx := int32(b.dict.FunctionTable().Len())
	f := b.dict.FunctionTable().AppendEmpty()
	f.SetNameStrindex(b.internString(fn.SystemName))
	f.SetSystemNameStrindex(b.internString(fn.SystemName))
	f.SetFilenameStrindex(b.internString(fn.Filename))
	f.SetStartLine(int64(fn.StartLine))
	b.functions[fn] = idx
	return idx
}

func (b *pprofileBuilder) internMapping(k mappingKey) int32 {
	if idx, ok := b.mappings[k]; ok {
		return idx
	}
	idx := int32(b.dict.MappingTable().Len())
	m := b.dict.MappingTable().AppendEmpty()
	m.SetFilenameStrindex(b.internString(k.filename))

	// Both the typed build IDs when known and the htlhash fallback, so a
	// backend keying on either one finds it.
	b.appendAttr(m.AttributeIndices(), attrBuildIDGNU, k.gnuBuildID)
	b.appendAttr(m.AttributeIndices(), attrBuildIDGo, k.goBuildID)
	if k.buildID != "" && k.buildID != k.gnuBuildID && k.buildID != k.goBuildID {
		b.appendAttr(m.AttributeIndices(), attrBuildIDHtlhash, k.buildID)
	}

	b.mappings[k] = idx
	return idx
}

func (b *pprofileBuilder) internLocation(fi frameInfo) int32 {
	mappingIdx := int32(-1)
	if fi.HasMappingFile || fi.BuildID != "" {
		mappingIdx = b.internMapping(mappingKey{
			filename:   fi.MappingFile,
			buildID:    fi.BuildID,
			gnuBuildID: fi.GNUBuildID,
			goBuildID:  fi.GoBuildID,
		})
	}

	functionIdx := int32(-1)
	if fi.HasFunction {
		functionIdx = b.internFunction(fi.Function)
	}

	key := locationKey{
		mappingIndex: mappingIdx,
		address:      fi.Address,
		frameType:    fi.FrameType,
		functionIdx:  functionIdx,
		hasFunction:  fi.HasFunction,
		line:         fi.Line,
		column:       fi.Column,
	}
	if idx, ok := b.locations[key]; ok {
		return idx
	}

	idx := int32(b.dict.LocationTable().Len())
	loc := b.dict.LocationTable().AppendEmpty()
	loc.SetAddress(fi.Address)
	if mappingIdx >= 0 {
		loc.SetMappingIndex(mappingIdx)
	}
	if fi.HasFunction {
		line := loc.Lines().AppendEmpty()
		line.SetFunctionIndex(functionIdx)
		line.SetLine(int64(fi.Line))
		line.SetColumn(int64(fi.Column))
	}
	b.appendAttr(loc.AttributeIndices(), profileFrameTypeKey, fi.FrameType)

	b.locations[key] = idx
	return idx
}

func (b *pprofileBuilder) internStack(s sampleData) int32 {
	key := stackKey{hash: s.TraceHash, synthetic: s.SyntheticMemoryFrames}
	if idx, ok := b.stacks[key]; ok {
		return idx
	}

	idx := int32(b.dict.StackTable().Len())
	stack := b.dict.StackTable().AppendEmpty()
	for _, uf := range s.Frames {
		frame := uf.Value()
		var fi frameInfo
		if s.SyntheticMemoryFrames {
			fi = classifyMemoryFrame(frame, s.MemoryBuildID, s.MemoryExecPath)
		} else {
			fi = classifyFrame(frame, b.executables)
		}
		stack.LocationIndices().Append(b.internLocation(fi))
	}

	b.stacks[key] = idx
	return idx
}

// resourceLabels is the process-invariant half of a sample's attribution. It
// becomes an OTLP Resource, so every sample from the same process shares one.
type resourceLabels struct {
	Labels labels.Labels

	PID            int64
	ExecutablePath string
	ContainerID    string
	ServiceName    string
}

// hash keys the ResourceProfiles map. Two samples with equal label sets and
// equal process identity must land in the same resource, or the batch carries
// a Resource per sample and the attribute table balloons.
func (r resourceLabels) hash() uint64 {
	h := xxh3.New()
	r.Labels.Range(func(l labels.Label) {
		_, _ = h.WriteString(l.Name)
		_, _ = h.WriteString("\x00")
		_, _ = h.WriteString(l.Value)
		_, _ = h.WriteString("\x00")
	})
	_, _ = h.WriteString("\x01")
	_, _ = h.WriteString(strconv.FormatInt(r.PID, 10))
	_, _ = h.WriteString(r.ExecutablePath)
	_, _ = h.WriteString(r.ContainerID)
	_, _ = h.WriteString(r.ServiceName)
	return h.Sum64()
}

func (b *pprofileBuilder) resourceFor(res resourceLabels) *resourceProfileSet {
	key := res.hash()
	if rp, ok := b.resources[key]; ok {
		return rp
	}

	resProfiles := b.profiles.ResourceProfiles().AppendEmpty()
	attrs := resProfiles.Resource().Attributes()

	// The standard attributes first, so a consumer that only speaks semconv
	// still gets process identity.
	if res.ServiceName != "" {
		attrs.PutStr(attrServiceName, res.ServiceName)
	}
	if res.PID != 0 {
		attrs.PutInt(attrProcessPID, res.PID)
	}
	if res.ExecutablePath != "" {
		attrs.PutStr(attrProcessExePath, res.ExecutablePath)
	}
	if res.ContainerID != "" {
		attrs.PutStr(attrContainerID, res.ContainerID)
	}
	if b.nodeName != "" {
		attrs.PutStr(attrHostName, b.nodeName)
	}
	// Then parca-agent's own label vocabulary, verbatim, so relabel rules
	// and external labels keep the names operators configured.
	res.Labels.Range(func(l labels.Label) {
		attrs.PutStr(l.Name, l.Value)
	})

	scope := resProfiles.ScopeProfiles().AppendEmpty()
	scope.Scope().SetName("parca-agent")

	rp := &resourceProfileSet{scope: scope, byType: make(map[sampleType]pprofile.Profile)}
	b.resources[key] = rp
	return rp
}

func (b *pprofileBuilder) profileFor(rp *resourceProfileSet, st sampleType) pprofile.Profile {
	if p, ok := rp.byType[st]; ok {
		return p
	}

	p := rp.scope.Profiles().AppendEmpty()
	p.SampleType().SetTypeStrindex(b.internString(st.Type))
	p.SampleType().SetUnitStrindex(b.internString(st.Unit))
	if st.PeriodType != "" {
		p.PeriodType().SetTypeStrindex(b.internString(st.PeriodType))
		p.PeriodType().SetUnitStrindex(b.internString(st.PeriodUnit))
	}
	if st.Period != 0 {
		p.SetPeriod(st.Period)
	}

	rp.byType[st] = p
	return p
}

// AddSample records one sample. Not safe for concurrent use; the reporter holds
// a mutex around it.
func (b *pprofileBuilder) AddSample(res resourceLabels, st sampleType, s sampleData) {
	rp := b.resourceFor(res)
	profile := b.profileFor(rp, st)

	stackIdx := b.internStack(s)

	sample := profile.Samples().AppendEmpty()
	sample.SetStackIndex(stackIdx)
	sample.TimestampsUnixNano().Append(s.Timestamp)
	// One value per timestamp, matching the profile's single SampleType.
	sample.Values().Append(s.Value)

	attrs := sample.AttributeIndices()
	s.SampleLabels.Range(func(l labels.Label) {
		switch l.Name {
		case "thread_name":
			b.appendAttr(attrs, attrThreadName, l.Value)
		case "thread_id":
			b.appendAttr(attrs, attrThreadID, l.Value)
		case "cpu":
			b.appendAttr(attrs, attrCPUNumber, l.Value)
		default:
			b.appendAttr(attrs, attrProcessLabelPrefix+l.Name, l.Value)
		}
	})
	for k, v := range s.CustomLabels {
		b.appendAttr(attrs, attrProcessLabelPrefix+k.String(), v.String())
	}
	for k, v := range s.ExtraAttrs {
		b.appendAttr(attrs, attrProcessLabelPrefix+k, v)
	}

	b.sampleCount++
}

// SampleCount reports how many samples the current batch holds, so the caller
// can skip an empty export.
func (b *pprofileBuilder) SampleCount() int { return b.sampleCount }

// Build stamps the collection window onto every profile and hands over the
// batch, leaving the builder empty for the next interval.
func (b *pprofileBuilder) Build(start, end time.Time) pprofile.Profiles {
	duration := uint64(end.Sub(start).Nanoseconds())
	for i := range b.profiles.ResourceProfiles().Len() {
		rp := b.profiles.ResourceProfiles().At(i)
		for j := range rp.ScopeProfiles().Len() {
			sp := rp.ScopeProfiles().At(j)
			for k := range sp.Profiles().Len() {
				p := sp.Profiles().At(k)
				p.SetTime(pcommon.Timestamp(start.UnixNano()))
				p.SetDurationNano(duration)
			}
		}
	}

	out := b.profiles
	b.reset()
	return out
}

// classifyMemoryFrame handles the synthetic frames ReportMemoryTraces builds.
// Those stash the build ID and executable path in FunctionName and SourceFile
// because there is no mapping to hang them on, so classifyFrame would emit a
// function literally named after a build ID.
func classifyMemoryFrame(frame libpf.Frame, buildID, execPath string) frameInfo {
	return frameInfo{
		FrameType:      libpf.NativeFrame.String(),
		Address:        uint64(frame.AddressOrLineno),
		MappingFile:    execPath,
		HasMappingFile: execPath != "",
		BuildID:        buildID,
		GNUBuildID:     buildID,
		// No function: memory frames are symbolized server-side from the
		// build ID and address, exactly like sampled native frames.
	}
}
