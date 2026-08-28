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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// The canonical model is the neutral form both encodings decode to. It exists
// so losslessness can be judged by diffing two JSON documents rather than by
// eyeballing two very different in-memory shapes.
//
// Field-for-field it is the Arrow v2 row, because that is the richer of the two
// and therefore the one that can lose information. Anything in here that OTLP
// has no native home for is called out in encodeOTLP.

type canonSample struct {
	// Labels is the flattened label set. Arrow carries one flat map; OTLP
	// splits it across Resource and Sample attributes, and the split has to
	// be reversible for the round trip to close.
	Labels map[string]string `json:"labels,omitempty"`

	Stack []canonLocation `json:"stack"`

	// StacktraceID is Arrow's 16-byte trace hash. OTLP has no field for it:
	// stacks are dictionary indices there, so it rides as an attribute.
	StacktraceID string `json:"stacktrace_id,omitempty"`

	Value     int64  `json:"value"`
	Timestamp uint64 `json:"timestamp"`

	SampleType string `json:"sample_type"`
	SampleUnit string `json:"sample_unit"`
	PeriodType string `json:"period_type,omitempty"`
	PeriodUnit string `json:"period_unit,omitempty"`
	Period     int64  `json:"period"`
	Duration   uint64 `json:"duration"`

	// Producer and Temporality have no native OTLP representation. Producer
	// is a parca concept; temporality was dropped from pprofile.Profile in
	// the dictionary redesign. Both ride as attributes.
	Producer    string `json:"producer,omitempty"`
	Temporality string `json:"temporality,omitempty"`
}

type canonLocation struct {
	Address        uint64      `json:"address"`
	FrameType      string      `json:"frame_type,omitempty"`
	MappingFile    string      `json:"mapping_file,omitempty"`
	MappingBuildID string      `json:"mapping_build_id,omitempty"`
	Lines          []canonLine `json:"lines,omitempty"`
}

type canonLine struct {
	Line       uint64 `json:"line"`
	Column     uint64 `json:"column"`
	SystemName string `json:"system_name,omitempty"`
	Filename   string `json:"filename,omitempty"`
	StartLine  uint64 `json:"start_line,omitempty"`
}

// canonKey is a total order over samples. Neither encoding preserves row order
// -- OTLP regroups by resource and sample type, and the Arrow writers dedupe --
// so the comparison has to be order-independent.
func (s canonSample) canonKey() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// canonicalJSON renders a sample set as a stable document: labels sorted by key
// (map marshalling already does that), samples sorted by their own encoding.
func canonicalJSON(samples []canonSample) ([]byte, error) {
	keys := make([]string, len(samples))
	for i, s := range samples {
		keys[i] = s.canonKey()
	}
	sort.Strings(keys)

	buf := bytes.NewBuffer(nil)
	buf.WriteString("[\n")
	for i, k := range keys {
		buf.WriteString("  ")
		buf.WriteString(k)
		if i < len(keys)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("]\n")
	return buf.Bytes(), nil
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
