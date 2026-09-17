// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// attrValueType reports the pdata value type an attribute was written with,
// which is the thing string-vs-int assertions need and resolveAttrs discards.
func attrValueType(t *testing.T, p pprofile.Profiles, key string) pcommon.ValueType {
	t.Helper()
	dict := p.Dictionary()
	profile := onlyProfile(t, p)
	require.Equal(t, 1, profile.Samples().Len())

	indices := profile.Samples().At(0).AttributeIndices()
	for i := range indices.Len() {
		a := dict.AttributeTable().At(int(indices.At(i)))
		if dict.StringTable().At(int(a.KeyStrindex())) == key {
			return a.Value().Type()
		}
	}
	t.Fatalf("attribute %q not present on the sample", key)
	return pcommon.ValueTypeEmpty
}

func sampleWithLabels(t *testing.T, b *pprofileBuilder, lbls ...labels.Label) pprofile.Profiles {
	t.Helper()

	sb := labels.NewScratchBuilder(len(lbls))
	for _, l := range lbls {
		sb.Add(l.Name, l.Value)
	}
	sb.Sort()

	return addOne(b, cpuSampleType(19), sampleData{
		Frames:       frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:        1,
		SampleLabels: sb.Labels(),
	})
}

// TestSampleAttributeTypes pins the wire types of the semconv attributes the
// per-sample path emits. thread.id and cpu.logical_number are integers in the
// conventions and in upstream's reporter; emitting them as strings makes a
// consumer that reads them as ints either error or drop the attribute, and
// nothing about the profile looks wrong when that happens.
func TestSampleAttributeTypes(t *testing.T) {
	out := sampleWithLabels(t, testBuilder(t),
		labels.Label{Name: "cpu", Value: "7"},
		labels.Label{Name: "thread_id", Value: "424242"},
		labels.Label{Name: "thread_name", Value: "worker"},
	)

	require.Equal(t, pcommon.ValueTypeInt, attrValueType(t, out, attrThreadID))
	require.Equal(t, pcommon.ValueTypeInt, attrValueType(t, out, attrCPUNumber))
	require.Equal(t, pcommon.ValueTypeStr, attrValueType(t, out, attrThreadName))

	dict := out.Dictionary()
	profile := onlyProfile(t, out)
	indices := profile.Samples().At(0).AttributeIndices()
	for i := range indices.Len() {
		a := dict.AttributeTable().At(int(indices.At(i)))
		switch dict.StringTable().At(int(a.KeyStrindex())) {
		case attrThreadID:
			require.Equal(t, int64(424242), a.Value().Int())
		case attrCPUNumber:
			require.Equal(t, int64(7), a.Value().Int())
		case attrThreadName:
			require.Equal(t, "worker", a.Value().Str())
		}
	}
}

// TestSampleAttributeIntAndStringDoNotShareATableEntry covers the attribute
// cache: a string "7" and an integer 7 must not collide, or whichever is
// interned first silently decides the type for both.
func TestSampleAttributeIntAndStringDoNotShareATableEntry(t *testing.T) {
	b := testBuilder(t)
	out := sampleWithLabels(t, b,
		// cpu becomes an int; the relabel-derived label keeps the same digits
		// as a string under the process.context.label namespace.
		labels.Label{Name: "cpu", Value: "7"},
		labels.Label{Name: "shard", Value: "7"},
	)

	require.Equal(t, pcommon.ValueTypeInt, attrValueType(t, out, attrCPUNumber))
	require.Equal(t, pcommon.ValueTypeStr,
		attrValueType(t, out, attrProcessLabelPrefix+"shard"))
}

// TestUnparseableIntAttributeFallsBackToString covers a relabel rule rewriting
// one of the numeric labels. Dropping the attribute would lose data silently,
// so the value ships as a string instead.
func TestUnparseableIntAttributeFallsBackToString(t *testing.T) {
	out := sampleWithLabels(t, testBuilder(t),
		labels.Label{Name: "thread_id", Value: "main"},
	)
	require.Equal(t, pcommon.ValueTypeStr, attrValueType(t, out, attrThreadID))
}

// TestSchemaURLIsStamped guards the declaration that says which convention
// version the attribute keys follow. Upstream stamps both scopes.
func TestSchemaURLIsStamped(t *testing.T) {
	out := sampleWithLabels(t, testBuilder(t), labels.Label{Name: "cpu", Value: "0"})

	require.Equal(t, 1, out.ResourceProfiles().Len())
	rp := out.ResourceProfiles().At(0)
	require.Equal(t, semconvSchemaURL, rp.SchemaUrl())

	require.Equal(t, 1, rp.ScopeProfiles().Len())
	require.Equal(t, semconvSchemaURL, rp.ScopeProfiles().At(0).SchemaUrl())
}
