package metrics

//go:generate python3 genschema/gen.py metrics.json all.go

// MetricUnit is the type for metric units (e.g. millis).
type MetricUnit uint64

// MetricType is the type for metric types (e.g. gauge).
type MetricType uint64

type Metric struct {
	Desc  string
	Field string
	Type  MetricType
	Unit  MetricUnit
}
