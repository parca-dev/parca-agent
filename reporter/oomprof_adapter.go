/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import "github.com/parca-dev/oomprof/oomprof"

// oomprofBatchSize bounds how many samples we ship to the reporter in a
// single ReportMemoryTraces call. Memory traces share a writer lock with
// every other v2 sample row, so we want each lock acquisition to do a
// bounded amount of work. oomprof can deliver large bursts when a process
// is rapidly allocating.
const oomprofBatchSize = 100

// oomprofAdapter implements oomprof.Reporter on top of a ParcaReporter,
// chunking the incoming sample batch and forwarding each chunk through
// ReportMemoryTraces. It holds the ParcaReporter interface (not the
// concrete impl) so tests and future producers can stub it.
type oomprofAdapter struct {
	rep ParcaReporter
}

func newOOMProfAdapter(r ParcaReporter) *oomprofAdapter {
	return &oomprofAdapter{rep: r}
}

// SampleEvents satisfies oomprof.Reporter. Each chunk of at most
// oomprofBatchSize samples is handed to the reporter as a single
// ReportMemoryTraces call.
func (a *oomprofAdapter) SampleEvents(
	samples []oomprof.Sample, meta oomprof.SampleMeta,
) error {
	for i := 0; i < len(samples); i += oomprofBatchSize {
		end := i + oomprofBatchSize
		if end > len(samples) {
			end = len(samples)
		}
		if err := a.rep.ReportMemoryTraces(samples[i:end], meta); err != nil {
			return err
		}
	}
	return nil
}
