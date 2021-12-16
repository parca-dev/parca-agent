package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/containerd/cgroups"
	"github.com/go-kit/log"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
)

func TestCgroupProfiler(t *testing.T) {
	var (
		gotSample = make(chan struct{})

		// Put this here specifically so we only close over the t and gotsample variables
		// and don't bloat this closure with a bunch of variables.
		sink = func(r Record) {
			if len(r.Profile.Sample) == 0 {
				t.Fatal("expected at least one sample")
			}
			gotSample <- struct{}{}
		}

		unit           = "upower.service" // Ensure we profile a noisy and ubiquitous process.
		logger         = log.NewNopLogger()
		ksymCache      = ksym.NewKsymCache(logger)
		ctx            = context.Background()
		duration       = time.Second * 10
		errCh          = make(chan error)
		externalLabels = map[string]string{"systemdunit": unit}
	)

	f, err := os.CreateTemp(os.TempDir(), "test.tmp")
	if err != nil {
		t.Fatal(err)
	}
	// Seems backwards but since defers stack this will
	// close first then remove.
	defer os.Remove(f.Name())
	defer f.Close()

	p := NewCgroupProfiler(
		logger,
		externalLabels,
		ksymCache,
		NewNoopProfileStoreClient(),
		debuginfo.NewNoopClient(),
		&SystemdUnitTarget{
			Name:       unit,
			NodeName:   "testnode",
			cgroupMode: cgroups.Mode(),
		},
		duration,
		sink,
		f.Name(),
	)
	if p == nil {
		t.Fatal("expected a non-nil profiler")
	}

	// Start the profiler. Run in separate goroutine so we can
	// assert since this operation blocks.
	go func(errc chan error) { errc <- p.Run(ctx) }(errCh)

	t.Log("waiting for profiler to collect data")
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-gotSample:
		// Nothing to do here, just break out of the select.
	case <-time.After(duration + time.Second): // Allow enough time for profiling to complete.
		t.Fatal("timed out waiting for profiler to run")
	}
}
