package convert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollapsedAsyncProfilerToPprof(t *testing.T) {
	for _, file := range []string{"cpu", "allocs"} {
		f, err := os.Open(filepath.Join("./testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		_, err = CollapsedAsyncProfilerToPprof(f, profilerType(file))
		if err != nil {
			t.Fatal(err)
		}
	}
}
