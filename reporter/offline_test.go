package reporter

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/memory"
	"github.com/stretchr/testify/require"
)

func Test_Offline_ReadFile(t *testing.T) {
	alloc := memory.NewGoAllocator()
	schema := arrow.NewSchema([]arrow.Field{
		{
			Name:     "name",
			Type:     &arrow.StringType{},
			Nullable: true,
		},
	}, nil)

	bld := array.NewRecordBuilder(alloc, schema)
	t.Cleanup(bld.Release)

	bld.Field(0).(*array.StringBuilder).Append("hello")
	bld.Field(0).(*array.StringBuilder).Append("world")

	rec := bld.NewRecord()
	t.Cleanup(rec.Release)

	f, err := os.CreateTemp("", "test-*.arrow")
	require.NoError(t, err)

	// Write a few records to the file
	log, err := NewArrowLogger(f.Name())
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		require.NoError(t, log.Write(alloc, rec))
	}
	require.NoError(t, log.Close())

	// Read the Arrow log
	logreader, err := OpenArrowLog(f.Name())
	require.NoError(t, err)

	// Validate the number of records the log has
	count := 0
	for {
		_, err := logreader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}
		count++
	}
	require.Equal(t, 10, count)
}
