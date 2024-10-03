package reporter

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/stretchr/testify/require"
)

func Test_Offline_ReadFile(t *testing.T) {
	f, err := os.Open("/tmp/offline-data/019251da-d851-7cee-a4dd-385102cb1d9a.ipc")
	require.NoError(t, err)

	printFile(t, f)
	printFile(t, f)
}

func printFile(t *testing.T, f ipc.ReadAtSeeker) {
	t.Helper()
	reader, err := ipc.NewFileReader(f)
	require.NoError(t, err)

	for {
		batch, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		t.Log(batch)
	}
}
