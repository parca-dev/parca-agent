package buildid

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClean(t *testing.T) {
	t.Parallel()

	require.Equal(t, "abc", Clean("abc"))
	require.Equal(t, "abc", Clean("abc\x00"))
	require.Equal(t, "abc", Clean("abc\x00ignored"))
}

func TestGNUFromNotes(t *testing.T) {
	t.Parallel()

	buildID := []byte{0xde, 0xad, 0xbe, 0xef}

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(len(gnuBuildIDNoteName))))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(len(buildID))))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(gnuBuildIDNoteType)))
	buf.WriteString(gnuBuildIDNoteName)
	buf.Write(buildID)

	got, ok, err := gnuFromNotes(buf.Bytes(), binary.LittleEndian, 4)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "deadbeef", got)
}

func TestResolveFallsBackToCleanBuildID(t *testing.T) {
	t.Parallel()

	require.Equal(t, "go-build-id", Resolve("/does/not/exist", "go-build-id\x00"))
	require.Equal(t, "", Resolve("", "\x00"))
}
