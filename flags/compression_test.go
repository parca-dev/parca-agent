package flags

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/encoding"
)

func TestConfigureCompression(t *testing.T) {
	for _, tc := range []struct {
		name       string
		compression string
		wantOpt    bool
		wantErr    bool
	}{
		{"default gzip", CompressionGzip, true, false},
		{"zstd", CompressionZstd, true, false},
		{"none", CompressionNone, false, false},
		{"empty is none", "", false, false},
		{"unknown is rejected", "brotli", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt, ok, err := ConfigureCompression(tc.compression)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantOpt, ok)
			if tc.wantOpt {
				require.NotNil(t, opt)
			}
		})
	}
}

// TestZstdCompressorRoundTrip exercises the compressor through the same
// interface gRPC calls, including reuse from the pool, since a broken Reset
// would corrupt the second message rather than the first.
func TestZstdCompressorRoundTrip(t *testing.T) {
	RegisterZstdCompressor()

	c := encoding.GetCompressor(zstdCompressorName)
	require.NotNil(t, c, "zstd must be registered under the name a collector negotiates")
	require.Equal(t, "zstd", c.Name())

	payloads := [][]byte{
		bytes.Repeat([]byte("parca-agent profiles "), 512),
		[]byte("short"),
		{},
		bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 4096),
	}

	for i, want := range payloads {
		var buf bytes.Buffer
		w, err := c.Compress(&buf)
		require.NoError(t, err, "payload %d", i)
		_, err = w.Write(want)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := c.Decompress(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)

		require.Equal(t, want, got, "payload %d did not survive the round trip", i)
	}
}

// TestZstdCompressorCompresses guards against a codec that silently passes
// bytes through, which would look fine in a round-trip test.
func TestZstdCompressorCompresses(t *testing.T) {
	RegisterZstdCompressor()
	c := encoding.GetCompressor(zstdCompressorName)

	// Profile payloads are highly repetitive, which is why compression pays.
	payload := bytes.Repeat([]byte("stacktrace_id sample_type cpu nanoseconds "), 1024)

	var buf bytes.Buffer
	w, err := c.Compress(&buf)
	require.NoError(t, err)
	_, err = w.Write(payload)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.Less(t, buf.Len(), len(payload)/4,
		"expected at least 4x compression on repetitive input, got %d -> %d", len(payload), buf.Len())
}
