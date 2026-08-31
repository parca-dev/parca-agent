package flags

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigureCompression(t *testing.T) {
	for _, tc := range []struct {
		name        string
		compression string
		wantOpt     bool
		wantErr     bool
	}{
		{"default gzip", CompressionGzip, true, false},
		{"none", CompressionNone, false, false},
		{"empty is none", "", false, false},
		{"unknown is rejected", "zstd", false, true},
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
