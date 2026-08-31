package flags

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProfileFormat pins the compatibility mapping from the deprecated
// --use-v2-schema bool onto the format enum, so existing invocations keep the
// encoding they had.
func TestProfileFormat(t *testing.T) {
	for _, tc := range []struct {
		name        string
		format      string
		useV2Schema bool
		want        string
	}{
		{"default is arrow-v2", RemoteStoreFormatArrowV2, true, RemoteStoreFormatArrowV2},
		{"deprecated bool false means arrow-v1", RemoteStoreFormatArrowV2, false, RemoteStoreFormatArrowV1},
		{"explicit arrow-v1 wins", RemoteStoreFormatArrowV1, true, RemoteStoreFormatArrowV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Flags{}
			f.RemoteStore.Format = tc.format
			f.RemoteStore.UseV2Schema = tc.useV2Schema
			require.Equal(t, tc.want, f.ProfileFormat())
		})
	}
}
