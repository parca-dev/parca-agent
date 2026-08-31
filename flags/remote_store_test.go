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
		{"explicit otlp is unaffected by the bool", RemoteStoreFormatOTLP, false, RemoteStoreFormatOTLP},
		{"explicit otlp with the bool set", RemoteStoreFormatOTLP, true, RemoteStoreFormatOTLP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Flags{}
			f.RemoteStore.Format = tc.format
			f.RemoteStore.UseV2Schema = tc.useV2Schema
			require.Equal(t, tc.want, f.ProfileFormat())
		})
	}
}

func TestValidateRemoteStore(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   func() Flags
		wantErr bool
	}{
		{
			name: "arrow formats need no extra validation",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatArrowV2
				f.OfflineMode.StoragePath = "/var/lib/parca"
				return f
			},
		},
		{
			name: "otlp with no debuginfo destination is rejected",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatOTLP
				return f
			},
			wantErr: true,
		},
		{
			name: "otlp with a remote store passes",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatOTLP
				f.RemoteStore.Address = "ingest:4317"
				return f
			},
		},
		{
			name: "otlp with a dedicated debuginfo address passes",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatOTLP
				f.RemoteStore.Address = "ingest:4317"
				f.Debuginfo.Address = "api:443"
				return f
			},
		},
		{
			name: "otlp with upload disabled passes",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatOTLP
				f.Debuginfo.UploadDisable = true
				return f
			},
		},
		{
			name: "otlp with offline mode is rejected",
			build: func() Flags {
				f := Flags{}
				f.RemoteStore.Format = RemoteStoreFormatOTLP
				f.RemoteStore.Address = "ingest:4317"
				f.OfflineMode.StoragePath = "/var/lib/parca"
				return f
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := tc.build().validateRemoteStore()
			if tc.wantErr {
				require.NotEqual(t, ExitSuccess, code, "expected this combination to be rejected")
				return
			}
			require.Equal(t, ExitSuccess, code)
		})
	}
}
