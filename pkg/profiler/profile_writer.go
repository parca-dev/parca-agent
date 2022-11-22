// Copyright 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package profiler

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/pprof/profile"
	"github.com/klauspost/compress/gzip"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"
)

// FileProfileWriter writes profiles to a local file.
type FileProfileWriter struct {
	dir string
}

// NewFileProfileWriter creates a new FileProfileWriter.
func NewFileProfileWriter(dirPath string) *FileProfileWriter {
	return &FileProfileWriter{dir: dirPath}
}

func (fw *FileProfileWriter) Write(_ context.Context, labels model.LabelSet, prof *profile.Profile) error {
	path := fmt.Sprintf("%s_%s_%03d.pb.gz", string(labels["pid"]), string(labels["__name__"]), time.Now().UnixNano())

	if err := os.MkdirAll(fw.dir, 0o755); err != nil {
		return fmt.Errorf("could not use temp dir, %s: %w", fw.dir, err)
	}

	f, err := os.OpenFile(filepath.Join(fw.dir, path), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}
	if err := prof.Write(f); err != nil {
		return err
	}

	return nil
}

// RemoteProfileWriter is a profile writer that writes profiles to a remote profile store.
type RemoteProfileWriter struct {
	zw                 *gzip.Writer
	profileStoreClient profilestorepb.ProfileStoreServiceClient
}

// NewRemoteProfileWriter creates a new RemoteProfileWriter.
func NewRemoteProfileWriter(profileStoreClient profilestorepb.ProfileStoreServiceClient) *RemoteProfileWriter {
	return &RemoteProfileWriter{
		zw:                 gzip.NewWriter(nil),
		profileStoreClient: profileStoreClient,
	}
}

// Write sends the profile using the designated write client.
func (rw *RemoteProfileWriter) Write(ctx context.Context, labels model.LabelSet, prof *profile.Profile) error {
	// Write a profile into buf with a reusable gzip writer
	// to reduce memory allocations (reuse a compressor).
	// Note, an archive won't have a gzip footer (it still works)
	// because we can't call Close.
	buf := bytes.NewBuffer(nil)
	zw, err := gzip.NewWriterLevel(buf, gzip.StatelessCompression)
	if err != nil {
		return err
	}
	if err = prof.WriteUncompressed(zw); err != nil {
		zw.Close()
		return err
	}
	zw.Close()

	_, err = rw.profileStoreClient.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
		Normalized: true,
		Series: []*profilestorepb.RawProfileSeries{{
			Labels: &profilestorepb.LabelSet{Labels: convertLabels(labels)},
			Samples: []*profilestorepb.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}},
	})

	return err
}

func convertLabels(labels model.LabelSet) []*profilestorepb.Label {
	newLabels := make([]*profilestorepb.Label, 0, len(labels))
	for key, value := range labels {
		newLabels = append(newLabels, &profilestorepb.Label{
			Name:  string(key),
			Value: string(value),
		})
	}
	return newLabels
}
