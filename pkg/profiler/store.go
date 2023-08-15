// Copyright 2022-2023 The Parca Authors
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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/klauspost/compress/gzip"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/profile"
)

// FileStore writes profiles to a local file.
type FileStore struct {
	dir string
}

// NewFileStore creates a new FileProfileWriter.
func NewFileStore(dirPath string) *FileStore {
	return &FileStore{dir: dirPath}
}

func (fw *FileStore) Store(_ context.Context, labels model.LabelSet, prof profile.Writer, _ []*profilestorepb.ExecutableInfo) error {
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

// RemoteStore is a profile writer that writes profiles to a remote profile store.
type RemoteStore struct {
	profileStoreClient profilestorepb.ProfileStoreServiceClient
	// pool of gzip encoders helps to reduce GC pressure.
	pool sync.Pool
}

// NewRemoteStore creates a new RemoteProfileWriter.
func NewRemoteStore(logger log.Logger, profileStoreClient profilestorepb.ProfileStoreServiceClient) *RemoteStore {
	return &RemoteStore{
		profileStoreClient: profileStoreClient,
		pool: sync.Pool{New: func() interface{} {
			z, err := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			if err != nil {
				level.Error(logger).Log("msg", "failed to create gzip writer", "err", err)
				return nil
			}
			return z
		}},
	}
}

// Store sends the profile using the designated write client.
func (rw *RemoteStore) Store(ctx context.Context, labels model.LabelSet, prof profile.Writer, ei []*profilestorepb.ExecutableInfo) error {
	buf := bytes.NewBuffer(nil)
	zw := rw.pool.Get().(*gzip.Writer) //nolint:forcetypeassert
	zw.Reset(buf)
	if err := prof.WriteUncompressed(zw); err != nil {
		zw.Close()
		rw.pool.Put(zw)
		return err
	}
	zw.Close()
	rw.pool.Put(zw)

	_, err := rw.profileStoreClient.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
		Series: []*profilestorepb.RawProfileSeries{{
			Labels: &profilestorepb.LabelSet{Labels: convertLabels(labels)},
			Samples: []*profilestorepb.RawSample{{
				RawProfile:     buf.Bytes(),
				ExecutableInfo: ei,
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
