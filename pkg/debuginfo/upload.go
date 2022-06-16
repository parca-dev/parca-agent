// Copyright (c) 2022 The Parca Authors
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

package debuginfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"
	"github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
)

// SourceInfo source information of the given debug information.
type SourceInfo struct {
	BuildID string
	Path    string
	// SourceType string // local, running, debuginfod etc. // TODO(kakkoyun): Next iterations.
}

// Uploader uploads debug information to the Parca server.
type Uploader struct {
	logger log.Logger
	client Client
}

// NewUploader creates a new Uploader.
func NewUploader(logger log.Logger, client Client) *Uploader {
	return &Uploader{
		logger: log.With(logger, "component", "uploader"),
		client: client,
	}
}

// UploadAll uploads all debug information to the Parca server.
func (u *Uploader) UploadAll(ctx context.Context, srcDbgInfo map[SourceInfo]io.Reader) error {
	var result *multierror.Error
	for src, r := range srcDbgInfo {
		if err := u.Upload(ctx, src, r); err != nil {
			level.Warn(u.logger).Log(
				"msg", "failed to upload debug information",
				"buildid", src.BuildID, "err", err,
			)
			result = multierror.Append(result, err)
			continue
		}
		level.Debug(u.logger).Log(
			"msg", "debug information uploaded successfully",
			"buildid", src.BuildID,
		)
	}

	return result.ErrorOrNil()
}

// Upload uploads the debug information to the Parca server.
func (u *Uploader) Upload(ctx context.Context, src SourceInfo, r io.Reader) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	h, err := hash.File(src.Path)
	if err != nil {
		return err
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = time.Second
	expBackOff.MaxElapsedTime = time.Minute

	err = backoff.Retry(func() error {
		if _, err := u.client.Upload(ctx, src.BuildID, h, r); err != nil {
			if errors.Is(err, debuginfo.ErrDebugInfoAlreadyExists) {
				// No need to retry.
				return backoff.Permanent(err)
			}
			level.Debug(u.logger).Log(
				"msg", "failed to upload debug information",
				"buildid", src.BuildID,
				"retry", expBackOff.NextBackOff(),
				"err", err,
			)
			return err
		}
		return nil
	}, expBackOff)
	if err != nil {
		return fmt.Errorf("failed to upload debug information: %w", err)
	}

	return nil
}
