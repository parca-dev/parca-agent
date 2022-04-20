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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	grun "github.com/oklog/run"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/logger"
)

type flags struct {
	LogLevel string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`
	TempDir  string `kong:"help='Temporary directory path to use for object files.',default='tmp'"`

	Upload struct {
		StoreAddress       string `kong:"required,help='gRPC address to sends symbols to.'"`
		BearerToken        string `kong:"help='Bearer token to authenticate with store.'"`
		BearerTokenFile    string `kong:"help='File to read bearer token from to authenticate with store.'"`
		Insecure           bool   `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
		InsecureSkipVerify bool   `kong:"help='Skip TLS certificate verification.'"`

		Paths []string `kong:"required,arg,name='path',help='Paths to upload.',type:'path'"`
	} `cmd:"" help:"Upload debug information files."`

	Extract struct {
		OutputDir string `kong:"help='Output directory path to use for extracted debug information files.',default='out'"`

		Paths []string `kong:"required,arg,name='path',help='Paths to extract debug information.',type:'path'"`
	} `cmd:"" help:"Extract debug information."`

	Buildid struct {
		Path string `kong:"required,arg,name='path',help='Paths to extract buildid.',type:'path'"`
	} `cmd:"" help:"Extract buildid."`
}

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	if err := run(); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "done!")
}

func run() error {
	flags := flags{}
	kongCtx := kong.Parse(&flags)
	logger := logger.NewLogger(flags.LogLevel, logger.LogFormatLogfmt, "")

	debugInfoClient := debuginfo.NewNoopClient()

	if len(flags.Upload.StoreAddress) > 0 {
		level.Debug(logger).Log("msg", "configuration", "bearertoken", flags.Upload.BearerToken, "insecure", flags.Upload.Insecure)
		conn, err := grpcConn(prometheus.NewRegistry(), flags)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		defer conn.Close()

		debugInfoClient = parcadebuginfo.NewDebugInfoClient(conn)
	}

	die := debuginfo.NewExtractor(logger, debugInfoClient, flags.TempDir)
	diu := debuginfo.NewUploader(logger, debugInfoClient)

	var g grun.Group
	ctx, cancel := context.WithCancel(context.Background())
	switch kongCtx.Command() {
	case "upload <path>":
		g.Add(func() error {
			buildIDFiles := map[string]string{}
			for _, path := range flags.Upload.Paths {
				buildID, err := buildid.BuildID(path)
				if err != nil {
					level.Error(logger).Log("failed to extract elf build ID", "err", err)
					continue
				}
				buildIDFiles[buildID] = path
			}

			if len(buildIDFiles) == 0 {
				return errors.New("failed to find actionable files")
			}

			debugInfoFiles, err := die.ExtractAll(ctx, buildIDFiles)
			if err != nil {
				return fmt.Errorf("failed to extract debug information: %w", err)
			}
			defer func() {
				for _, f := range debugInfoFiles {
					os.Remove(f)
				}
			}()

			return diu.UploadAll(ctx, debugInfoFiles)
		}, func(error) {
			cancel()
		})
	case "extract <path>":
		g.Add(func() error {
			if err := os.RemoveAll(flags.Extract.OutputDir); err != nil {
				return fmt.Errorf("failed to clean output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			if err := os.MkdirAll(flags.Extract.OutputDir, 0o755); err != nil {
				return fmt.Errorf("failed to create output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			buildIDFiles := map[string]string{}
			for _, path := range flags.Extract.Paths {
				buildID, err := buildid.BuildID(path)
				if err != nil {
					level.Error(logger).Log("msg", "failed to extract elf build ID", "err", err)
					continue
				}
				buildIDFiles[buildID] = path
			}

			if len(buildIDFiles) == 0 {
				return errors.New("failed to find actionable files")
			}

			files, err := die.ExtractAll(ctx, buildIDFiles)
			if err != nil {
				return err
			}

			for _, f := range files {
				// ./out/<buildid>/debuginfo
				_, p := filepath.Split(filepath.Dir(f))
				output := filepath.Join(flags.Extract.OutputDir, filepath.Base(p))
				if err := os.Rename(f, output); err != nil {
					level.Error(logger).Log("msg", "failed to move file", "file", output, "err", err)
					continue
				}
				level.Info(logger).Log("msg", "debug information extracted", "file", output)
			}
			return nil
		}, func(error) {
			cancel()
		})
	case "buildid <path>":
		g.Add(func() error {
			_, err := buildid.BuildID(flags.Buildid.Path)
			if err != nil {
				level.Error(logger).Log("msg", "failed to extract elf build ID", "err", err)
				return err
			}
			return nil
		}, func(error) {
			cancel()
		})
	default:
		level.Error(logger).Log("err", "Unknown command", "cmd", kongCtx.Command())
		cancel()
		return errors.New("unknown command: " + kongCtx.Command())
	}

	g.Add(grun.SignalHandler(ctx, os.Interrupt, os.Kill))
	return g.Run()
}

func grpcConn(reg prometheus.Registerer, flags flags) (*grpc.ClientConn, error) {
	met := grpc_prometheus.NewClientMetrics()
	met.EnableClientHandlingTimeHistogram()
	reg.MustRegister(met)

	opts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(
			met.UnaryClientInterceptor(),
		),
	}
	if flags.Upload.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			//nolint:gosec
			InsecureSkipVerify: flags.Upload.InsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	if flags.Upload.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    flags.Upload.BearerToken,
			insecure: flags.Upload.Insecure,
		}))
	}

	if flags.Upload.BearerTokenFile != "" {
		b, err := ioutil.ReadFile(flags.Upload.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    string(b),
			insecure: flags.Upload.Insecure,
		}))
	}

	return grpc.Dial(flags.Upload.StoreAddress, opts...)
}

type perRequestBearerToken struct {
	token    string
	insecure bool
}

func (t *perRequestBearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t *perRequestBearerToken) RequireTransportSecurity() bool {
	return !t.insecure
}
