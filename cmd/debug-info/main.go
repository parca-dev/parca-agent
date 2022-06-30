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
	"io"
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
	"github.com/rzajac/flexbuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/logger"
)

type flags struct {
	LogLevel string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`

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

	die := debuginfo.NewExtractor(logger)
	diu := debuginfo.NewUploader(logger, debugInfoClient)

	var g grun.Group
	ctx, cancel := context.WithCancel(context.Background())
	switch kongCtx.Command() {
	case "upload <path>":
		g.Add(func() error {
			srcDst := map[string]io.WriteSeeker{}
			srcReader := map[debuginfo.SourceInfo]io.Reader{}

			buffers := []*flexbuf.Buffer{}
			for _, path := range flags.Upload.Paths {
				buildID, err := buildid.BuildID(path)
				if err != nil {
					level.Error(logger).Log("failed to extract elf build ID", "err", err)
					continue
				}
				f, err := os.Open(path)
				if err != nil {
					level.Error(logger).Log("failed to open source file", "err", err)
					continue
				}
				f.Close()

				buf := &flexbuf.Buffer{}
				srcDst[path] = buf
				srcReader[debuginfo.SourceInfo{BuildID: buildID, Path: path}] = buf
				buffers = append(buffers, buf)
			}

			if len(srcDst) == 0 {
				return errors.New("failed to find actionable files")
			}

			if err := die.ExtractAll(ctx, srcDst); err != nil {
				return fmt.Errorf("failed to extract debug information: %w", err)
			}
			defer func() {
				for _, buf := range buffers {
					buf.SeekStart()
				}
			}()

			return diu.UploadAll(ctx, srcReader)
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
			srcDst := map[string]io.WriteSeeker{}
			for _, path := range flags.Extract.Paths {
				buildID, err := buildid.BuildID(path)
				if err != nil {
					level.Error(logger).Log("msg", "failed to extract elf build ID", "err", err)
					continue
				}
				f, err := os.Open(path)
				if err != nil {
					level.Error(logger).Log("failed to open source file", "err", err)
					continue
				}
				f.Close()

				// ./out/<buildid>.debuginfo
				output := filepath.Join(flags.Extract.OutputDir, buildID+".debuginfo")

				outFile, err := os.Create(output)
				if err != nil {
					level.Error(logger).Log("msg", "failed to create output file", "err", err)
					continue
				}
				defer outFile.Close()

				srcDst[path] = outFile
			}

			if len(srcDst) == 0 {
				return errors.New("failed to find actionable files")
			}

			return die.ExtractAll(ctx, srcDst)
		}, func(error) {
			cancel()
		})

	case "buildid <path>":
		g.Add(func() error {
			id, err := buildid.BuildID(flags.Buildid.Path)
			if err != nil {
				level.Error(logger).Log("msg", "failed to extract elf build ID", "err", err)
				return err
			}
			if id == "" {
				return errors.New("failed to extract ELF build ID")
			}
			fmt.Fprintf(os.Stdout, "Build ID: %s\n", id)
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
