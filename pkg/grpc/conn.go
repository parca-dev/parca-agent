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

package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/prometheus/client_golang/prometheus"
	tracing "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"

	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
)

type perRequestBearerToken struct {
	token    string
	insecure bool
}

func NewPerRequestBearerToken(token string, insecure bool) *perRequestBearerToken {
	return &perRequestBearerToken{
		token:    token,
		insecure: insecure,
	}
}

func (t *perRequestBearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t *perRequestBearerToken) RequireTransportSecurity() bool {
	return !t.insecure
}

func Conn(logger log.Logger, reg prometheus.Registerer, tp trace.TracerProvider, address string, unaryTimeout time.Duration, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	encoding.RegisterCodec(vtprotoCodec{})

	// metrics
	metrics := grpc_prometheus.NewClientMetrics(
		grpc_prometheus.WithClientHandlingTimeHistogram(
			grpc_prometheus.WithHistogramOpts(&prometheus.HistogramOpts{
				NativeHistogramBucketFactor: 1.1,
				Buckets:                     nil,
			}),
		),
	)
	reg.MustRegister(metrics)

	// tracing
	exemplarFromContext := func(ctx context.Context) prometheus.Labels {
		if span := trace.SpanContextFromContext(ctx); span.IsSampled() {
			return prometheus.Labels{"traceID": span.TraceID().String()}
		}
		return nil
	}
	logTraceID := func(ctx context.Context) logging.Fields {
		if span := trace.SpanContextFromContext(ctx); span.IsSampled() {
			return logging.Fields{"traceID", span.TraceID().String()}
		}
		return nil
	}
	propagators := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

	opts = append(opts,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(parcadebuginfo.MaxMsgSize),
			grpc.MaxCallRecvMsgSize(parcadebuginfo.MaxMsgSize),
		),
		grpc.WithChainUnaryInterceptor(
			timeout.UnaryClientInterceptor(unaryTimeout), // 5m by default.
			retry.UnaryClientInterceptor(
				// Back-off with Jitter: scalar: 1s, jitterFraction: 0,1, 10 runs
				// i: 1		t:969.91774ms		total:969.91774ms
				// i: 2		t:1.914221005s		total:2.884138745s
				// i: 3		t:3.788704363s		total:6.672843108s
				// i: 4		t:8.285062088s		total:14.957905196s
				// i: 5		t:14.480256611s		total:29.438161807s
				// i: 6		t:32.586249789s		total:1m2.024411596s
				// i: 7		t:1m6.755804584s	total:2m8.78021618s
				// i: 8		t:2m3.116345957s	total:4m11.896562137s
				// i: 9		t:4m3.895083732s	total:8m15.791645869s
				// i: 10	t:9m19.350609671s	total:17m35.14225554s
				retry.WithBackoff(retry.BackoffExponentialWithJitter(time.Second, 0.1)),
				retry.WithMax(10),
				// The passed in context has a `5m` timeout (see above), the whole invocation should finish within that time.
				// However, by default all retried calls will use the parent context for their deadlines.
				// This means, that unless you shorten the deadline of each call of the retry, you won't be able to retry the first call at all.
				// `WithPerRetryTimeout` allows you to shorten the deadline of each retry call, allowing you to fit multiple retries in the single parent deadline.
				retry.WithPerRetryTimeout(2*time.Minute),
			),
			tracing.UnaryClientInterceptor(
				tracing.WithTracerProvider(tp),
				tracing.WithPropagators(propagators),
			),
			metrics.UnaryClientInterceptor(
				grpc_prometheus.WithExemplarFromContext(exemplarFromContext),
			),
			logging.UnaryClientInterceptor(interceptorLogger(logger), logging.WithFieldsFromContext(logTraceID)),
		),
		grpc.WithChainStreamInterceptor(
			tracing.StreamClientInterceptor(
				tracing.WithTracerProvider(tp),
				tracing.WithPropagators(propagators),
			),
			metrics.StreamClientInterceptor(
				grpc_prometheus.WithExemplarFromContext(exemplarFromContext),
			),
			logging.StreamClientInterceptor(interceptorLogger(logger), logging.WithFieldsFromContext(logTraceID)),
		),
	)

	return grpc.Dial(address, opts...)
}

// interceptorLogger adapts go-kit logger to interceptor logger.
func interceptorLogger(l log.Logger) logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, lvl logging.Level, msg string, fields ...any) {
		largs := append([]any{"msg", msg}, fields...)
		switch lvl {
		case logging.LevelDebug:
			_ = level.Debug(l).Log(largs...)
		case logging.LevelInfo:
			_ = level.Info(l).Log(largs...)
		case logging.LevelWarn:
			_ = level.Warn(l).Log(largs...)
		case logging.LevelError:
			_ = level.Error(l).Log(largs...)
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
	})
}
