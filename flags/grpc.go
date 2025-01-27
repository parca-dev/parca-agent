package flags

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tracing "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// WaitGrpcEndpoint waits until the gRPC connection is established.
func (f FlagsRemoteStore) WaitGrpcEndpoint(ctx context.Context, reg prometheus.Registerer, tp trace.TracerProvider) (*grpc.ClientConn, error) {
	// Sleep with a fixed backoff time added of +/- 20% jitter
	tick := time.NewTicker(libpf.AddJitter(f.GRPCStartupBackoffTime, 0.2))
	defer tick.Stop()

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

	var retries uint32
	for {
		if grpcConn, err := f.setupGrpcConnection(ctx, metrics, tp); err != nil {
			if retries >= f.GRPCMaxConnectionRetries {
				return nil, err
			}
			retries++

			log.Warnf(
				"Failed to setup gRPC connection (try %d of %d): %v",
				retries,
				f.GRPCMaxConnectionRetries,
				err,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
				continue
			}
		} else {
			return grpcConn, nil
		}
	}
}

// setupGrpcConnection sets up a gRPC connection instrumented with our auth interceptor
func (f FlagsRemoteStore) setupGrpcConnection(parent context.Context, metrics *grpc_prometheus.ClientMetrics, tp trace.TracerProvider) (*grpc.ClientConn, error) {
	encoding.RegisterCodec(vtprotoCodec{})

	//nolint:staticcheck
	opts := []grpc.DialOption{grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(f.GRPCMaxCallRecvMsgSize),
			grpc.MaxCallSendMsgSize(f.GRPCMaxCallSendMsgSize)),
		grpc.WithReturnConnectionError(),
	}

	if f.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				// Support only TLS1.3+ with valid CA certificates
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: f.InsecureSkipVerify,
			})))
	}

	// Auth
	if f.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(
			NewPerRequestBearerToken(f.BearerToken, f.Insecure)),
		)
	}

	if f.BearerTokenFile != "" {
		b, err := os.ReadFile(f.BearerTokenFile)
		if err != nil {
			panic(fmt.Errorf("failed to read bearer token from file: %w", err))
		}

		opts = append(opts, grpc.WithPerRPCCredentials(
			NewPerRequestBearerToken(strings.TrimSpace(string(b)), f.Insecure)),
		)
	}

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
		grpc.WithChainUnaryInterceptor(
			timeout.UnaryClientInterceptor(f.RPCUnaryTimeout), // 5m by default.
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
			metrics.UnaryClientInterceptor(
				grpc_prometheus.WithExemplarFromContext(exemplarFromContext),
			),
			logging.UnaryClientInterceptor(interceptorLogger(), logging.WithFieldsFromContext(logTraceID)),
		),
		grpc.WithChainStreamInterceptor(
			metrics.StreamClientInterceptor(
				grpc_prometheus.WithExemplarFromContext(exemplarFromContext),
			),
			logging.StreamClientInterceptor(interceptorLogger(), logging.WithFieldsFromContext(logTraceID)),
		),
		grpc.WithStatsHandler(tracing.NewClientHandler(
			tracing.WithTracerProvider(tp),
			tracing.WithPropagators(propagators),
		)),
	)

	ctx, cancel := context.WithTimeout(parent, f.GRPCConnectionTimeout)
	defer cancel()
	//nolint:staticcheck
	return grpc.DialContext(ctx, f.Address, opts...)
}

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

// interceptorLogger adapts go-kit logger to interceptor logger.
func interceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, lvl logging.Level, msg string, fields ...any) {
		largs := append([]any{msg}, fields...)
		switch lvl {
		case logging.LevelDebug:
			log.Debug(largs...)
		case logging.LevelInfo:
			log.Info(largs...)
		case logging.LevelWarn:
			log.Warn(largs...)
		case logging.LevelError:
			log.Error(largs...)
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
	})
}
