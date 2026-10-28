package flags

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// --debuginfo-address dials a second connection with the same registerer as
// the remote store's, which used to panic on the duplicate registration.
func TestRegisterClientMetricsSharesOneSetPerRegisterer(t *testing.T) {
	reg := prometheus.NewRegistry()

	first, err := registerClientMetrics(reg)
	require.NoError(t, err)
	second, err := registerClientMetrics(reg)
	require.NoError(t, err)

	require.Same(t, first, second)
}

func TestSeparateStoreConnections(t *testing.T) {
	// The sample endpoint uses plaintext and a direct token, while the symbol
	// endpoint requires TLS and a token file. Both unary and streaming RPCs
	// must receive only their endpoint's credentials and headers.
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("symbol-token\n"), 0o600))
	reg := prometheus.NewRegistry()
	for _, tc := range []struct {
		name   string
		config FlagsGRPC
		opts   []grpc.ServerOption
		token  string
	}{
		{
			name:   "samples",
			config: FlagsGRPC{Insecure: true, BearerToken: "sample-token"},
			token:  "sample-token",
		},
		{
			name:   "symbols",
			config: FlagsGRPC{InsecureSkipVerify: true, BearerTokenFile: tokenFile},
			opts:   []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: tlsServer.TLS.Certificates}))},
			token:  "symbol-token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan metadata.MD, 2)
			opts := append(tc.opts,
				grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					md, _ := metadata.FromIncomingContext(ctx)
					received <- md
					return handler(ctx, req)
				}),
				grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
					md, _ := metadata.FromIncomingContext(stream.Context())
					received <- md
					return handler(srv, stream)
				}),
			)
			server := grpc.NewServer(opts...)
			t.Cleanup(server.Stop)
			healthServer := health.NewServer()
			healthServer.SetServingStatus(tc.name, healthpb.HealthCheckResponse_SERVING)
			healthpb.RegisterHealthServer(server, healthServer)
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			go func() { _ = server.Serve(lis) }()

			f := tc.config
			f.Address = lis.Addr().String()
			f.GRPCHeaders = map[string]string{"x-tenant": tc.name}
			f.GRPCStartupBackoffTime = time.Second
			f.GRPCConnectionTimeout = time.Second
			f.RPCUnaryTimeout = time.Second
			f.GRPCMaxCallRecvMsgSize = 1024
			f.GRPCMaxCallSendMsgSize = 1024
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var conn *grpc.ClientConn
			if tc.name == "symbols" {
				conn, err = f.NewGrpcClient(reg, noop.NewTracerProvider())
			} else {
				conn, err = f.WaitGrpcEndpoint(ctx, reg, noop.NewTracerProvider())
			}
			require.NoError(t, err)
			defer conn.Close()
			client := healthpb.NewHealthClient(conn)
			resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: tc.name})
			require.NoError(t, err)
			require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
			stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: tc.name})
			require.NoError(t, err)
			resp, err = stream.Recv()
			require.NoError(t, err)
			require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
			for range 2 {
				select {
				case md := <-received:
					require.Equal(t, []string{"Bearer " + tc.token}, md.Get("authorization"))
					require.Equal(t, []string{tc.name}, md.Get("x-tenant"))
				case <-ctx.Done():
					t.Fatal("did not receive RPC metadata")
				}
			}
		})
	}
}

func TestLazyConnectionRecovers(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := lis.Addr().String()
	require.NoError(t, lis.Close())
	f := FlagsGRPC{
		Address: address, Insecure: true, RPCUnaryTimeout: 100 * time.Millisecond,
		GRPCMaxCallRecvMsgSize: 1024, GRPCMaxCallSendMsgSize: 1024,
	}
	start := time.Now()
	conn, err := f.NewGrpcClient(prometheus.NewRegistry(), noop.NewTracerProvider())
	require.NoError(t, err)
	defer conn.Close()
	require.Less(t, time.Since(start), time.Second, "startup must not wait for the unavailable proxy")
	client := healthpb.NewHealthClient(conn)
	_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.Error(t, err, "unavailable endpoint must have a bounded RPC failure")
	startServer := func() *grpc.Server {
		listener, err := net.Listen("tcp", address)
		require.NoError(t, err)
		server := grpc.NewServer()
		healthpb.RegisterHealthServer(server, health.NewServer())
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		return server
	}
	check := func() bool {
		resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		return err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING
	}
	server := startServer()
	require.Eventually(t, check, 10*time.Second, 50*time.Millisecond)
	server.Stop()
	_, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.Error(t, err)
	startServer()
	require.Eventually(t, check, 10*time.Second, 50*time.Millisecond, "same client must recover after restart")
	require.NoError(t, conn.Close())
	require.Equal(t, connectivity.Shutdown, conn.GetState())
}
