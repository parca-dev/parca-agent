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

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
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

func Conn(reg prometheus.Registerer, tp trace.TracerProvider, address string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	// Register the vtproto codec.
	encoding.RegisterCodec(vtprotoCodec{})

	metrics := grpc_prometheus.NewClientMetrics()
	metrics.EnableClientHandlingTimeHistogram()
	reg.MustRegister(metrics)

	propagators := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

	opts = append(opts,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(parcadebuginfo.MaxMsgSize),
			grpc.MaxCallRecvMsgSize(parcadebuginfo.MaxMsgSize),
		),
		// metrics.
		grpc.WithUnaryInterceptor(metrics.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(metrics.StreamClientInterceptor()),
		// tracing.
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor(
			otelgrpc.WithTracerProvider(tp),
			otelgrpc.WithPropagators(propagators),
		)),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor(
			otelgrpc.WithTracerProvider(tp),
			otelgrpc.WithPropagators(propagators),
		)),
	)

	return grpc.Dial(address, opts...)
}
