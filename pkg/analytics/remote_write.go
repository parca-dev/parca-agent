// Copyright 2023-2024 The Parca Authors
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

package analytics

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"

	prometheus "buf.build/gen/go/prometheus/prometheus/protocolbuffers/go"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/otel/trace"
)

const (
	maxErrMsgLen = 1024
	defaultURL   = "https://analytics.parca.dev/api/v1/write"
)

type Client struct {
	tp     trace.TracerProvider
	tracer trace.Tracer

	client    *http.Client
	urlString string
	userAgent string
	timeout   time.Duration

	buf  []byte
	pBuf *proto.Buffer
}

func NewClient(
	tp trace.TracerProvider,
	client *http.Client,
	userAgent string,
	timeout time.Duration,
) *Client {
	analyticsURL := defaultURL
	customAnalyticsURL := os.Getenv("ANALYTICS_URL")
	if customAnalyticsURL != "" {
		analyticsURL = customAnalyticsURL
	}

	return &Client{
		tp:     tp,
		tracer: tp.Tracer("parca/analytics"),

		client: client,

		urlString: analyticsURL,
		userAgent: userAgent,
		timeout:   timeout,

		pBuf: proto.NewBuffer(nil),
		buf:  make([]byte, 1024),
	}
}

func (c *Client) Send(ctx context.Context, wreq *prometheus.WriteRequest) error {
	ctx, span := c.tracer.Start(ctx, "Send", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	c.pBuf.Reset()
	err := c.pBuf.Marshal(wreq)
	if err != nil {
		return err
	}

	// snappy uses len() to see if it needs to allocate a new slice. Make the
	// buffer as long as possible.
	if c.buf != nil {
		c.buf = c.buf[0:cap(c.buf)]
	}
	c.buf = snappy.Encode(c.buf, c.pBuf.Bytes())

	return c.sendReq(ctx, c.buf)
}

// Store sends a batch of samples to the HTTP endpoint, the request is the proto marshaled
// and encoded bytes from codec.go.
func (c *Client) sendReq(ctx context.Context, req []byte) error {
	ctx, span := c.tracer.Start(ctx, "sendReq", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	httpReq, err := http.NewRequest(http.MethodPost, c.urlString, bytes.NewReader(req))
	if err != nil {
		// Errors from NewRequest are from unparsable URLs, so are not
		// recoverable.
		return err
	}

	httpReq.Header.Add("Content-Encoding", "snappy")
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("User-Agent", c.userAgent)
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, otelhttptrace.NewClientTrace(ctx, otelhttptrace.WithTracerProvider(c.tp)))

	httpResp, err := c.client.Do(httpReq.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, httpResp.Body) //nolint:errcheck
		httpResp.Body.Close()
	}()

	if httpResp.StatusCode/100 != 2 {
		scanner := bufio.NewScanner(io.LimitReader(httpResp.Body, maxErrMsgLen))
		line := ""
		if scanner.Scan() {
			line = scanner.Text()
		}
		err = fmt.Errorf("server returned HTTP status %s: %s", httpResp.Status, line)
	}
	return err
}
