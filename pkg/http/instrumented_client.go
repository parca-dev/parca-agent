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

package http

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	inFlightGauge            prometheus.Gauge
	requestTotalCount        *prometheus.CounterVec
	dnsLatencyHistogram      *prometheus.HistogramVec
	tlsLatencyHistogram      *prometheus.HistogramVec
	requestDurationHistogram *prometheus.HistogramVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		inFlightGauge: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "http_client_in_flight_requests",
			Help: "A gauge of in-flight requests.",
		}),
		requestTotalCount: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_client_request_total",
			Help: "Total http client request by code and method.",
		}, []string{"code", "method"}),
		dnsLatencyHistogram: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:                        "http_client_dns_duration_seconds",
				Help:                        "Track dns latency histogram.",
				NativeHistogramBucketFactor: 1.1,
			},
			[]string{"event"},
		),
		tlsLatencyHistogram: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:                        "http_client_tls_duration_seconds",
				Help:                        "Track TLS latency histogram.",
				NativeHistogramBucketFactor: 1.1,
			},
			[]string{"event"},
		),
		requestDurationHistogram: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:                        "http_client_request_duration_seconds",
				Help:                        "A histogram of request latencies.",
				NativeHistogramBucketFactor: 1.1,
			},
			[]string{"code", "method"},
		),
	}
	return m
}

func instrumentedRoundTripper(tripper http.RoundTripper, m *metrics) http.RoundTripper {
	if m == nil {
		return tripper
	}

	trace := &promhttp.InstrumentTrace{
		DNSStart: func(t float64) {
			m.dnsLatencyHistogram.WithLabelValues("dns_start").Observe(t)
		},
		DNSDone: func(t float64) {
			m.dnsLatencyHistogram.WithLabelValues("dns_done").Observe(t)
		},
		TLSHandshakeStart: func(t float64) {
			m.tlsLatencyHistogram.WithLabelValues("tls_handshake_start").Observe(t)
		},
		TLSHandshakeDone: func(t float64) {
			m.tlsLatencyHistogram.WithLabelValues("tls_handshake_done").Observe(t)
		},
	}

	return promhttp.InstrumentRoundTripperInFlight(
		m.inFlightGauge,
		promhttp.InstrumentRoundTripperCounter(
			m.requestTotalCount,
			promhttp.InstrumentRoundTripperTrace(
				trace,
				promhttp.InstrumentRoundTripperDuration(
					m.requestDurationHistogram,
					tripper,
				),
			),
		),
	)
}

func NewClient(reg prometheus.Registerer, tripper ...http.RoundTripper) *http.Client {
	if tripper != nil {
		return &http.Client{
			Transport: instrumentedRoundTripper(tripper[0], newMetrics(reg)),
		}
	}
	return &http.Client{
		Transport: instrumentedRoundTripper(http.DefaultTransport, newMetrics(reg)),
	}
}
