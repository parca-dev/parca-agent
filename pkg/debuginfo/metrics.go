package debuginfo

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metrics struct {
	uploadSuccess prometheus.Counter
	uploadFailure prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	return &metrics{
		uploadSuccess: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "parca_agent_debuginfo_upload_total",
				Help: "Number of debuginfo successfully uploaded",
			},
		),
		uploadFailure: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name: "parca_agent_debuginfo_upload_failed_total",
				Help: "Number of failed debuginfo uploads",
			},
		),
	}
}
