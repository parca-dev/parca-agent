package arrowmetrics

import (
	"math/rand/v2"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/google/uuid"
)

type mock_producer struct {
	deviceUuids []string
	lastTime    time.Time
}

// nDevices - number of devices. samplesFromTime - samples will
// begin starting at this time (e.g. set to sometime in the past
// to report old data with the first batch)
func NewNvidiaMockProducer(nDevices int, samplesFromTime time.Time) Producer {
	deviceUuids := make([]string, 0, nDevices)
	for _ = range nDevices {
		deviceUuids = append(deviceUuids, uuid.New().String())
	}

	return &mock_producer{
		deviceUuids: deviceUuids,
		lastTime:    samplesFromTime,
	}
}

const PERIOD = time.Second / 6

func (p *mock_producer) Produce(ms pmetric.MetricSlice) error {
	for i, uuid := range p.deviceUuids {
		log.Debugf("Collecting metrics for device %s at index %d", uuid, i)

		m := ms.AppendEmpty()
		g := m.SetEmptyGauge()

		now := time.Now()
		

		for i, uuid := range p.deviceUuids {
			lastTimeRounded := p.lastTime.Truncate(PERIOD).Add(PERIOD)

			for lastTimeRounded.Before(now) {
				dp := g.DataPoints().AppendEmpty()
				dp.SetIntValue(int64(rand.IntN(100)))
				dp.SetTimestamp(pcommon.NewTimestampFromTime(lastTimeRounded))
				lastTimeRounded = lastTimeRounded.Add(PERIOD)
				dp.Attributes().PutStr("UUID", uuid)
				dp.Attributes().PutInt("index", int64(i))
			}
		}
		p.lastTime = now
	}
	return nil
}
