package arrowmetrics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type perDeviceState struct {
	d             nvml.Device
	lastTimestamp uint64
}

type producer struct {
	devices []perDeviceState
}

type byTs []nvml.Sample

func (a byTs) Len() int           { return len(a) }
func (a byTs) Less(i, j int) bool { return a[i].TimeStamp < a[j].TimeStamp }
func (a byTs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func NewNvidiaProducer() (*producer, error) {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("Failed to initialize NVML library: %v", nvml.ErrorString(ret))
	}
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("Failed to get count of Nvidia devices: %v", nvml.ErrorString(ret))
	}
	devices := make([]perDeviceState, count)
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("Failed to get handle for Nvidia device %d: %v", i, nvml.ErrorString(ret))
		}
		devices[i] = perDeviceState{
			d:             device,
			lastTimestamp: 0,
		}
	}
	return &producer{
		devices: devices,
	}, nil
}

func (p *producer) Produce(ms pmetric.MetricSlice) error {
	for i, pds := range p.devices {
		uuid, ret := pds.d.GetUUID()
		if ret != nvml.SUCCESS {
			log.Errorf("Failed to get device UUID at index %d: %v", i, nvml.ErrorString(ret))
			continue
		}
		log.Debugf("Collecting metrics for device %s at index %d", uuid, i)

		m := ms.AppendEmpty()
		g := m.SetEmptyGauge()

		valueType, utilSamps, ret := pds.d.GetSamples(nvml.GPU_UTILIZATION_SAMPLES, pds.lastTimestamp)
		if ret != nvml.SUCCESS {
			log.Errorf("Failed to get GPU utilization for device %s at index %d", uuid, i)
			continue
		}
		var setVal func(pmetric.NumberDataPoint, [8]byte)
		switch valueType {
		case nvml.VALUE_TYPE_DOUBLE:
			setVal = func(dp pmetric.NumberDataPoint, val [8]byte) {
				var value float64
				// TODO - test this on a big-endian machine
				err := binary.Read(bytes.NewReader(val[:]), binary.NativeEndian, &value)
				if err != nil {
					// justification for panic: this can never happen unless we've made
					// a programming error.
					panic(err)
				}
				dp.SetDoubleValue(value)
			}
		case nvml.VALUE_TYPE_UNSIGNED_INT, nvml.VALUE_TYPE_UNSIGNED_LONG, nvml.VALUE_TYPE_UNSIGNED_LONG_LONG, nvml.VALUE_TYPE_SIGNED_LONG_LONG, nvml.VALUE_TYPE_SIGNED_INT, nvml.VALUE_TYPE_COUNT:
			setVal = func(dp pmetric.NumberDataPoint, val [8]byte) {
				var value int64
				// TODO - test this on a big-endian machine
				err := binary.Read(bytes.NewReader(val[:]), binary.NativeEndian, &value)
				if err != nil {
					// justification for panic: this can never happen unless we've made
					// a programming error.
					panic(err)
				}
				dp.SetIntValue(value)
			}
		default:
			log.Errorf("Unknown data type in GPU metrics: %d", valueType)
			continue
		}

		sort.Sort(byTs(utilSamps))

		for _, samp := range utilSamps {
			pds.lastTimestamp = max(pds.lastTimestamp, samp.TimeStamp)

			dp := g.DataPoints().AppendEmpty()
			setVal(dp, samp.SampleValue)

			// samp.TimeStamp is micros since epoch; pcommon.Timestamp expects
			// nanos since epoch
			dp.SetTimestamp(pcommon.Timestamp(samp.TimeStamp * 1000))
			dp.Attributes().PutStr("UUID", uuid)
			dp.Attributes().PutInt("index", int64(i))
		}

	}
	return nil
}
