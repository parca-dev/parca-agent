package agent

import (
	"context"

	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"google.golang.org/grpc"
)

type Batcher struct {
	series      []*profilestorepb.RawProfileSeries
	writeClient profilestorepb.ProfileStoreServiceClient
	logger      log.Logger

	mtx                *sync.RWMutex
	lastProfileTakenAt time.Time
	lastError          error
}

func NewBatcher(wc profilestorepb.ProfileStoreServiceClient) *Batcher {
	return &Batcher{
		series:      []*profilestorepb.RawProfileSeries{},
		writeClient: wc,
		mtx:         &sync.RWMutex{},
	}
}

func (b *Batcher) loopReport(lastProfileTakenAt time.Time, lastError error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.lastProfileTakenAt = lastProfileTakenAt
	b.lastError = lastError
}

func (b *Batcher) Run(ctx context.Context) error {
	// TODO(Sylfrena): Make ticker duration configurable
	const tickerDuration = 10 * time.Second

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		err := b.batchLoop(ctx)
		b.series = []*profilestorepb.RawProfileSeries{}

		b.loopReport(time.Now(), err)
	}
}

func (b *Batcher) batchLoop(ctx context.Context) error {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	_, err := b.writeClient.WriteRaw(ctx,
		&profilestorepb.WriteRawRequest{Series: b.series})

	if err != nil {
		level.Error(b.logger).Log("msg", "Writeclient failed to send profiles", "err", err)
		return err
	}

	return nil
}

func isEqualLabel(a *profilestorepb.LabelSet, b *profilestorepb.LabelSet) bool {
	ret := true

	if len(a.Labels) == len(b.Labels) {
		for i := range a.Labels {
			if (a.Labels[i].Name != b.Labels[i].Name) || (a.Labels[i].Value != b.Labels[i].Value) {
				ret = false
			}
		}
	} else {
		ret = false
	}

	return ret
}

func ifExists(arr []*profilestorepb.RawProfileSeries, p *profilestorepb.RawProfileSeries) (bool, int) {
	res := false

	for i, val := range arr {
		if isEqualLabel(val.Labels, p.Labels) {
			return true, i
		}
	}
	return res, -1
}

func (b *Batcher) WriteRaw(ctx context.Context, r *profilestorepb.WriteRawRequest, opts ...grpc.CallOption) (*profilestorepb.WriteRawResponse, error) {

	b.mtx.Lock()
	defer b.mtx.Unlock()

	for _, profileSeries := range r.Series {
		ok, j := ifExists(b.series, profileSeries)

		if ok {
			b.series[j].Samples = append(b.series[j].Samples, profileSeries.Samples...)
		} else {
			b.series = append(b.series, &profilestorepb.RawProfileSeries{
				Labels:  profileSeries.Labels,
				Samples: profileSeries.Samples,
			})
		}

	}

	return &profilestorepb.WriteRawResponse{}, nil

}
