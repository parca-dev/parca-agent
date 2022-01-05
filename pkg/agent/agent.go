package agent

import (
	"context"

	"github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"
	"google.golang.org/grpc"
)

const CgroupPathLabelName = model.LabelName("__cgroup_path__")

// TODO(kakkoyun): Remove?
type Record struct {
	Labels  []*profilestorepb.Label
	Profile *profile.Profile
}

type NoopProfileStoreClient struct{}

func NewNoopProfileStoreClient() profilestorepb.ProfileStoreServiceClient {
	return &NoopProfileStoreClient{}
}

func (c *NoopProfileStoreClient) WriteRaw(ctx context.Context, in *profilestorepb.WriteRawRequest, opts ...grpc.CallOption) (*profilestorepb.WriteRawResponse, error) {
	return &profilestorepb.WriteRawResponse{}, nil
}
