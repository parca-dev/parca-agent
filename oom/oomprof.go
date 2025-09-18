package oom

import (
	"bytes"
	"context"
	"fmt"

	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	profilestorepb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/profilestore/v1alpha1"

	"github.com/parca-dev/oomprof/oomprof"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func StartOOMProf(ctx context.Context, grpcConn *grpc.ClientConn, verbose bool, nodeName string,
	externalLabels map[string]string, reportAllocs bool) (state *oomprof.State, err error) {
	profChan := make(chan oomprof.ProfileData, 10)
	cfg := oomprof.Config{
		ScanInterval: 0,
		MemLimit:     32 * 1024 * 1024, // 32MB
		LogTracePipe: false,            // only have oom prof or parca-agent read trace pipe, not both
		Verbose:      verbose,
		Symbolize:    false,
		ReportAlloc:  reportAllocs, // whether to report allocs in memory profiles
	}
	state, err = oomprof.Setup(ctx, &cfg, profChan)
	if err != nil {
		return nil, err
	}
	client := profilestoregrpc.NewProfileStoreServiceClient(grpcConn)
	go handleOOMProfData(ctx, profChan, client, nodeName, externalLabels)
	return state, nil
}

// handleOOMProfData handles ProfileData from oomprof and sends it to the ProfileStoreService
func handleOOMProfData(ctx context.Context, profileCh <-chan oomprof.ProfileData, client profilestoregrpc.ProfileStoreServiceClient, nodeName string, externalLabels map[string]string) {
	for {
		select {
		case <-ctx.Done():
			log.Info("OOMProf profile handler shutting down")
			return
		case profileData := <-profileCh:
			log.Infof("Received OOMProf profile for PID %d, command %s",
				profileData.PID, profileData.Command)

			// Convert the profile to protobuf format and send directly to Parca
			err := sendOOMProfile(ctx, client, profileData, nodeName, externalLabels)
			if err != nil {
				log.Errorf("Failed to send OOM profile: %v", err)
			}
		}
	}
}

// sendOOMProfileToParca sends an OOM profile directly to Parca using the gRPC client
func sendOOMProfile(ctx context.Context, client profilestoregrpc.ProfileStoreServiceClient, profileData oomprof.ProfileData, nodeName string, externalLabels map[string]string) error {
	// Convert profile to raw bytes
	var buf bytes.Buffer
	err := profileData.Profile.Write(&buf)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	// Build labels for the profile
	labelSet := make([]*profilestorepb.Label, 0, len(externalLabels)+3)

	// Add external labels
	for k, v := range externalLabels {
		labelSet = append(labelSet, &profilestorepb.Label{
			Name:  k,
			Value: v,
		})
	}

	// Add OOM-specific labels
	// FIXME: subject these to relabeling?
	labelSet = append(labelSet, &profilestorepb.Label{
		Name:  "job",
		Value: "oomprof",
	})
	labelSet = append(labelSet, &profilestorepb.Label{
		Name:  "node",
		Value: nodeName,
	})
	labelSet = append(labelSet, &profilestorepb.Label{
		Name:  "__name__",
		Value: "memory",
	})
	labelSet = append(labelSet, &profilestorepb.Label{
		Name:  "pid",
		Value: fmt.Sprintf("%d", profileData.PID),
	})
	labelSet = append(labelSet, &profilestorepb.Label{
		Name:  "comm",
		Value: profileData.Command,
	})

	// Create the WriteRaw request
	req := &profilestorepb.WriteRawRequest{
		Series: []*profilestorepb.RawProfileSeries{
			{
				Labels: &profilestorepb.LabelSet{
					Labels: labelSet,
				},
				Samples: []*profilestorepb.RawSample{
					{
						RawProfile: buf.Bytes(),
					},
				},
			},
		},
	}

	// Send the profile
	_, err = client.WriteRaw(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to write raw profile: %w", err)
	}

	log.Infof("Successfully sent OOM profile for PID %d, command %s, size: %d bytes to Parca",
		profileData.PID, profileData.Command, len(buf.Bytes()))

	return nil
}
