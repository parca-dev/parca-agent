package metadata

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	internalapi "k8s.io/cri-api/pkg/apis"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
)

const criTimeout = 2 * time.Second // same as crictl

// criClient wraps the CRI RuntimeService for pod metadata retrieval
type criClient struct {
	service internalapi.RuntimeService
}

// newCRIClient creates a new CRI client using the official k8s.io/cri-client
func newCRIClient(socketPath string) (*criClient, error) {
	if socketPath == "" {
		socketPath = findCRISocket()
		if socketPath == "" {
			return nil, fmt.Errorf("no CRI socket found")
		}
	}

	// Check if socket exists
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("CRI socket not accessible: %w", err)
	}

	log.Infof("Connecting to CRI socket: %s", socketPath)

	// Use the official CRI client library (same as crictl)
	service, err := remote.NewRemoteRuntimeService(socketPath, criTimeout, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRI client: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), criTimeout)
	defer cancel()

	_, err = service.Version(ctx, "v1")
	if err != nil {
		return nil, fmt.Errorf("failed to verify CRI connection: %w", err)
	}

	log.Info("Successfully connected to CRI runtime")

	return &criClient{service: service}, nil
}

// findCRISocket tries to find a CRI socket in common locations
func findCRISocket() string {
	commonPaths := []string{
		"/run/containerd/containerd.sock",     // containerd
		"/var/run/containerd/containerd.sock", // containerd (alternative)
		"/var/run/crio/crio.sock",             // CRI-O
		"/run/crio/crio.sock",                 // CRI-O (alternative)
		"/run/cri-dockerd.sock",               // cri-dockerd
		"/var/run/cri-dockerd.sock",           // cri-dockerd (alternative)
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// listPodsViaCRI retrieves all pods on the node via CRI
func (c *criClient) listPodsViaCRI(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	// List all pod sandboxes (no need for detailed status calls)
	sandboxes, err := c.service.ListPodSandbox(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list pod sandboxes: %w", err)
	}

	// List all containers once
	containers, err := c.service.ListContainers(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Build map of sandbox ID -> containers
	sandboxContainers := make(map[string][]*runtimeapi.Container)
	for _, container := range containers {
		sandboxID := container.PodSandboxId
		sandboxContainers[sandboxID] = append(sandboxContainers[sandboxID], container)
	}

	// Convert sandboxes to pods
	pods := make([]corev1.Pod, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		pod := convertSandboxToPod(sandbox, nodeName, sandboxContainers[sandbox.Id])
		pods = append(pods, *pod)
	}

	log.Debugf("Listed %d pods via CRI", len(pods))
	return pods, nil
}

// convertSandboxToPod converts CRI PodSandbox to corev1.Pod
func convertSandboxToPod(sandbox *runtimeapi.PodSandbox, nodeName string, containers []*runtimeapi.Container) *corev1.Pod {
	pod := &corev1.Pod{}

	// Basic metadata from sandbox
	if sandbox.Metadata != nil {
		pod.Name = sandbox.Metadata.Name
		pod.Namespace = sandbox.Metadata.Namespace
		pod.UID = types.UID(sandbox.Metadata.Uid)
	}

	// Labels and annotations
	pod.Labels = sandbox.Labels
	pod.Annotations = sandbox.Annotations

	// Node info
	pod.Spec.NodeName = nodeName
	if hostname, ok := sandbox.Labels["io.kubernetes.pod.nodename"]; ok && hostname != "" {
		pod.Spec.NodeName = hostname
	}

	// Convert containers to container statuses
	pod.Status.ContainerStatuses = make([]corev1.ContainerStatus, 0, len(containers))
	for _, container := range containers {
		cs := corev1.ContainerStatus{
			ContainerID: container.Id,
			Image:       container.Image.Image,
			ImageID:     container.ImageRef,
		}
		if container.Metadata != nil {
			cs.Name = container.Metadata.Name
		}
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, cs)
	}

	return pod
}
