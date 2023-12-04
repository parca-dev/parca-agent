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

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/parca-dev/parca-agent/pkg/cgroup"
	"github.com/parca-dev/parca-agent/pkg/discovery/kubernetes/containerruntimes"
	"github.com/parca-dev/parca-agent/pkg/discovery/kubernetes/containerruntimes/containerd"
	"github.com/parca-dev/parca-agent/pkg/discovery/kubernetes/containerruntimes/crio"
	"github.com/parca-dev/parca-agent/pkg/discovery/kubernetes/containerruntimes/docker"
	"github.com/parca-dev/parca-agent/pkg/namespace"
)

const KubeConfigEnv = "KUBECONFIG"

type Client struct {
	logger        log.Logger
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	criClient     containerruntimes.CRIClient
}

func NewKubernetesClient(logger log.Logger, nodeName, socketPath string) (*Client, error) {
	var (
		config *rest.Config
		err    error
	)
	kubeconfigFile := os.Getenv(KubeConfigEnv)
	if kubeconfigFile != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigFile)
		if err != nil {
			return nil, fmt.Errorf("create config from %s: %w", kubeconfigFile, err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("create in-cluster config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get node %v: %w", nodeName, err)
	}

	// get a CRI client to talk to the CRI handling pods in this node
	criClient, err := newCRIClient(logger, node, socketPath)
	if err != nil {
		return nil, fmt.Errorf("create CRI client: %w", err)
	}

	return &Client{
		logger:        logger,
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		criClient:     criClient,
	}, nil
}

func (c *Client) Clientset() kubernetes.Interface {
	return c.clientset
}

func newCRIClient(logger log.Logger, node *v1.Node, socketPath string) (containerruntimes.CRIClient, error) {
	criVersion := node.Status.NodeInfo.ContainerRuntimeVersion
	list := strings.Split(criVersion, "://")
	if len(list) < 1 {
		return nil, fmt.Errorf("impossible to get CRI type from %s", criVersion)
	}

	criType := list[0]

	switch criType {
	case "docker":
		if socketPath == "" {
			level.Debug(logger).Log("msg", "no docker socket path provided, using default", "path", docker.DefaultSocketPath)
			socketPath = docker.DefaultSocketPath
		}
		if _, err := os.Stat(socketPath); err != nil {
			return nil, fmt.Errorf("docker socket path is not reachable: %w", err)
		}
		return docker.NewDockerClient(socketPath)
	case "containerd":
		if socketPath == "" {
			if _, err := os.Stat(containerd.DefaultSocketPath); err == nil {
				level.Debug(logger).Log("msg", "no containerd socket path provided, using default", "path", containerd.DefaultSocketPath)
				socketPath = containerd.DefaultSocketPath
			}
			if _, err := os.Stat(containerd.DefaultK3SSocketPath); err == nil {
				if socketPath != "" {
					level.Warn(logger).Log("msg", "multiple containerd socket paths found, using k3s", "path", containerd.DefaultK3SSocketPath)
				} else {
					level.Debug(logger).Log("msg", "no k3s containerd socket path provided, using default", "path", containerd.DefaultK3SSocketPath)
				}
				socketPath = containerd.DefaultK3SSocketPath
			}
		}
		if _, err := os.Stat(socketPath); err != nil {
			return nil, fmt.Errorf("containerd socket path is not reachable: %w", err)
		}
		return containerd.NewContainerdClient(socketPath)
	case "cri-o":
		if socketPath == "" {
			level.Debug(logger).Log("msg", "no cri-o socket path provided, using default", "path", crio.DefaultSocketPath)
			socketPath = crio.DefaultSocketPath
		}
		if _, err := os.Stat(socketPath); err != nil {
			return nil, fmt.Errorf("CRI-o socket path is not reachable: %w", err)
		}
		return crio.NewCrioClient(logger, socketPath)
	default:
		return nil, fmt.Errorf("unknown '%s' cri", criType)
	}
}

func (c *Client) Close() error {
	return c.criClient.Close()
}

type ContainerDefinition struct {
	NodeName      string
	ContainerID   string
	CgroupPath    string
	CgroupID      uint64
	Mntns         uint64
	Namespace     string
	PodName       string
	ContainerName string
	PodLabels     map[string]string
	CgroupV1      string
	CgroupV2      string
	MountSources  []string
	PID           int
}

func (c *ContainerDefinition) Labels() []*profilestorepb.Label {
	return []*profilestorepb.Label{{
		Name:  "node",
		Value: c.NodeName,
	}, {
		Name:  "namespace",
		Value: c.Namespace,
	}, {
		Name:  "pod",
		Value: c.PodName,
	}, {
		Name:  "container",
		Value: c.ContainerName,
	}, {
		Name:  "containerid",
		Value: c.ContainerID,
	}}
}

// PodToContainers return a list of the containers of a given Pod.
// Containers that are not running or don't have an ID are not considered.
func (c *Client) PodToContainers(pod *v1.Pod) []*ContainerDefinition {
	containers := []*ContainerDefinition{}

	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID == "" {
			continue
		}
		if s.State.Running == nil {
			continue
		}

		pid, err := c.criClient.PIDFromContainerID(s.ContainerID)
		if err != nil {
			level.Debug(c.logger).Log("msg", "skipping pod, cannot find pid", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}
		cgroupPathV1, cgroupPathV2, err := cgroup.Paths(pid)
		if err != nil {
			level.Debug(c.logger).Log("msg", "skipping pod, cannot find cgroup path", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}
		cgroupPathV2WithMountpoint, _ := cgroup.PathV2AddMountpoint(cgroupPathV2)
		cgroupID, _ := cgroup.ID(cgroupPathV2WithMountpoint)
		mntns, err := namespace.MountNamespaceInode(pid) // linux namespace.
		if err != nil {
			level.Debug(c.logger).Log("msg", "skipping pod, cannot find mnt namespace", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}

		containerDef := &ContainerDefinition{
			NodeName:      c.nodeName,
			ContainerID:   s.ContainerID,
			CgroupPath:    cgroupPathV2WithMountpoint,
			CgroupID:      cgroupID,
			Mntns:         mntns,
			Namespace:     pod.GetNamespace(), // kubernetes namespace.
			PodName:       pod.GetName(),
			ContainerName: s.Name,
			PodLabels:     pod.ObjectMeta.Labels,
			PID:           pid,
			CgroupV1:      cgroupPathV1,
			CgroupV2:      cgroupPathV2,
		}
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (c *Client) ListContainers() ([]*ContainerDefinition, error) {
	// List pods
	pods, err := c.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: c.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	var arr []*ContainerDefinition
	for _, p := range pods.Items {
		pod := p
		containers := c.PodToContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}
