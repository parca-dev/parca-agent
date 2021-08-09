// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/parca-dev/parca-agent/containerutils"
	"github.com/parca-dev/parca-agent/containerutils/containerd"
	"github.com/parca-dev/parca-agent/containerutils/crio"
	"github.com/parca-dev/parca-agent/containerutils/docker"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	profilestorepb "github.com/parca-dev/parca/proto/gen/go/profilestore"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const KubeConfigEnv = "KUBECONFIG"

type K8sClient struct {
	logger        log.Logger
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	criClient     containerutils.CRIClient
}

func NewK8sClient(logger log.Logger, nodeName string) (*K8sClient, error) {
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
	// TODO: when to close it?
	criClient, err := newCRIClient(logger, node)
	if err != nil {
		return nil, fmt.Errorf("create CRI client: %w", err)
	}

	return &K8sClient{
		logger:        logger,
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		criClient:     criClient,
	}, nil
}

func (c *K8sClient) Clientset() kubernetes.Interface {
	return c.clientset
}

func newCRIClient(logger log.Logger, node *v1.Node) (containerutils.CRIClient, error) {
	criVersion := node.Status.NodeInfo.ContainerRuntimeVersion
	list := strings.Split(criVersion, "://")
	if len(list) < 1 {
		return nil, fmt.Errorf("Impossible to get CRI type from %s", criVersion)
	}

	criType := list[0]

	switch criType {
	case "docker":
		return docker.NewDockerClient(docker.DEFAULT_SOCKET_PATH)
	case "containerd":
		return containerd.NewContainerdClient(containerd.DEFAULT_SOCKET_PATH)
	case "cri-o":
		return crio.NewCrioClient(logger, crio.DEFAULT_SOCKET_PATH)
	default:
		return nil, fmt.Errorf("Unknown '%s' cri", criType)
	}
}

func (k *K8sClient) CloseCRI() {
	k.criClient.Close()
}

type ContainerDefinition struct {
	NodeName      string
	ContainerId   string
	CgroupPath    string
	CgroupId      uint64
	Mntns         uint64
	Namespace     string
	PodName       string
	ContainerName string
	PodLabels     map[string]string
	CgroupV1      string
	CgroupV2      string
	MountSources  []string
	Pid           int
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
		Value: c.ContainerId,
	}}
}

func (c *ContainerDefinition) PerfEventCgroupPath() string {
	// This is so hacky I'm thoroughly ashamed of it, but cgroup setups are so
	// inconsistent that this is a "works most of the time" heuristic.
	parts := strings.Split(c.CgroupV1, "/")
	kubepodsFound := false
	keep := []string{}
	for _, part := range parts {
		if strings.HasPrefix(part, "kubepods") {
			kubepodsFound = true
		}
		if kubepodsFound {
			keep = append(keep, part)
		}
	}

	return "/sys/fs/cgroup/perf_event/" + strings.Join(keep, "/")
}

// PodToContainers return a list of the containers of a given Pod.
// Containers that are not running or don't have an ID are not considered.
func (k *K8sClient) PodToContainers(pod *v1.Pod) []ContainerDefinition {
	containers := []ContainerDefinition{}

	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID == "" {
			continue
		}
		if s.State.Running == nil {
			continue
		}

		pid, err := k.criClient.PidFromContainerId(s.ContainerID)
		if err != nil {
			level.Warn(k.logger).Log("msg", "skipping pod, cannot find pid", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}
		cgroupPathV1, cgroupPathV2, err := containerutils.GetCgroupPaths(pid)
		if err != nil {
			level.Warn(k.logger).Log("msg", "skipping pod, cannot find cgroup path", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}
		cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)
		cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)
		mntns, err := containerutils.GetMntNs(pid)
		if err != nil {
			level.Warn(k.logger).Log("msg", "skipping pod, cannot find mnt namespace", "namespace", pod.GetNamespace(), "pod", pod.GetName(), "err", err)
			continue
		}

		containerDef := ContainerDefinition{
			NodeName:      k.nodeName,
			ContainerId:   s.ContainerID,
			CgroupPath:    cgroupPathV2WithMountpoint,
			CgroupId:      cgroupId,
			Mntns:         mntns,
			Namespace:     pod.GetNamespace(),
			PodName:       pod.GetName(),
			ContainerName: s.Name,
			PodLabels:     pod.ObjectMeta.Labels,
			Pid:           pid,
			CgroupV1:      cgroupPathV1,
			CgroupV2:      cgroupPathV2,
		}
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *K8sClient) ListContainers() (arr []ContainerDefinition, err error) {
	// List pods
	pods, err := k.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		containers := k.PodToContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}
