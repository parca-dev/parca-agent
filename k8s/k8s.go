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
	"log"
	"os"
	"strings"

	"github.com/polarsignals/polarsignals-agent/containerutils"
	"github.com/polarsignals/polarsignals-agent/containerutils/containerd"
	"github.com/polarsignals/polarsignals-agent/containerutils/crio"
	"github.com/polarsignals/polarsignals-agent/containerutils/docker"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const KubeConfigEnv = "KUBECONFIG"

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	criClient     containerutils.CRIClient
}

func NewK8sClient(nodeName string) (*K8sClient, error) {
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
	criClient, err := newCRIClient(node)
	if err != nil {
		return nil, fmt.Errorf("create CRI client: %w", err)
	}

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		criClient:     criClient,
	}, nil
}

func (c *K8sClient) Clientset() kubernetes.Interface {
	return c.clientset
}

func newCRIClient(node *v1.Node) (containerutils.CRIClient, error) {
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
		return crio.NewCrioClient(crio.DEFAULT_SOCKET_PATH)
	default:
		return nil, fmt.Errorf("Unknown '%s' cri", criType)
	}
}

func (k *K8sClient) CloseCRI() {
	k.criClient.Close()
}

type ContainerDefinition struct {
	ContainerId   string
	CgroupPath    string
	CgroupId      uint64
	Mntns         uint64
	Namespace     string
	PodName       string
	ContainerName string
	Labels        map[string]string
	CgroupV1      string
	CgroupV2      string
	MountSources  []string
	Pid           int
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
			log.Printf("Skip pod %s/%s: cannot find pid: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}
		cgroupPathV1, cgroupPathV2, err := containerutils.GetCgroupPaths(pid)
		if err != nil {
			log.Printf("Skip pod %s/%s: cannot find cgroup path: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}
		cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)
		cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)
		mntns, err := containerutils.GetMntNs(pid)
		if err != nil {
			log.Printf("Skip pod %s/%s: cannot find mnt namespace: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}

		containerDef := ContainerDefinition{
			ContainerId:   s.ContainerID,
			CgroupPath:    cgroupPathV2WithMountpoint,
			CgroupId:      cgroupId,
			Mntns:         mntns,
			Namespace:     pod.GetNamespace(),
			PodName:       pod.GetName(),
			ContainerName: s.Name,
			Labels:        pod.ObjectMeta.Labels,
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
