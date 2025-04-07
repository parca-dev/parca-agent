/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// containermetadata provides functionality for retrieving the kubernetes pod and container
// metadata or the docker container metadata for a particular PID.
// For kubernetes it uses the shared informer from the k8s client-go API
// (https://github.com/kubernetes/client-go/blob/master/tools/cache/shared_informer.go). Through
// the shared informer we are notified of changes in the state of pods in the Kubernetes
// cluster and can add the pod container metadata to the cache.
// As a backup to the kubernetes shared informer and to find the docker container metadata for
// each pid received (if it is not already in the container caches), it will retrieve the container
// id from the /proc/PID/cgroup and retrieve the metadata for the containerID.
package metadata

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/util/strutil"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

const (
	dockerHost            = "DOCKER_HOST"
	kubernetesServiceHost = "KUBERNETES_SERVICE_HOST"

	// There is a limit of 110 Pods per node (but can be overridden)
	kubernetesDefaultPodsPerNode = 110
	// From experience, usually there are no more than 10 containers (including sidecar
	// containers) in a single Pod.
	kubernetesContainersPerPod = 10
	// We're setting the default cache size according to Kubernetes best practices,
	// in order to reduce the number of Kubernetes API calls at runtime.
	containerMetadataCacheSize = kubernetesDefaultPodsPerNode * kubernetesContainersPerPod

	// containerIDCacheSize defines the size of the cache which maps a process to container ID
	// information. Its perfect size would be the number of processes running on the system.
	containerIDCacheSize = 1024
	// containerIDCacheTimeout decides how long we keep entries in the PID -> container ID cache.
	// The timeout exists to avoid collisions in case of PID reuse.
	containerIDCacheTimeout = 1 * time.Minute

	// deferredTimeout is the timeout to prevent busy loops.
	deferredTimeout = 1 * time.Minute

	// deferredLRUSize defines the size of LRUs deferring look ups.
	deferredLRUSize = 8192
)

var (
	kubePattern       = regexp.MustCompile(`\d+:.*:/.*/*kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	dockerKubePattern = regexp.MustCompile(`\d+:.*:/.*/*docker/pod[^/]+/([0-9a-f]{64})`)
	altKubePattern    = regexp.MustCompile(
		`\d+:.*:/.*/*kubepods.*?/[^/]+/docker-([0-9a-f]{64})`)
	// The systemd cgroupDriver needs a different regex pattern:
	systemdKubePattern    = regexp.MustCompile(`\d+:.*:/.*/*kubepods-.*([0-9a-f]{64})`)
	dockerPattern         = regexp.MustCompile(`\d+:.*:/.*?/*docker[-|/]([0-9a-f]{64})`)
	dockerBuildkitPattern = regexp.MustCompile(`\d+:.*:/.*/*docker/buildkit/([0-9a-z]+)`)
	lxcPattern            = regexp.MustCompile(`\d+::/lxc\.(monitor|payload)\.([a-zA-Z]+)/`)
	containerdPattern     = regexp.MustCompile(`\d+:.+:/([a-zA-Z0-9_-]+)/+([a-zA-Z0-9_-]+)`)

	containerIDPattern = regexp.MustCompile(`.+://([0-9a-f]{64})`)

	cgroupTemplate = "/proc/%d/cgroup"

	ErrDeferred = errors.New("lookup deferred due to previous failure")
)

// MetadataProvider implementations support adding metadata to a labels.Builder.
type MetadataProvider interface {
	// AddMetadata adds metadata to the provided labels.Builder for the given PID.
	// It returns whether the metadata can be safely cached.
	AddMetadata(pid libpf.PID, lb *labels.Builder) bool
}

// containerMetadataProvider does the retrieval of container metadata for a particular pid.
type containerMetadataProvider struct {
	// Counters to keep track how often external APIs are called.
	kubernetesClientQueryCount atomic.Uint64
	dockerClientQueryCount     atomic.Uint64
	containerdClientQueryCount atomic.Uint64

	// the kubernetes node name used to retrieve the pod information.
	nodeName string

	// containerIDCache stores per process container ID information.
	containerIDCache *lru.SyncedLRU[libpf.PID, containerIDEntry]

	// containerMetadataCache provides a cache to quickly retrieve the pod metadata for a
	// particular container id. It caches the pod name and container name metadata. Locked LRU.
	containerMetadataCache *lru.SyncedLRU[string, model.LabelSet]

	kubeClientSet kubernetes.Interface
	dockerClient  *client.Client

	containerdClient *containerd.Client

	// deferredPID prevents busy loops for PIDs where the cgroup extraction fails.
	deferredPID *lru.SyncedLRU[libpf.PID, libpf.Void]

	kubernetesNode *corev1.Node
}

// hashString is a helper function for containerMetadataCache
// xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// containerEnvironment specifies a used container technology.
type containerEnvironment uint16

// List of known container technologies we can handle.
const (
	envUndefined  containerEnvironment = 0
	envKubernetes containerEnvironment = 1 << iota
	envDocker
	envLxc
	envContainerd
	envDockerBuildkit
)

// isContainerEnvironment tests if env is target.
func isContainerEnvironment(env, target containerEnvironment) bool {
	return target&env == target
}

// containerIDEntry stores the information we fetch from the cgroup information of the process.
type containerIDEntry struct {
	containerID string
	env         containerEnvironment
}

// NewContainerMetadataProvider creates a new container metadata provider.
func NewContainerMetadataProvider(ctx context.Context, nodeName string) (MetadataProvider, error) {
	containerIDCache, err := lru.NewSynced[libpf.PID, containerIDEntry](
		containerIDCacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create container id cache: %v", err)
	}
	containerIDCache.SetLifetime(containerIDCacheTimeout)

	p := &containerMetadataProvider{
		containerIDCache: containerIDCache,
		dockerClient:     getDockerClient(),
		containerdClient: getContainerdClient(),
		nodeName:         nodeName,
	}

	p.deferredPID, err = lru.NewSynced[libpf.PID, libpf.Void](deferredLRUSize,
		libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	p.deferredPID.SetLifetime(deferredTimeout)

	if os.Getenv(kubernetesServiceHost) != "" {
		err = createKubernetesClient(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client %v", err)
		}
	} else {
		log.Infof("Environment variable %s not set", kubernetesServiceHost)
		p.containerMetadataCache, err = lru.NewSynced[string, model.LabelSet](
			containerMetadataCacheSize, hashString)
		if err != nil {
			return nil, fmt.Errorf("unable to create container metadata cache: %v", err)
		}
	}

	log.Debugf("Container metadata handler: %v", p)

	return p, nil
}

func createKubernetesClient(ctx context.Context, p *containerMetadataProvider) error {
	log.Debugf("Create Kubernetes client")

	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in cluster configuration for Kubernetes: %v", err)
	}
	p.kubeClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	k, ok := p.kubeClientSet.(*kubernetes.Clientset)
	if !ok {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	p.kubernetesClientQueryCount.Add(1)
	p.kubernetesNode, err = p.kubeClientSet.CoreV1().Nodes().Get(ctx, p.nodeName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get kubernetes nodes for '%s': %v",
			p.nodeName, err)
	}

	p.containerMetadataCache, err = getContainerMetadataCache(ctx, p.kubernetesNode)
	if err != nil {
		return fmt.Errorf("failed to create container metadata cache: %v", err)
	}

	// Create the shared informer factory and use the client to connect to
	// Kubernetes and get notified of new pods that are created in the specified node.
	factory := informers.NewSharedInformerFactoryWithOptions(k, 0,
		informers.WithTweakListOptions(func(options *v1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + p.nodeName
		}))
	informer := factory.Core().V1().Pods().Informer()

	// Kubernetes serves a utility to handle API crashes
	defer runtime.HandleCrash()

	handle, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in AddFunc handler: %#v", obj)
				return
			}
			p.addPodContainerLabels(pod)
		},
		UpdateFunc: func(_ any, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Errorf("Received unknown object in UpdateFunc handler: %#v",
					newObj)
				return
			}
			p.addPodContainerLabels(pod)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to attach event handler: %v", err)
	}

	// Shutdown the informer when the context attached to this handler expires
	stopper := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopper)
		if err := informer.RemoveEventHandler(handle); err != nil {
			log.Errorf("Failed to remove event handler: %v", err)
		}
	}()
	// Run the informer
	go informer.Run(stopper)

	return nil
}

// getPodsPerNode returns the number of pods per node.
// Depending on the configuration of the kubernetes environment, we may not be allowed to query
// for the allocatable information of the nodes.
func getPodsPerNode(ctx context.Context, node *corev1.Node) (int, error) {
	// With the ListOptions filter in place, there should be only one node listed in the
	// return we get from the API.
	quantity, ok := node.Status.Allocatable[corev1.ResourcePods]
	if !ok {
		return 0, fmt.Errorf("failed to get allocatable information from %s",
			node.Name)
	}

	return int(quantity.Value()), nil
}

func getContainerMetadataCache(ctx context.Context, node *corev1.Node) (
	*lru.SyncedLRU[string, model.LabelSet], error) {
	podsPerNode, err := getPodsPerNode(ctx, node)
	if err != nil {
		log.Infof("Failed to size cache based on pods per node: %v", err)
		podsPerNode = kubernetesDefaultPodsPerNode
	}

	cacheSize := podsPerNode * kubernetesContainersPerPod
	return lru.NewSynced[string, model.LabelSet](
		uint32(cacheSize), hashString)
}

const (
	metaLabelPrefix        = model.MetaLabelPrefix + "kubernetes_"
	namespaceLabel         = metaLabelPrefix + "namespace"
	podIPLabel             = metaLabelPrefix + "pod_ip"
	podContainerNameLabel  = metaLabelPrefix + "pod_container_name"
	podContainerIDLabel    = metaLabelPrefix + "pod_container_id"
	podContainerImageLabel = metaLabelPrefix + "pod_container_image"
	podContainerIsInit     = metaLabelPrefix + "pod_container_init"
	podReadyLabel          = metaLabelPrefix + "pod_ready"
	podPhaseLabel          = metaLabelPrefix + "pod_phase"
	podNodeNameLabel       = metaLabelPrefix + "pod_node_name"
	podHostIPLabel         = metaLabelPrefix + "pod_host_ip"
	podUID                 = metaLabelPrefix + "pod_uid"
	podControllerKind      = metaLabelPrefix + "pod_controller_kind"
	podControllerName      = metaLabelPrefix + "pod_controller_name"

	presentValue = model.LabelValue("true")
)

func containerForName(name string, containers []corev1.Container) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func (p *containerMetadataProvider) addPodContainerLabels(pod *corev1.Pod) {
	log.Debugf("Update container metadata cache for pod %s", pod.Name)

	for i := range pod.Status.ContainerStatuses {
		var containerID string
		var err error
		if containerID, err = matchContainerID(
			pod.Status.ContainerStatuses[i].ContainerID); err != nil {
			log.Debugf("failed to get kubernetes container metadata: %v", err)
			continue
		}

		name := pod.Status.ContainerStatuses[i].Name
		ctr := containerForName(name, pod.Spec.Containers)
		if ctr == nil {
			log.Infof("failed to find kubernetes container in spec named: %s", name)
			continue
		}

		p.addPodContainerMetadata(pod, ctr, containerID, false)
	}

	for i := range pod.Status.InitContainerStatuses {
		var containerID string
		var err error
		if containerID, err = matchContainerID(
			pod.Status.InitContainerStatuses[i].ContainerID); err != nil {
			log.Debugf("failed to get kubernetes container metadata: %v", err)
			continue
		}

		name := pod.Status.InitContainerStatuses[i].Name
		ctr := containerForName(name, pod.Spec.InitContainers)
		if ctr == nil {
			log.Infof("failed to find init kubernetes container in spec named: %s", name)
			continue
		}

		p.addPodContainerMetadata(pod, ctr, containerID, false)
	}
}

func (p *containerMetadataProvider) addPodContainerMetadata(
	pod *corev1.Pod,
	c *corev1.Container,
	containerID string,
	isInit bool,
) model.LabelSet {
	ls := model.LabelSet{
		namespaceLabel:         lv(pod.Namespace),
		podIPLabel:             lv(pod.Status.PodIP),
		podReadyLabel:          podReady(pod),
		podPhaseLabel:          lv(string(pod.Status.Phase)),
		podNodeNameLabel:       lv(pod.Spec.NodeName),
		podHostIPLabel:         lv(pod.Status.HostIP),
		podUID:                 lv(string(pod.ObjectMeta.UID)),
		podContainerNameLabel:  lv(c.Name),
		podContainerIDLabel:    lv(containerID),
		podContainerImageLabel: lv(c.Image),
		podContainerIsInit:     lv(strconv.FormatBool(isInit)),
	}

	createdBy := GetControllerOf(pod)
	if createdBy != nil {
		if createdBy.Kind != "" {
			ls[podControllerKind] = lv(createdBy.Kind)
		}
		if createdBy.Name != "" {
			ls[podControllerName] = lv(createdBy.Name)
		}
	}

	addObjectMetaLabels(ls, pod.ObjectMeta, RolePod)
	addObjectMetaLabels(ls, p.kubernetesNode.ObjectMeta, RoleNode)
	p.containerMetadataCache.Add(containerID, ls)
	return ls
}

func podReady(pod *corev1.Pod) model.LabelValue {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return lv(strings.ToLower(string(cond.Status)))
		}
	}
	return lv(strings.ToLower(string(corev1.ConditionUnknown)))
}

func lv(v string) model.LabelValue {
	return model.LabelValue(v)
}

// Role is role of the service in Kubernetes.
type Role string

// The valid options for Role.
const (
	RolePod  Role = "pod"
	RoleNode Role = "node"
)

func addObjectMetaLabels(labelSet model.LabelSet, objectMeta v1.ObjectMeta, role Role) {
	labelSet[model.LabelName(metaLabelPrefix+string(role)+"_name")] = lv(objectMeta.Name)

	for k, v := range objectMeta.Labels {
		ln := strutil.SanitizeLabelName(k)
		labelSet[model.LabelName(metaLabelPrefix+string(role)+"_label_"+ln)] = lv(v)
		labelSet[model.LabelName(metaLabelPrefix+string(role)+"_labelpresent_"+ln)] = presentValue
	}

	for k, v := range objectMeta.Annotations {
		ln := strutil.SanitizeLabelName(k)
		labelSet[model.LabelName(metaLabelPrefix+string(role)+"_annotation_"+ln)] = lv(v)
		labelSet[model.LabelName(metaLabelPrefix+string(role)+"_annotationpresent_"+ln)] = presentValue
	}
}

// GetControllerOf returns a pointer to a copy of the controllerRef if controllee has a controller
// https://github.com/kubernetes/apimachinery/blob/cd2cae2b39fa57e8063fa1f5f13cfe9862db3d41/pkg/apis/meta/v1/controller_ref.go
func GetControllerOf(controllee v1.Object) *v1.OwnerReference {
	for _, ref := range controllee.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			return &ref
		}
	}
	return nil
}

func getContainerdClient() *containerd.Client {
	knownContainerdSockets := []string{
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/docker/containerd/containerd.sock",
		"/system/run/containerd/containerd.sock",
	}

	for _, socket := range knownContainerdSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		opt := containerd.WithTimeout(3 * time.Second)
		if c, err := containerd.New(socket, opt); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Containerd client to %v", knownContainerdSockets)
	return nil
}

func getDockerClient() *client.Client {
	// /var/run/docker.sock is the default socket used by client.NewEnvClient().
	knownDockerSockets := []string{"/var/run/docker.sock"}

	// If the default socket is not available check if DOCKER_HOST is set to a different socket.
	envDockerSocket := os.Getenv(dockerHost)
	if envDockerSocket != "" {
		knownDockerSockets = append(knownDockerSockets, envDockerSocket)
	}

	for _, socket := range knownDockerSockets {
		if _, err := os.Stat(socket); err != nil {
			continue
		}
		if c, err := client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		); err == nil {
			return c
		}
	}
	log.Infof("Can't connect Docker client to %v", knownDockerSockets)
	return nil
}

func matchContainerID(containerIDStr string) (string, error) {
	containerIDParts := containerIDPattern.FindStringSubmatch(containerIDStr)
	if len(containerIDParts) != 2 {
		return "", fmt.Errorf("could not get string submatch for container id %v",
			containerIDStr)
	}
	return containerIDParts[1], nil
}

// AddMetadata adds metadata to the provided labels.Builder for the given PID.
func (p *containerMetadataProvider) AddMetadata(pid libpf.PID, lb *labels.Builder) bool {
	// Fast path, check container metadata has been cached
	// For kubernetes pods, the shared informer may have updated
	// the container id to container metadata cache, so retrieve the container ID for this pid.
	pidContainerID, env, err := p.lookupContainerID(pid)
	if err != nil {
		log.Debugf("Failed to get container id for pid %d: %v", pid, err)
		return false
	}
	if envUndefined == env {
		// We were not able to identify a container technology for the given PID.
		return true
	}

	// Fast path, check if the containerID metadata has been cached
	if metadata, ok := p.containerMetadataCache.Get(pidContainerID); ok {
		for k, v := range metadata {
			lb.Set(string(k), string(v))
		}
		return true
	}

	// For kubernetes pods this route should happen rarely, this means that we are processing a
	// trace but the shared informer has been delayed in updating the container id metadata cache.
	// If it is not a kubernetes pod then we need to look up the container id in the configured
	// client.
	switch {
	case isContainerEnvironment(env, envKubernetes) && p.kubeClientSet != nil:
		metadata, err := p.getKubernetesPodMetadata(pidContainerID)
		if err != nil {
			log.Debugf("Failed to get kubernetes pod metadata for container id %v: %v",
				pidContainerID, err)
			return false
		}
		for k, v := range metadata {
			lb.Set(string(k), string(v))
		}
		return true
	case isContainerEnvironment(env, envDocker) && p.dockerClient != nil:
		metadata, err := p.getDockerContainerMetadata(pidContainerID)
		if err != nil {
			log.Warnf("Failed to get docker container metadata for container id %v: %v",
				pidContainerID, err)
			return false
		}
		for k, v := range metadata {
			lb.Set(string(k), string(v))
		}
		return true
	case isContainerEnvironment(env, envContainerd) && p.containerdClient != nil:
		metadata, err := p.getContainerdContainerMetadata(pidContainerID)
		if err != nil {
			log.Debugf("Failed to get containerd container metadata for container id %v: %v",
				pidContainerID, err)
			return false
		}
		for k, v := range metadata {
			lb.Set(string(k), string(v))
		}
		return true
	case isContainerEnvironment(env, envDockerBuildkit):
		lb.Set("__meta_docker_build_kit_container_id", pidContainerID)
		return true
	case isContainerEnvironment(env, envLxc):
		lb.Set("__meta_lxc_container_id", pidContainerID)
		return true
	default:
		log.Debugf("Failed to handle unknown container technology %d", env)
		return true
	}
}

func (p *containerMetadataProvider) getKubernetesPodMetadata(pidContainerID string) (
	model.LabelSet, error) {
	log.Debugf("Get kubernetes pod metadata for container id %v", pidContainerID)

	p.kubernetesClientQueryCount.Add(1)
	pods, err := p.kubeClientSet.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: "spec.nodeName=" + p.nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve kubernetes pods, %v", err)
	}

	for j := range pods.Items {
		for i := range pods.Items[j].Status.ContainerStatuses {
			var containerID string
			if pods.Items[j].Status.ContainerStatuses[i].ContainerID == "" {
				continue
			}
			if containerID, err = matchContainerID(pods.Items[j].Status.ContainerStatuses[i].ContainerID); err != nil {
				log.Error(err)
				continue
			}
			if containerID == pidContainerID {
				name := pods.Items[j].Status.ContainerStatuses[i].Name
				ctr := containerForName(name, pods.Items[j].Spec.Containers)
				if ctr == nil {
					log.Infof("failed to find kubernetes container in spec named: %s", name)
					continue
				}

				return p.addPodContainerMetadata(&pods.Items[j], ctr, containerID, false), nil
			}
		}

		for i := range pods.Items[j].Status.InitContainerStatuses {
			var containerID string
			if pods.Items[j].Status.InitContainerStatuses[i].ContainerID == "" {
				continue
			}
			if containerID, err = matchContainerID(pods.Items[j].Status.InitContainerStatuses[i].ContainerID); err != nil {
				log.Error(err)
				continue
			}
			if containerID == pidContainerID {
				name := pods.Items[j].Status.InitContainerStatuses[i].Name
				ctr := containerForName(name, pods.Items[j].Spec.InitContainers)
				if ctr == nil {
					log.Infof("failed to find init kubernetes container in spec named: %s", name)
					continue
				}

				return p.addPodContainerMetadata(&pods.Items[j], ctr, containerID, false), nil
			}
		}
	}

	return nil,
		fmt.Errorf("failed to find matching kubernetes pod/container metadata for "+
			"containerID '%v' in %d pods", pidContainerID, len(pods.Items))
}

func (p *containerMetadataProvider) getDockerContainerMetadata(pidContainerID string) (
	model.LabelSet, error) {
	log.Debugf("Get docker container metadata for container id %v", pidContainerID)

	p.dockerClientQueryCount.Add(1)
	containers, err := p.dockerClient.ContainerList(context.Background(),
		container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list docker containers, %v", err)
	}

	for i := range containers {
		if containers[i].ID == pidContainerID {
			// remove / prefix from container name
			containerName := strings.TrimPrefix(containers[i].Names[0], "/")
			metadata := model.LabelSet{
				"__meta_docker_container_id":   lv(containers[i].ID),
				"__meta_docker_container_name": lv(containerName),
			}
			p.containerMetadataCache.Add(pidContainerID, metadata)
			return metadata, nil
		}
	}

	return nil,
		fmt.Errorf("failed to find matching docker container metadata for containerID, %v",
			pidContainerID)
}

func (p *containerMetadataProvider) getContainerdContainerMetadata(pidContainerID string) (
	model.LabelSet, error) {
	log.Debugf("Get containerd container metadata for container id %v", pidContainerID)

	// Avoid heap allocations here - do not use strings.SplitN()
	var fields [4]string // allocate the array on the stack with capacity 3
	n := stringutil.SplitN(pidContainerID, "/", fields[:])

	if n < 3 {
		return nil,
			fmt.Errorf("unexpected format of containerd identifier: %s",
				pidContainerID)
	}

	p.containerdClientQueryCount.Add(1)
	ctx := namespaces.WithNamespace(context.Background(), fields[1])
	containers, err := p.containerdClient.Containers(ctx)
	if err != nil {
		return nil,
			fmt.Errorf("failed to get containerd containers in namespace '%s': %v",
				fields[1], err)
	}

	for _, container := range containers {
		if container.ID() == fields[2] {
			// Containerd does not differentiate between the name and the ID of a
			// container. So we both options to the same value.
			metadata := model.LabelSet{
				"__meta_containerd_container_id":   lv(fields[2]),
				"__meta_containerd_container_name": lv(fields[2]),
				"__meta_containerd_pod_name":       lv(fields[1]),
			}
			p.containerMetadataCache.Add(pidContainerID, metadata)
			return metadata, nil
		}
	}

	return nil,
		fmt.Errorf("failed to find matching containerd container metadata for containerID, %v",
			pidContainerID)
}

// lookupContainerID looks up a process ID from the host PID namespace,
// returning its container ID and the used container technology.
func (p *containerMetadataProvider) lookupContainerID(pid libpf.PID) (containerID string, env containerEnvironment,
	err error) {
	if entry, exists := p.containerIDCache.Get(pid); exists {
		return entry.containerID, entry.env, nil
	}

	if _, exists := p.deferredPID.Get(pid); exists {
		return "", envUndefined, ErrDeferred
	}

	containerID, env, err = p.extractContainerIDFromFile(fmt.Sprintf(cgroupTemplate, pid))
	if err != nil {
		p.deferredPID.Add(pid, libpf.Void{})
		return "", envUndefined, err
	}

	// Store the result in the cache.
	p.containerIDCache.Add(pid, containerIDEntry{
		containerID: containerID,
		env:         env,
	})

	return containerID, env, nil
}

func (p *containerMetadataProvider) extractContainerIDFromFile(cgroupFilePath string) (
	containerID string, env containerEnvironment, err error) {
	f, err := os.Open(cgroupFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("%s does not exist anymore. "+
				"Failed to get container id", cgroupFilePath)
			return "", envUndefined, nil
		}
		return "", envUndefined, fmt.Errorf("failed to get container id from %s: %v",
			cgroupFilePath, err)
	}
	defer f.Close()

	containerID = ""
	env = envUndefined

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)

	var parts []string
	for scanner.Scan() {
		line := scanner.Text()

		if p.kubeClientSet != nil {
			parts = dockerKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= (envKubernetes | envDocker)
				break
			}
			parts = kubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
			parts = altKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
			parts = systemdKubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				env |= envKubernetes
				break
			}
		}

		if p.dockerClient != nil {
			if parts = dockerPattern.FindStringSubmatch(line); parts != nil {
				containerID = parts[1]
				env |= envDocker
				break
			}
			if parts = dockerBuildkitPattern.FindStringSubmatch(line); parts != nil {
				containerID = parts[1]
				env |= envDockerBuildkit
				break
			}
		}

		if p.containerdClient != nil {
			if parts = containerdPattern.FindStringSubmatch(line); parts != nil {
				// Forward the complete match as containerID so, we can extract later
				// the exact containerd namespace and container ID from it.
				containerID = parts[0]
				env |= envContainerd
				break
			}
		}

		if parts = lxcPattern.FindStringSubmatch(line); parts != nil {
			containerID = parts[2]
			env |= envLxc
			break
		}
	}

	return containerID, env, nil
}
