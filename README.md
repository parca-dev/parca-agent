![Build](https://github.com/parca-dev/parca-agent/actions/workflows/build.yml/badge.svg)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)

# Parca Agent

Parca Agent is an always-on sampling profiler that uses eBPF to capture raw profiling data with very low overhead. It observes user-space and kernel-space stacktraces 100 times per second and builds [pprof](https://github.com/google/pprof) formatted profiles from the extracted data. Read more details in the [design documentation](docs/Design.md).

The collected data can be viewed locally via HTTP endpoints and then be configured to be sent to a [Conprof](https://github.com/conprof/conprof) server or a Conprof compatible service (such as [Polar Signals](https://www.polarsignals.com/)) to be queried and analyzed over time.

It discovers targets through:

* **Kubernetes**: Discovering all the containers on the node the Parca agent is running on. (On by default, but can be disabled using `--kubernetes=false`)
* **SystemD**: A list of SystemD units to be profiled on a node can be configured for the Parca agent to pick up. (Use the `--systemd-units` flag to list the units to profile, eg. `--systemd-units=docker.service` to profile the docker daemon)

## Requirements

* Linux Kernel version 4.18+
* A source of targets to discover from: [Kubernetes](https://kubernetes.io/) or [SystemD](https://systemd.io/).

## Quickstart

To quickly try out the Parca Agent with Kubernetes, create a [minikube](https://minikube.sigs.k8s.io/docs/) cluster with an actual virtual machine, eg. virtualbox:

```
minikube start --driver=virtualbox
```

Then provision the parca-agent:

```
kubectl create -f https://raw.githubusercontent.com/parca-dev/parca-agent/main/manifests.yaml
```

<details>
  <summary><code>manifests.yaml</code></summary>
  <p>
    
  [embedmd]:# (manifests.yaml)
  ```yaml
  apiVersion: v1
  kind: Namespace
  metadata:
    name: parca
  ---
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: parca-agent
    namespace: parca
  ---
  kind: ClusterRoleBinding
  apiVersion: rbac.authorization.k8s.io/v1
  metadata:
    name: parca-agent
  subjects:
  - kind: ServiceAccount
    name: parca-agent
    namespace: parca
  roleRef:
    kind: ClusterRole
    name: cluster-admin
    apiGroup: rbac.authorization.k8s.io
  ---
  apiVersion: apps/v1
  kind: DaemonSet
  metadata:
    name: parca-agent
    namespace: parca
    labels:
      app.kubernetes.io/name: parca-agent
  spec:
    selector:
      matchLabels:
        app.kubernetes.io/name: parca-agent
    template:
      metadata:
        labels:
          app.kubernetes.io/name: parca-agent
      spec:
        serviceAccount: parca-agent
        hostPID: true
        containers:
        - name: parca-agent
          image: quay.io/parca/parca-agent@sha256:265fb65d029d136644304737c739786c2b1695034dd66c743dc59ef6324c3311
          imagePullPolicy: Always
          args:
          - /bin/parca-agent
          - --node=$(NODE_NAME)
            #- --sampling-ratio=0.5
            #- --pod-label-selector=app=my-web-app
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            privileged: true
          volumeMounts:
          - name: root
            mountPath: /host/root
            readOnly: true
          - name: proc
            mountPath: /host/proc
            readOnly: true
          - name: run
            mountPath: /run
          - name: modules
            mountPath: /lib/modules
          - name: debugfs
            mountPath: /sys/kernel/debug
          - name: cgroup
            mountPath: /sys/fs/cgroup
          - name: bpffs
            mountPath: /sys/fs/bpf
          - name: localtime
            mountPath: /etc/localtime
        tolerations:
        - effect: NoSchedule
          operator: Exists
        - effect: NoExecute
          operator: Exists
        volumes:
        - name: root
          hostPath:
            path: /
        - name: proc
          hostPath:
            path: /proc
        - name: run
          hostPath:
            path: /run
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: modules
          hostPath:
            path: /lib/modules
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
        - name: localtime
          hostPath:
            path: /etc/localtime
  ```
    
  </p>
</details>

To view the active profilers port-forward and visit `http://localhost:8080`:

```
kubectl -n parca port-forward `kubectl -n parca get pod -lapp.kubernetes.io/name=parca-agent -ojsonpath="{.items[0].metadata.name}"` 8080
```

To continuously send every profile collected to a Conprof instance or a Conprof compatible service configure the `--store-address` and potential credentials needed. For example, to send to a Conprof server in the `conprof` namespace set: `--store-address=conprof.conprof.svc:10901`.

To send to a Conprof compatible service such as Polar Signals, use:

* `--store-address=grpc.polarsignals.com:443`
* `--bearer-token=<project-token>`

## Supported Profiles

Profiles available for compiled languages (eg. C, C++, Go, Rust):

* CPU
* Soon: Network usage, Allocations

The following types of profiles require explicit instrumentation:

* Runtime specific information such as Goroutines

## Debugging

### Web UI

The HTTP endpoints can be used to inspect the active profilers, by visiting port `8080` of the process (the host-port that the agent binds to can be configured using the `--http-address` flag).

On a minikube cluster that might look like the following:

![Active Profilers](/activeprofilers.png?raw=true "Active Profilers")

And by clicking "Show Profile" in one of the rows, the currently collected profile will be rendered once the collection finishes (this can take up to 10 seconds).

![Profile View](/profileview.png?raw=true "Profile View")

A raw profile can also be downloaded here by clicking "Download Pprof". Note that in the case of native stack traces such as produced from compiled language like C, C++, Go, Rust, etc. are not symbolized and if this pprof profile is analyzed using the standard pprof tooling the symbols will need to be available to the tooling.

### Logging

To debug potential errors, enable debug logging using `--log-level=debug`.

## Configuration

Flags:

[embedmd]:# (dist/help.txt)
```txt
Usage: parca-agent --node=STRING

Flags:
  -h, --help                    Show context-sensitive help.
      --log-level="info"        Log level.
      --http-address=":8080"    Address to bind HTTP server to.
      --node=STRING             Name node the process is running on. If on
                                Kubernetes, this must match the Kubernetes node
                                name.
      --store-address=STRING    gRPC address to send profiles and symbols to.
      --bearer-token=STRING     Bearer token to authenticate with store.
      --bearer-token-file=STRING
                                File to read bearer token from to authenticate
                                with store.
      --insecure                Send gRPC requests via plaintext instead of TLS.
      --insecure-skip-verify    Skip TLS certificate verification.
      --sampling-ratio=1.0      Sampling ratio to control how many of the
                                discovered targets to profile. Defaults to 1.0,
                                which is all.
      --kubernetes              Discover containers running on this node to
                                profile automatically.
      --pod-label-selector=STRING
                                Label selector to control which Kubernetes Pods
                                to select.
      --systemd-units=SYSTEMD-UNITS,...
                                SystemD units to profile on this node.
```

### SystemD

To discover SystemD units, the names must be passed to the agent. For example, to profile the docker daemon pass `--systemd-units=docker.service`.

### Sampling

#### Sampling Ratio

To sample all targets, either to save resources on storage or reduce overhead, use the `--sampling-ratio` flag. For example, to profile only 50% of the discovered targets use `--sampling-ratio=0.5`.

#### Kubernetes label selector

To further sample targets on Kubernetes use the `--pod-label-selector=` flag. For example to only profile Pods with the `app.kubernetes.io/name=my-web-app` label, use `--pod-label-selector=app.kubernetes.io/name=my-web-app`.

## Roadmap

* Additional language support for just-in-time (JIT) compilers, and dynamic languages (non-exhaustive list):
  * Ruby
  * Node.js
  * Python
  * JVM
* Additional types of profiles:
  * Memory allocations
  * Network usage

## Security

Parca Agent requires to be run as `root` user (or `CAP_SYS_ADMIN`). Various security precautions have been taken to protect users running Parca Agent. See details in [SECURITY.md](./SECURITY.md).

To report a security vulnerability see [this guide](./SECURITY.md#Report-Security-Vulnerabilities).

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

Apache 2

## Credits

Thanks to:

* Aqua Security for creating [libbpfgo](https://github.com/aquasecurity/libbpfgo) (cgo bindings for [libbpf](https://github.com/libbpf/libbpf)), while we contributed several features to it, they have made it spectacularly easy for us to contribute and it has been a great collaboration. Their use of libbpf in [tracee](https://github.com/aquasecurity/tracee) has also been a helpful resource.
* Kinvolk for creating [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget) some parts of this project were inspired by parts of it.
