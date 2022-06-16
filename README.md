![Build](https://github.com/parca-dev/parca-agent/actions/workflows/build.yml/badge.svg)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)

# Parca Agent

Parca Agent is an always-on sampling profiler that uses eBPF to capture raw profiling data with very low overhead. It observes user-space and kernel-space stacktraces 100 times per second and builds [pprof](https://github.com/google/pprof) formatted profiles from the extracted data. Read more details in the [design documentation](docs/design.md).

The collected data can be viewed locally via HTTP endpoints and then be configured to be sent to a [Parca](https://github.com/parca-dev/parca) server to be queried and analyzed over time.

It discovers targets through:

* **Kubernetes**: Discovering all the containers on the node the Parca agent is running on. (On by default, but can be disabled using `--kubernetes=false`)
* **systemd**: A list of Cgroups to be profiled on a node can be configured for the Parca agent to pick up. (Use the `--cgroups` flag to indicate the Cgroups to profile, eg. `--cgroups=docker.service` to profile the docker daemon)

## Requirements

* Linux Kernel version 4.18+
* A source of targets to discover from: [Kubernetes](https://kubernetes.io/) or [systemd](https://systemd.io/).

## Quickstart

See the [Kubernetes Getting Started](https://www.parca.dev/docs/kubernetes).

## Supported Profiles

Profiles available for compiled languages (eg. C, C++, Go, Rust):

* CPU
* Soon: Network usage, Allocations

The following types of profiles require explicit instrumentation:

* Runtime specific information such as Goroutines

## Debugging

### Web UI

The HTTP endpoints can be used to inspect the active profilers, by visiting port `7071` of the process (the host-port that the agent binds to can be configured using the `--http-address` flag).

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
  -h, --help                      Show context-sensitive help.
      --log-level="info"          Log level.
      --http-address=":7071"      Address to bind HTTP server to.
      --node=STRING               Name node the process is running on. If on
                                  Kubernetes, this must match the Kubernetes
                                  node name.
      --external-label=KEY=VALUE;...
                                  Label(s) to attach to all profiles.
      --store-address=STRING      gRPC address to send profiles and symbols to.
      --bearer-token=STRING       Bearer token to authenticate with store.
      --bearer-token-file=STRING
                                  File to read bearer token from to authenticate
                                  with store.
      --insecure                  Send gRPC requests via plaintext instead of
                                  TLS.
      --batch-write-interval=10s
                                  Interval between batcher client writes. Leave
                                  this empty to use the default value of 10s
      --insecure-skip-verify      Skip TLS certificate verification.
      --sampling-ratio=1.0        Sampling ratio to control how many of the
                                  discovered targets to profile. Defaults to
                                  1.0, which is all.
      --kubernetes                Discover containers running on this node to
                                  profile automatically.
      --pod-label-selector=STRING
                                  Label selector to control which Kubernetes
                                  Pods to select.
      --cgroups=CGROUPS,...       Cgroups to profile on this node.
      --systemd-units=SYSTEMD-UNITS,...
                                  [deprecated, use --cgroups instead] systemd
                                  units to profile on this node.
      --temp-dir=""               (Deprecated) Temporary directory path to use
                                  for processing object files.
      --socket-path=STRING        The filesystem path to the container runtimes
                                  socket. Leave this empty to use the defaults.
      --profiling-duration=10s    The agent profiling duration to use. Leave
                                  this empty to use the defaults.
      --cgroup-path=STRING        The cgroupfs path.
      --systemd-cgroup-path=STRING
                                  [deprecated, use --cgroup-path] The cgroupfs
                                  path to a systemd slice.
      --debug-info-disable        Disable debuginfo collection.
```

### Cgroups

To profile Cgroups, their names must be passed to the agent. For example, to profile the docker daemon pass `--cgroups=docker.service`.

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

Parca Agent requires to be run as `root` user (or `CAP_SYS_ADMIN`). Various security precautions have been taken to protect users running Parca Agent. See details in [Security Considerations](./docs/security.md).

To report a security vulnerability see [this guide](./docs/security.md#Report-Security-Vulnerabilities).

## Contributing

Check out our [Contributing Guide](CONTRIBUTING.md) to get started!

## License

User-space code: Apache 2

Kernel-space code (eBPF profilers): GNU General Public License, version 2

## Credits

Thanks to:

* Aqua Security for creating [libbpfgo](https://github.com/aquasecurity/libbpfgo) (cgo bindings for [libbpf](https://github.com/libbpf/libbpf)), while we contributed several features to it, they have made it spectacularly easy for us to contribute and it has been a great collaboration. Their use of libbpf in [tracee](https://github.com/aquasecurity/tracee) has also been a helpful resource.
* Kinvolk for creating [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget) some parts of this project were inspired by parts of it.
