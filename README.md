![Build](https://github.com/parca-dev/parca-agent/actions/workflows/build.yml/badge.svg)
![Container](https://github.com/parca-dev/parca-agent/actions/workflows/container.yml/badge.svg)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)

# Parca Agent

Parca Agent is an always-on sampling profiler that uses eBPF to capture raw profiling data with very low overhead. It observes user-space and kernel-space stacktraces 100 times per second and builds [pprof](https://github.com/google/pprof) formatted profiles from the extracted data. Read more details in the [design documentation](docs/design.md).

The collected data can be viewed locally via HTTP endpoints and then be configured to be sent to a [Parca](https://github.com/parca-dev/parca) server to be queried and analyzed over time.

Kubernetes metadata is added to the profiled processes by default but can be disabled with `--kubernetes=false`.

## Requirements

* Linux Kernel version 4.18+

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
      --node=STRING               The name of the node that the process is
                                  running on. If on Kubernetes, this must match
                                  the Kubernetes node name.
      --config-path="parca-agent.yaml"
                                  Path to config file.
      --profiling-duration=10s    The agent profiling duration to use. Leave
                                  this empty to use the defaults.
      --metadata-external-labels=KEY=VALUE;...
                                  Label(s) to attach to all profiles.
      --metadata-container-runtime-socket-path=STRING
                                  The filesystem path to the container runtimes
                                  socket. Leave this empty to use the defaults.
      --local-store-directory=STRING
                                  The local directory to store the profiling
                                  data.
      --remote-store-address=STRING
                                  gRPC address to send profiles and symbols to.
      --remote-store-bearer-token=STRING
                                  Bearer token to authenticate with store.
      --remote-store-bearer-token-file=STRING
                                  File to read bearer token from to authenticate
                                  with store.
      --remote-store-insecure     Send gRPC requests via plaintext instead of
                                  TLS.
      --remote-store-insecure-skip-verify
                                  Skip TLS certificate verification.
      --remote-store-debug-info-upload-disable
                                  Disable debuginfo collection and upload.
      --remote-store-batch-write-interval=10s
                                  Interval between batch remote client writes.
                                  Leave this empty to use the default value of
                                  10s.
      --debug-info-directories=/usr/lib/debug,...
                                  Ordered list of local directories to
                                  search for debug info files. Defaults to
                                  /usr/lib/debug.
```

### Cgroups

All processes in the machine are profiled automatically, no matter which Cgroup they are in.


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
