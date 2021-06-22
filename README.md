# Polar Signals Agent

Polar Signals Agent is a sampling profiler that uses eBPF to capture the raw profiling data. It observes user-space and kernel-space stacktraces 100 times per second and builds [pprof](https://github.com/google/pprof) formatted profiles from the extracted data.

The collected data can be viewed locally via HTTP endpoints and then be configured to be sent to [Polar Signals](https://www.polarsignals.com/) to be queried and analyzed over time.

It finds targets through:

* **Kubernetes**: Discovering all the containers on the node the Polar Signals agent is running on. (On by default, but can be disabled using `--kubernetes=false`)
* **systemd**: A list of systemd units to be profiled on a node can be configured for the Polar Signals agent to pick up. (Use the `--systemd-units` flag to list the units to profile, eg. `--systemd-units=docker.service` to profile the docker daemon)

## Supported Profiles

Profiles available for compiled languages (eg. C, C++, Go, Rust):

* CPU
* Soon: Network usage, Allocations

The following types of profiles require explicit instrumentation:

* Heap
* Runtime specific information such as Go routines

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

## Roadmap

* Additional language support for just-in-time (JIT) compilers, and dynamic languages (non-exhaustive list):
  * Ruby
  * Node.js
  * Python
  * JVM
* Additional types of profiles:
  * Memory allocations
  * Network usage

## Credits

Thanks to:

* Aqua Security for creating [libbpfgo](https://github.com/aquasecurity/libbpfgo) (cgo bindings for [libbpf](https://github.com/libbpf/libbpf)), while we contributed several features to it, they have made it spectacularly easy for us to contribute and it has been a great collaboration. Their use of libbpf in [tracee](https://github.com/aquasecurity/tracee) has also been a helpful resource.
* Kinvolk for creating [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget) some parts of this project were inspired by parts of it.
