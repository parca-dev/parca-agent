# Polar Signals Agent

## How it works

Polar Signals Agent uses sampling profiling techniques via eBPF to capture CPU profiles. It observes user-space and kernel-space stacktraces 100 times per second and builds pprof profiles from the extracted data.

It finds targets through:

* **Kubernetes**: Polar Signals Agent discovers targets to profile through the Kubernetes API, any running container is automatically profiled.
* **systemd**: A list of systemd services to be profiled on a node can be configured for the Polar Signals agent to pick up.

## Setup

## Debugging

## Profiles

Profiles available via eBPF:

* CPU
* Soon: Network usage, Allocations

The following types of profiles require explicit instrumentation:

* Heap
* Runtime specific information such as Go routines

## Credits

Thanks to:

* Aqua Security for creating [libbpfgo](https://github.com/aquasecurity/libbpfgo) (cgo bindings for [libbpf](https://github.com/libbpf/libbpf)), while we contributed several features to it, they have made it spectacularly easy for us to contribute and it has been a great collaboration. Their use of libbpf in [tracee](https://github.com/aquasecurity/tracee) has also been a helpful resource.
* Kinvolk for creating [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget) some parts of this project were inspired by parts of it.
