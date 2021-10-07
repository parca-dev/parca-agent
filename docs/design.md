# Design

Parca Agent implements a sampling profiler, to sample stack traces 100 times per second via eBPF. It tracks user-space as well as kernel-space stack traces. From the raw data it builds a [pprof](https://github.com/google/pprof) formatted profile, and optionally sends it to a Parca server where it is stored and can be queried and analyzed over time.

Parca Agent uses BPF CO-RE (Compile Once – Run Everywhere) using [libbpf](https://github.com/libbpf/libbpf), and pre-compiles all BPF programs, and statically embeds them in the target binary, from where it is loaded via libbpf when used. This means that Parca Agent does not need to compile the BPF program at startup or runtime like when using [bcc-tools](https://github.com/iovisor/bcc/tree/master/tools), meaning no Clang & LLVM, nor kernel headers need to be installed on the host. The only requirement is a [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) capable Kernel (Linux Kernel 4.18+).

From a high-level it performs the following steps:

* [Target Discovery](#target-discovery): Discovers cgroups to attach the profiler on the machine the Parca Agent is running on.
* [Obtaining raw data](#obtaining-raw-data): Use a BPF program to sample raw stack traces and read aggregates every 10 seconds.
* [Transform to pprof](#transform-to-pprof): Transform the raw stack traces to a [pprof](https://github.com/google/pprof)  formatted profile.
* [Symbolize](#symbolization): Symbolize stack traces if necessary.
* [Send data to server](#send-data-to-server): Upload available symbol data and [pprof](https://github.com/google/pprof)  formatted profile to remote server.

![Parca Agent Architecture Diagram](https://docs.google.com/drawings/d/18xXj1Tjt9l-iuR3gse1lqI4QA2XTCQOylC5kc2cVMT4/export/svg)

## Target Discovery

The Parca Agent works by attaching the profiler to a [Linux cgroups](https://en.wikipedia.org/wiki/Cgroups), so the cgroups to attach to must first be discovered through some mechanism. Parca Agent currently has two primary mechanisms to discover cgroups: Kubernetes and systemd. Besides the cgroups, the target discovery also provides the labels to label a series of profiles being sent to the server.

### Kubernetes

To discover cgroups to profile in Kubernetes, Parca Agent first discovers all Pods running on the node it is on, then discovers the primary PID of the cgroup using Kubernetes CRI (container runtime interface). For profiling purposes a `perf_event` cgroup is required, which is read from `/proc/PID/cgroup`.

> Note: Unfortunately, Kubernetes CRI does not actually have the retrieving PIDs formally specified, because CRI is intended for any type of sandboxing, including virtual machines (which wouldn't have a PID in the same way). While there are some recommendations, in practice retrieving the PID actually requires a direct integration with each container runtime, because runtimes are inconsistent and don't appear to follow the recommendation. Parca Agent has explicit support for docker, containerd, and cri-o.

Labels provided by the Kubernetes discovery are: `node`, `namespace`, `pod`, `container` and `containerid`.

### systemd

systemd starts all services in a cgroup, and conveniently and consistently mounts the cgroup hierarchy. Unfortunately [`perf_event` is one of the few cgroups systemd does not automatically manage](https://systemd.io/CGROUP_DELEGATION/#controller-support). This means the `perf_event` cgroup needs to be separately managed by Parca Agent. It will replicate the cgroup hierarchy under `system.slice`, into `perf_event` and sync the `cgroup.procs` once per second.

Labels provided by the systemd discovery are: `node` and `systemd_unit`.

## Obtaining raw data

Parca Agent obtains the raw data by attaching an BPF program to a [Linux cgroup](https://en.wikipedia.org/wiki/Cgroups) using [perf_event_open](https://man7.org/linux/man-pages/man2/perf_event_open.2.html). It instructs the Kernel to call the BPF program every 100 times per second.

The way BPF programs communicate with user-space uses BPF maps. The Parca Agent BPF program records data in two maps:

* **Stack traces**: The stack traces map is made up of the stack trace ID as the key and the memory addresses that represent the code executed that represents that stack trace.
* **Counts**: The counts map is made up of a key that is a triple of PID, user-space stack ID, and kernel-space stack ID and value is the amount of times that stack trace ID has been observed.

Parca Agent reads all data every 10 seconds. The data that is read from the BPF maps gets processed and then purged to reset for the next iteration.

<p align="center">
  <img alt="Parca Agent BPF program" src="https://docs.google.com/drawings/d/1Xq3VpXzO9wo2k91ZQKVBzzo4axszTA0SCrzRSnosNi4/export/svg" alt="drawing" width="600" />
</p>

## Transform to pprof

Originally created by Google, [pprof](https://github.com/google/pprof) is both a format and toolchain to visualize and analyze profiling data.

The pprof format consists of 5 main components: Samples, Locations, Mappings, Functions, Strings.

### Samples

A sample is the stack trace (in the form of a list of Locations) and the number of times that stack trace has been seen.

### Locations

A location uniquely identifies a piece of code. It references the mapping it belongs to (essentially the binary or shared library/object) and the memory address of the executed code. A pseudo ID is generated for interpreted languages where there is no definitive relationship between the memory address and the code executed.

### Mappings

A mapping represents object files and how they were mapped in the process that the data was obtained from. This is important in order to be able to symbolize the stack traces later from machine-readable memory addresses to human-readable filename, line-number, package/module name, and function name. Mappings are parsed from `/proc/PID/maps`.

There are three special cases for mappings:

* Kernel
* VDSO
* vsyscall

## Symbolization

### Kernel symbols

Kernel stack traces are immediately symbolized by the Parca Agent since the Kernel can have a dynamic memory layout (for example, loaded eBPF programs in addition to the static kernel pieces). This is done by reading symbols from `/proc/kallsyms` and resolving the memory addresses accordingly.

### Application symbols

Binaries or shared libraries/objects that contain debug symbols have their symbols extracted and uploaded to the remote server. The remote server can then use it to symbolize the stack traces at read time rather than in the agent. This also allows debug symbols to be uploaded separately if they are stripped in a CI process or retrieved from symbol servers such as [debuginfod](https://sourceware.org/elfutils/Debuginfod.html), [Microsoft symbol server](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols), or [others](https://getsentry.github.io/symbolicator/).

Future integrations of interpreted (e.g. Ruby, nodejs, python) or JIT languages (e.g. JVM) must resolve symbols to their pprof `Location` `Line`s and `Function`s directly in the agent and persisted in the pprof profile since their dynamic nature cannot be guaranteed to be stable.

## Send data to server

First, if available, extracted symbols are uploaded to a Parca compatible server (this can be Parca itself or a compatible service like [Polar Signals](https://www.polarsignals.com/)). Then, combined with the labels provided by the target discovery, the serialized pprof formatted profile is sent to a Parca compatible server (this can be Parca itself or a compatible service like [Polar Signals](https://www.polarsignals.com/)).
