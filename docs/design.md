# Design

Parca Agent implements a sampling profiler, to sample stack traces [19 times per second](#cpu-sampling-frequency) via eBPF. It tracks user space as well as kernel-space stack traces. From the raw data, it builds a [pprof](https://github.com/google/pprof) formatted profile and optionally sends it to a Parca server where it is stored and can be queried and analyzed over time.

Parca Agent is a whole-system profiler. It collects stack traces from all the processes that run on the host system. This provides more insights about all the aspects of the system to the user. Please see our [blog post](https://www.polarsignals.com/blog/posts/2022/08/24/system-wide-profiling/) about internals of this mechanism.

Parca Agent uses BPF CO-RE (Compile Once – Run Everywhere) using [libbpf](https://github.com/libbpf/libbpf), pre-compiles all BPF programs, and statically embeds them in the target binary, from where it is loaded via libbpf when used. This means that Parca Agent does not need to compile the BPF program at startup or runtime like when using [bcc-tools](https://github.com/iovisor/bcc/tree/master/tools), meaning no Clang & LLVM, nor kernel headers need to be installed on the host. The only requirement is a [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html)-capable Kernel (Linux Kernel 5.3+ with BTF).

From a high level it performs the following steps:

* [Obtaining raw data](#obtaining-raw-data): Use a BPF program to sample raw stack traces and read aggregates every 10 seconds.
* [Transform to pprof](#transform-to-pprof): Transform the raw stack traces to a [pprof](https://github.com/google/pprof)-formatted profile.
* [Symbolize](#symbolization): Symbolize stack traces if necessary.
* [Metadata Discovery](#metadata-discovery): Discovers possible metadata sources and enriches the profiles collect from the host system Parca Agent runs on.
* [Send data to server](#send-data-to-server): Upload available symbol data and [pprof](https://github.com/google/pprof)-formatted profile to the remote server.

![Parca Agent Architecture Diagram](https://docs.google.com/drawings/d/18xXj1Tjt9l-iuR3gse1lqI4QA2XTCQOylC5kc2cVMT4/export/svg)

## Obtaining raw data

Parca Agent obtains the raw data by attaching an eBPF program to a `perf_event`, specifically `PERF_COUNT_SW_CPU_CLOCK` event (See for details [perf_event_open](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)). It instructs the Kernel to call the BPF program every [19 times per second](#cpu-sampling-frequency).

The way BPF programs communicate with user-space uses BPF maps. The Parca Agent BPF program records data in two maps:

* **Stack traces**: The stack traces map is made up of the stack trace ID as the key and the memory addresses that represent the code executed that represents that stack trace.
* **Counts**: The counts map is made up of a key that is a triple of PID, user-space stack ID, and kernel-space stack ID and value is the number of times that stack trace ID has been observed.

Parca Agent reads all data every 10 seconds. The data that is read from the BPF maps gets processed and then purged to reset for the next iteration.

<p align="center">
  <img alt="Parca Agent BPF program" src="https://docs.google.com/drawings/d/1Xq3VpXzO9wo2k91ZQKVBzzo4axszTA0SCrzRSnosNi4/export/svg" alt="drawing" width="600" />
</p>

### CPU sampling frequency

We sample at 19Hz (19 times per second) because it is a prime number, and primes are good to avoid collisions with other things that may be happening periodically on a machine.
In particular, 100 samples per second means every 10ms which is a frequency that may very well be used by user code, so a CPU profile could show a periodic workload on-CPU 100% of the time which is misleading
as it would produce a skewed profile.

19 is close to 20 which would have been a natural choice just for lowering profiling overhead, and it's easier to reason about, e.g., we could take roughly 80 samples per second on 4-CPU machine.

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

## Metadata Discovery

The metadata discovery provides the labels to label a series of profiles being sent to the server. Please see the [labelling document](https://www.parca.dev/docs/parca-agent-labelling) for further details.

## Send data to server

First, if available, extracted symbols are uploaded to a Parca compatible server (this can be Parca itself or a compatible service like [Polar Signals](https://www.polarsignals.com/)). Then, combined with the labels provided by the target discovery, the serialized pprof formatted profile is sent to a Parca compatible server (this can be Parca itself or a compatible service like [Polar Signals](https://www.polarsignals.com/)).
