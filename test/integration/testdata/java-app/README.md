# Spring boot example

This repo is an example for how a Java application can be profiled with Parca Agent. First deploy Parca and Parca Agent as usual, for example [on Kubernetes](https://www.parca.dev/docs/kubernetes).

In order for Parca Agent to be able to make sense of the just-in-time compiled code by the Java VM, the Java process needs to comply to the [Linux Kernel perf jit-interface](https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jit-interface.txt). To do this, the java process needs to be started with the following two flags `-XX:+PreserveFramePointer` and `-agentpath:/your/path/to/libperfmap.so` where the `libperfmap.so` agent can be downloaded [here](https://github.com/parca-dev/perf-map-agent/releases/tag/v0.0.1).

What the agent does is, it maintains a file in `/tmp/perf-PID.map`, that contains mappings from memory address to Java class and function names. This is the [Linux Kernel perf jit-interface](https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jit-interface.txt), and when this file is present, Parca Agent will detect that and resolve the otherwise to humans incomprehensible memory addresses to the human readable class and function names.

To run this example Java spring boot app on the same Kubernetes cluster execute:

```bash
kubectl run spring-boot-example --image=ghcr.io/parca-dev/spring-boot-example:v0.0.1 --port=8080
```

The important parts to make this work are:

* Adding the `libperfmap.so` agent to the container image (see [this line in the Dockerfile](./Dockerfile#L15)).
* Adding the [`-XX:+PreserveFramePointer` and `-agentpath:/app/libperfmap.so` flags to the Java command](./Dockerfile#L17). Depending on the setup and framework these flags may need to be set using the `JAVA_OPTS` environment variable.

## Roadmap

In the future there will be no need to load the additional agent at all, and everything will happen automatically. Follow [parca-dev/praca-agent#1](https://github.com/parca-dev/parca-agent/issues/1) for the latest status.

## Screenshot

An example screenshot of parts of an iciclegraph/flamegraph of data produced with this example:

![Screenshot from 2022-01-04 19-02-00](https://user-images.githubusercontent.com/4546722/148103403-dee74a40-7fc7-4681-8733-ac368cb036ee.png)
