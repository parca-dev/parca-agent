# Contributing Guidelines

This project is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license and accepts contributions via GitHub pull requests. This document outlines some of the conventions on development workflow, commit message formatting, contact points and other resources to make it easier to get your contribution accepted.

# Certificate of Origin

By contributing to this project you agree to sign a Contributor License Agreement(CLA).

# Code of Conduct

Parca-agent follows [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).


<!-- TODO: Add code of conduct info-->
# Prerequisites

- Linux Kernel version 4.18+
- A source of targets to discover from: Kubernetes or systemd.

Install the following dependencies (Instructions are linked for each dependency).

- [Go](https://golang.org/doc/install)
- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/engine/install/)
- [minikube](https://kubernetes.io/docs/tasks/tools/#minikube)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- [LLVM](https://apt.llvm.org/)

> **Note:** LLVM version 11 is enough to compile libbpf. However, Rust and Aya based toolchain requires LLVM version 14.

For the debian based distributions:
    ```console
    $ sudo apt-get update

    $ sudo apt-get install make zlib1g pkg-config libclang-14-dev llvm-14-dev libbpf-dev libelf-dev
    ```

Install the rust nightly toolchain as defined in the root `rust-toolchain.toml`

Alternatively, [Nix](https://nixos.org/download.html#download-nix) can be used to avoid installing system packages,
simply run `nix-shell` (or `nix-shell shell.nix`) to load the dependencies. Docker and VirtualBox are required to be installed as system packages.

# Getting Started

Fork the [parca-agent](https://github.com/parca-dev/parca-agent) and [parca](https://github.com/parca-dev/parca) repositories on GitHub.
Clone the repositories on to your machine.

```console
$ git clone git@github.com:parca-dev/parca-agent.git
```

## Run parca-agent

Code changes can be tested locally by building parca-agent and running it to profile systemd units.
The following code snippet profiles the docker daemon, i.e. `docker.service` systemd unit:

```console
$ cd parca-agent

$ make -C bpf setup

$ make

$ sudo dist/parca-agent --node=test --cgroups=docker.service --log-level=debug --kubernetes=false --insecure
```

The generated profiles can be seen at http://localhost:7071 .

**Note**: Currently, parca-agent has systemd discovery support for Cgroup v1 only.

## Working with parca server

Clone the parca server repository and copy the parca-agent repository (where you have made changes) to `parca/tmp/`:

```console
$ git clone git@github.com:parca-dev/parca.git

$ cp -Rf parca-agent parca/tmp/parca-agent
```

Then follow [the server's `CONTRIBUTING.md`](https://github.com/parca-dev/parca/blob/main/CONTRIBUTING.md#prerequisites) to get your development Kubernetes cluster running (via Tilt).

Test your changes by running:

```console
$ cd parca-agent && make test
```

<!--
TODO:
    #Internals
        ## Code Structure
-->

# Making a PR

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. If you are not entirely sure about this, you can discuss this on the [Parca Discord](https://discord.gg/ZgUpYgpzXy) server as well.

Please make sure to update tests as appropriate.

This is roughly what the contribution workflow should look like:

- Create a topic branch from where you want to base your work (usually main).
- Make commits of logical units.
- Make sure the tests pass, and add any new tests as appropriate.
- Use `make test` and `make test-e2e` to run unit tests and smoke tests respectively.
- Make sure the code is properly formatted. (`make format` could be useful here.)
- Make sure the code is properly linted. (`make lint` could be useful here.)
- Make sure your commit messages follow the commit guidelines (see below).
- Push your changes to a topic branch in your fork of the repository.
- Submit a pull request to the original repository.

Thank you for your contributions!


# Commit Guidelines

We follow a rough convention for commit messages that is designed to answer two
questions: what changed and why. The subject line should feature the what and
the body of the commit should describe the why.


```

scripts: add the test-cluster command

this uses tmux to setup a test cluster that you can easily kill and
start for debugging.

Fixes #38

```

The first line is the subject and should be no longer than 70 characters, the second line is always blank, and other lines should be wrapped at 80 characters. This allows the message to be easier to read on GitHub as well as in various git tools.
