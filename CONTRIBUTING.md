# Contributing Guidelines

This project is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license and accepts contributions via GitHub pull requests. This document outlines some of the conventions on development workflow, commit message formatting, contact points and other resources to make it easier to get your contribution accepted.

# Certificate of Origin

By contributing to this project you agree to sign a Contributor License Agreement(CLA).

# Code of Conduct

Parca-agent follows [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).


<!-- TODO: Add code of conduct info-->
# Prerequisites

- Linux Kernel version 4.18+
- [Nix](https://nixos.org/download.html) with the [`flakes`](https://nixos.wiki/wiki/Flakes#Enable_flakes) feature enabled

Execute [`nix develop`](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-develop.html) to get a development environment with all the dependencies.

[Our Nix binary cache](https://parca-agent.cachix.org) can be configured to avoid rebuilding everything from scratch,
run `nix run nixpkgs#cachix -- use parca-agent` to configure it or add the following to your [`nix.conf`](https://nixos.org/manual/nix/stable/command-ref/conf-file.html):

```ini
trusted-public-keys = parca-agent.cachix.org-1:BmDSovovL+kILZoyXzsrF1ZIR1CD9m58q3kuJk3zBXo=
trusted-substituters = https://parca-agent.cachix.org
```

Alternatively, [Docker](https://docs.docker.com/engine/install/) or [Podman](https://podman.io/getting-started/installation)
can be used to run Nix in a container, run `make container-devshell` to start one and `make container-devshell-exec` to get a shell.

An hypervisor like [VirtualBox](https://www.virtualbox.org/wiki/Downloads) is also required to serve as a driver for Minikube.

# Getting Started

Fork the [parca-agent](https://github.com/parca-dev/parca-agent) and [parca](https://github.com/parca-dev/parca) repositories on GitHub.
Clone the repositories on to your machine.

```console
$ git clone git@github.com:parca-dev/parca-agent.git
```

## Run parca-agent

Code changes can be tested locally by building parca-agent and running it to profile system processes.

```console
$ cd parca-agent

$ nix build

# Assumes Parca server runs on localhost:7070
$ sudo result/bin/parca-agent --node=test --log-level=debug --remote-store-address=localhost:7070 --remote-store-insecure
```

The generated profiles can be seen at http://localhost:7071 .

## Working with parca server

Clone the parca server repository and copy the parca-agent repository (where you have made changes) to `parca/tmp/`:

```console
$ git clone git@github.com:parca-dev/parca.git

$ cp -Rf parca-agent parca/tmp/parca-agent
```

Then depending on whether you would like to test changes to Parca Agent or Parca, you can run `make dev/up` in Parca Agent or follow [the server's `CONTRIBUTING.md`](https://github.com/parca-dev/parca/blob/main/CONTRIBUTING.md#prerequisites) to get your development Kubernetes cluster running with Tilt.

Test your changes by running:

```console
$ cd parca-agent && nix develop --command make test
```

<!--
TODO:
    #Internals
        ## Code Structure
-->

# Making a PR

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. If you are not entirely sure about this, you can discuss this on the [Parca Discord](https://discord.gg/ZgUpYgpzXy) server as well. RFCs are used to document all things architecture and design for the Parca project. You can find an index of the RFCs [here](https://docs.google.com/document/d/171XgH4l_gxvGnETVKQBddo75jQz5aTSDOqO0EZ7LLqE/edit?usp=share_link).

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

# pre-commit

[pre-commit](https://pre-commit.com) hooks can installed to help with the linting and formatting of your code:

```
pre-commit install
```
