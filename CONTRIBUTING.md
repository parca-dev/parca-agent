# Contributing Guidelines

This project is licensed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license and accept contributions via GitHub pull requests. This document outlines some of the conventions on development workflow, commit message formatting, contact points and other resources to make it easier to get your contribution accepted.

# Certificate of Origin

By contributing to this project you agree to the Developer Certificate of
Origin (DCO). This document was created by the Linux Kernel community and is a
simple statement that you, as a contributor, have the legal right to make the
contribution and agree to the terms specified in the [DCO](DCO) file  for that
particular contribution.


DCO sign-offs differ from contributor agreements (CLAs):

- While contributor agreements are usually made once and automatically cover all future contributions, DCO sign-offs must be present on every single commit, or else the contribution will not be accepted.
- A contributor agreement may be signed by a third party, like a company, on behalf of its employees, whereas the DCO is always an attestation by the author of the contribution.

<!-- TODO: Add code of conduct info-->
# Prerequisites

- Linux Kernel version 4.18+
- A source of targets to discover from: Kubernetes or SystemD.

Install the following dependencies (Instructions are linked for each dependency).

- [Go](https://golang.org/doc/install)
- [Node](https://nodejs.org/en/download/)
- [Docker](https://docs.docker.com/engine/install/)
- [minikube](https://v1-18.docs.kubernetes.io/docs/tasks/tools/install-minikube/)
- [kubectl](https://v1-18.docs.kubernetes.io/docs/tasks/tools/install-kubectl/)
- [LLVM](https://apt.llvm.org/)
    ```
    $ sudo apt-get install llvm

    $ sudo pacman -S  llvm
     ```


# Getting Started

Fork the [parca-agent](https://github.com/parca-dev/parca-agent) and [parca](https://github.com/parca-dev/parca) repositories on GitHub.
Clone the repositories on to your machine.

```
$ git clone git@github.com:parca-dev/parca.git

$ git clone git@github.com:parca-dev/parca-agent.git
```

## **Run parca-agent**


Code changes can be tested locally by building parca-agent and running it to profile systemd units.
The following code snippet profiles the docker daemon, i.e. `docker.service` systemd unit:

```
$ cd parca-agent

$ make

$ sudo dist/parca-agent --node=test --systemd-units=docker.service --log-level=debug --kubernetes=false --insecure
```

The generated profiles can be seen at http://localhost:7071 .

**Note**: Currently, parca-agent has systemd discovery support for Cgroup v1 only.

## **Working with parca server**

To launch parca-agent locally with the [parca server](https://github.com/parca-dev/parca#development), first copy your parca-agent repository (where you have made changes) to `parca/tmp/`:

```
$ cp -Rf parca-agent parca/tmp/parca-agent
```

Go to the project directory and compile parca:

```
$ cd parca

$ make build
```

Run the binary locally.

```
./bin/parca
```
Once compiled the server ui can be seen at http://localhost:7070.


To profile all containers using Kubernetes, the parca-agent can be run alongside parca-server and parca-ui using Tilt.

```
$ cp -Rf parca-agent parca/tmp/parca-agent

$ cd parca

$ make dev/up

$ tilt up
```

Test your changes by running:
```
$ cd parca && make go/test

$ cd parca-agent && make test
```

<!--
TODO:
    #Internals
        ## Code Structure
-->

# Making a PR

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. If you are not entirely sure about this, you can discuss this on the [PolarSignals Discord](https://discord.gg/knw3u5X9bs) server as well.

Please make sure to update tests as appropriate.

This is roughly what the contribution workflow should look like:

- Create a topic branch from where you want to base your work (usually master).
- Make commits of logical units.
- Make sure the tests pass, and add any new tests as appropriate.
- Make sure your commit messages follow the commit guidelines (see below).
- Push your changes to a topic branch in your fork of the repository.
- Submit a pull request to the original repository.

Thank you for your contributions!


# Commit Guidelines

We follow a rough convention for commit messages that is designed to answer two
questions: what changed and why. The subject line should feature the what and
the body of the commit should describe the why.

When creating a commit with `git`, a sign-off can be added with the [-s option](https://git-scm.com/docs/git-commit#git-commit--s). The sign-off is stored as part of the commit message itself, as a line of the format:

`Signed-off-by: Full Name <email>`

```

scripts: add the test-cluster command

this uses tmux to setup a test cluster that you can easily kill and
start for debugging.

Fixes #38

Signed-off-by: Jasnah Kholin <jasnahkholin@gmail.com>

```

The first line is the subject and should be no longer than 70 characters, the second line is always blank, and other lines should be wrapped at 80 characters. This allows the message to be easier to read on GitHub as well as in various git tools.


