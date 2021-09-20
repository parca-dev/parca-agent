# Contributing Guidelines

<!-- TODO: Add licensing/signing/code of conduct info-->

# Prerequisites


- Linux Kernel version 4.18+
- A source of targets to discover from: Kubernetes or SystemD.

Install the following dependencies:

- Go
- Docker
- LLVM
- Clang
- libbpfcc
- minikube
- kubectl

# Getting Started

Fork and clone the parca-agent and parca repositories on GitHub.

## **Run parca-agent**


Code changes can be tested locally by building parca-agent and running it via systemd. 
The following code snippet profiles the docker daemon via systemd:

``` 
$ cd parca-agent

$ make

$ sudo dist/parca-agent --node=test --systemd-units=docker.service --log-level=debug --kubernetes=false --store-address=localhost:7070 --insecure
```

The generated profiles can be seen at http://localhost:7070 .

## **Working with parca server**
To launch parca-agent locally with the parca server, first copy your parca-agent repository(where you have made changes) to `parca/tmp/`:

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

```
scripts: add the test-cluster command

this uses tmux to setup a test cluster that you can easily kill and
start for debugging.

Fixes #38
```

The first line is the subject and should be no longer than 70 characters, the second line is always blank, and other lines should be wrapped at 80 characters. This allows the message to be easier to read on GitHub as well as in various git tools.


