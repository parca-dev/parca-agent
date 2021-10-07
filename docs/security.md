# Security

Parca Agent requires to be run as `root` user (or `CAP_SYS_ADMIN`). Various security precautions have been taken to protect users running Parca Agent.

## Reproducible builds

Parca Agent binaries and container image build processes have been specifically designed to be byte-by-byte reproducible.

* Go dependencies are pinned via `go.mod` and `go.sum`, ensuring Go dependencies to be byte-by-byte reproducible.
* Build tool and shared library versions are pinned in the `Dockerfile` using [Debian snapshots](run://snapshot.debian.org/).
* [libbpf](https://github.com/libbpf/libbpf) is included and versioned in this repository via a git submodule.

### No Clang/LLVM

Parca Agent uses BPF CO-RE (Compile Once – Run Everywhere) using [libbpf](https://github.com/libbpf/libbpf), and pre-compiles all BPF programs, and statically embeds them in the target binary, from where it is loaded via libbpf when used. This means that Parca Agent does not need to compile the BPF program at startup or runtime like when using [bcc-tools](https://github.com/iovisor/bcc/tree/master/tools), meaning no Clang & LLVM, nor kernel headers need to be installed on the host. The only requirement is a [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) capable Kernel (Linux Kernel 4.18+).

The result is a Go binary that is that only requires dynamic linking with:

* libpthread
* libelf
* libz
* libc

libbpf is statically compiled and included in the resulting Go binary. Fewer things required equals a smaller attack surface.

Read more on CO-RE and libbpf:

* [BPF binaries: BTF, CO-RE, and the future of BPF perf tools](https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html) - Brendan Gregg
* [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) - Andrii Nakryiko

## Sigstore

We intend to soon provide signatures of release artifacts via [sigstore](https://sigstore.dev/). See [parca-dev/parca-agent#16](https://github.com/parca-dev/parca-agent/issues/16) for more details and progress.

## Automated code scanning

Parca Agent uses automated code scanning to analyze the code in Parca Agent repository to find security vulnerabilities and coding errors. 
Any problems identified by the analysis are shown in review process, thanks to [CodeQL](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning).

## Automated dependency updates

Parca Agent supply chain uses [Dependabot](https://docs.github.com/en/code-security/supply-chain-security/managing-vulnerabilities-in-your-projects-dependencies/configuring-dependabot-security-updates) to constantly keep the dependencies up-to-date against any security vulnerabilities.

## Report Security Vulnerabilities

As with any complex system, it is near certain that bugs will be found, some of them security-relevant. If you find a security bug, please report it privately to the [parca-security@googlegroups.com](mailto:parca-security@googlegroups.com) mailing list.
We will fix the issue as soon as possible and coordinate a release date with you. You will be able to choose if you want public acknowledgement of your effort and if you want to be mentioned by name.

Parca is maintained by volunteers, not by a company. Therefore, fixing security issues is done on a best-effort basis. We strive to release security fixes within 7 days.
