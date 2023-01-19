# Architectural Decision Records (ADRs)

> An Architectural Decision (AD) is a justified software design choice that addresses a functional or non-functional requirement that is architecturally significant.

> An Architecturally Significant Requirement (ASR) is a requirement that has a measurable effect on a software system’s architecture and quality.

> An Architectural Decision Record (ADR) captures a single AD and its rationale; the collection of ADRs created and maintained in a project constitute its decision log.

> All these are within the topic of Architectural Knowledge Management (AKM), but ADR usage can be extended to design and other decisions (“any decision record”).

Check [https://adr.github.io/](https://adr.github.io/) for further information.

## Useful links

- https://www.thoughtworks.com/en-us/radar/techniques/lightweight-architecture-decision-records

- https://github.com/joelparkerhenderson/architecture-decision-record

- https://adr.github.io/madr/

## Quick start

Just copy the `template.md` and rename it with your proposal. To better order we enumerate them. e. g. `001-ebpf-profiling.md`.

### Using the CLI (because why not?)

#### Installing `adr` helper tool

Go to the [releases page](https://github.com/marouni/adr/releases) and grab one of the binaries that correspond to your platform.

You can install it directly using:
```bash
go install github.com/marouni/adr@latest
```

#### Initializing `adr`

Before creating any new ADR you need to choose a folder that will host your ADRs and use the `init` sub-command to initialize the configuration:

```bash
adr init docs/adr
```

This will create a folder called `.adr` in your user home. Then you can copy the project specific `template.md` to that folder.

```bash
cp -f docs/adr/template.md ~/.adr/template.md
```

#### Creating a new ADR

As simple as:
```bash
adr new my awesome proposition
```
this will create a new numbered ADR in your ADR folder: `xxx-my-new-awesome-proposition.md`.

Next, just open the file in your preferred markdown editor and start writing your ADR.
