# Documentation

This folder collects the documentation for the [Parca Agent](https://github.com/parca-dev/parca-agent). It targets the developers and maintainers as the audience. For user documentation, please check out [the website](https://parca.dev).

## Folder Structure

We have two special folders (`adr` and `website`). The other folders are for documenting a specific concept. e. g. [Native Stack Unwinding](./native-stack-walking/).

### `adr`

Contains `Architectural Decision Records`. See [README.md](./adr/README.md) for further information.

### `website`

Contains the documents that are going to be synchronized to the [website](https://parca.dev).

You can find the repository for the documentation section of the website in [here](https://github.com/parca-dev/docs).

Check [`Makefile`](https://github.com/parca-dev/docs/blob/main/Makefile) for the specific script that does the sync. This is a manual process so you need to run the corresponding action on the `docs` repository.
