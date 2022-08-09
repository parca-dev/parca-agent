# Parca Agent Snap

This directory contains files used to build the [Parca Agent](https://parca.dev) snap.

## Parca Agent App

The snap provides a base `parca-agent` app, which can be executed as per the upstream
documentation.

You can start Parca Agent manually like so:

```bash
# Install from the 'edge' channel
$ sudo snap install parca-agent --channel edge

# Start the agent with simple defaults for testing
parca-agent --node="foobar" --store-address="localhost:7070" --insecure
```

## Parca Agent Service

Additionally, the snap provides a service for Parca Agent with a limited set of configuration
options. You can start the service like so:

```bash
$ snap start parca-agent
```

There are a small number of config options:

| Name            | Valid Options                    | Default          | Description                                                             |
| :-------------- | :------------------------------- | :--------------- | :---------------------------------------------------------------------- |
| `node`          | Any string                       | `$(hostname)`    | Name node the process is running on.                                    |
| `log-level`     | `error`, `warn`, `info`, `debug` | `info`           | Log level for Parca                                                     |
| `http-address`  | Any string                       | `:7071`          | Address for HTTP server to bind to                                      |
| `store-address` | Any string                       | `localhost:7071` | gRPC address to send profiles and symbols to.                           |
| `insecure`      | `true`, `false`                  | `false`          | Send gRPC requests via plaintext instead of TLS.                        |
| `kubernetes`    | `true`, `false`                  | `false`          | Discover containers running on this node and profile them automatically |

Config options can be set with `sudo snap set parca-agent <option>=<value>`
