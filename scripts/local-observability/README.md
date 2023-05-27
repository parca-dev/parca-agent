# Local Setup

This component uses `docker-compose` and by default runs against the `docker.io/otel/opentelemetry-collector-contrib:latest` image.

Run using `docker-compose up -d`

```shell
docker-compose up -d
```

This exposes the following backends:

- Jaeger at http://0.0.0.0:16686
- Prometheus at http://0.0.0.0:9090

Notes:

- It may take some time for the application metrics to appear on the Prometheus dashboard;

## Metrics

This is a minimal metrics monitoring setup with Prometheus.

## Tracing

This is a minimal local tracing setup with OpenTelemetry and Jaeger based on https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/examples/demo

Once you've started the setup with `docker-compose up -d` you can run Parca with the added flag:

```bash
./bin/parca-agent --otlp-address=127.0.0.1:4317
```

or use [`local-run-with-tracing.sh`](../local-run-with-tracing.sh).

Now check for traces on http://localhost:16686.
