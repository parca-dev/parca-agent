#!/bin/sh
go mod edit -replace github.com/open-telemetry/opentelemetry-ebpf-profiler=github.com/parca-dev/opentelemetry-ebpf-profiler@latest
go mod tidy
