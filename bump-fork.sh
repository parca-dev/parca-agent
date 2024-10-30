#!/bin/sh
go mod edit -replace go.opentelemetry.io/ebpf-profiler=github.com/parca-dev/opentelemetry-ebpf-profiler@latest
go mod tidy
