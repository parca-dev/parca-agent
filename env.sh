#! /usr/bin/env bash
set -euo pipefail

# renovate: datasource=go depName=github.com/brancz/gojsontoyaml
GOJSONTOYAML_VERSION='v0.1.0'
go install "github.com/brancz/gojsontoyaml@${GOJSONTOYAML_VERSION}"

# renovate: datasource=go depName=github.com/google/go-jsonnet
JSONNET_VERSION='v0.18.0'
go install "github.com/google/go-jsonnet/cmd/jsonnet@${JSONNET_VERSION}"
go install "github.com/google/go-jsonnet/cmd/jsonnetfmt@${JSONNET_VERSION}"

# renovate: datasource=go depName=github.com/jsonnet-bundler/jsonnet-bundler
JB_VERSION='v0.5.1'
go install "github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@${JB_VERSION}"

# renovate: datasource=go depName=github.com/campoy/embedmd
EMBEDMD_VERSION='v2.0.0'
go install "github.com/campoy/embedmd/v2@${EMBEDMD_VERSION}"

# renovate: datasource=go depName=mvdan.cc/gofumpt
GOFUMPT_VERSION='v0.3.1'
go install "mvdan.cc/gofumpt@${GOFUMPT_VERSION}"

# renovate: datasource=go depName=github.com/golangci/golangci-lint
GOLANGCI_LINT_VERSION='v1.48.0'
go install "github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
