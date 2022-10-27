#!/usr/bin/env bash

# Copyright 2022 The Parca Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################################################################################
#
# This script is meant to be run from the root of this project
#
################################################################################

set -euox pipefail

function dump_deploy_status() {
    kubectl get all --all-namespaces

    echo ">>> Retrieving Parca logs..."
    kubectl logs --namespace='parca' --selector='app.kubernetes.io/name=parca'

    echo ">>> Retrieving Parca Agent logs..."
    kubectl logs --namespace='parca' --selector='app.kubernetes.io/name=parca-agent'
}

function run() {
    # Driver set to virtualbox by default if not specified
    DRIVER=${1-virtualbox}
    VERSION=$2

    minikube_up "$DRIVER"
    generate_manifests "$VERSION"
    deploy
}

# Create local minikube cluster and deploys the dev env for parca and parca agent
function minikube_up() {
    # can be virtualbox, vmwarefusion, kvm2, vmware, none, docker, podman, ssh
    DRIVER=$1
    local ARGS=()

    if [[ "${DRIVER}" == "docker" ]]; then
        ARGS+=(--mount --mount-string=/boot:/boot:ro)
    fi

    echo "Spinning up a parca dev cluster"
    minikube start -p parca-e2e \
        --container-runtime=docker \
        --insecure-registry="localhost:5000" \
        --driver="$DRIVER" \
        --feature-gates=EphemeralContainers=true \
        --kubernetes-version=v1.22.3 \
        --docker-opt dns=8.8.8.8 \
        --docker-opt default-ulimit=memlock=9223372036854775807:9223372036854775807 \
        "${ARGS[@]}"

    eval "$(minikube -p parca-e2e docker-env)"
}

# Delete minikube instance
function minikube_down() {
    echo "Deleting parca-e2e cluster"
    minikube delete -p parca-e2e
}

# Configure clusters to run latest commit in Parca agent
function deploy() {
    echo "fetching parca binary"
    ### FIXME: Until release of 0.13.1, latest Parca manifest is broken
    ### https://github.com/parca-dev/parca/pull/1989
    # SERVER_LATEST_VERSION=$(git -c 'versionsort.suffix=-' ls-remote --tags --refs --sort='v:refname' https://github.com/parca-dev/parca.git 'v*.*.*' | tail -1 | cut -d/ -f3)
    SERVER_LATEST_VERSION=v0.12.1
    echo "Server version: $SERVER_LATEST_VERSION"

    #AGENT_LATEST_VERSION=$(curl -sSf https://api.github.com/repos/parca-dev/parca-agent/releases/latest | jq -r .tag_name)

    trap dump_deploy_status EXIT

    kubectl create namespace parca

    kubectl apply -f https://github.com/parca-dev/parca/releases/download/"$SERVER_LATEST_VERSION"/kubernetes-manifest.yaml
    kubectl -n parca rollout status deployment/parca --timeout=2m

    #kubectl apply -f https://github.com/parca-dev/parca-agent/releases/download/"$AGENT_LATEST_VERSION"/kubernetes-manifest.yaml
    kubectl apply -f ./manifests/local/
    kubectl -n parca rollout status daemonset/parca-agent --timeout=2m

    echo "Connecting to Parca and Parca agent"

    sleep 300
}

# Build image with latest commit
function generate_manifests() {
    VERSION=$1

    rm -rf manifests/local
    mkdir -p manifests/local

    make vendor
    jsonnet --tla-str version="$VERSION" -J vendor e2e.jsonnet -m manifests/local | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}'
}
