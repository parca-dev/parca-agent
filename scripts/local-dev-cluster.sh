#!/usr/bin/env bash

# Copyright 2022-2024 The Parca Authors
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
#

################################################################################
#
# This script is meant to be run from the root of this project with the Makefile
#
################################################################################

set -euo pipefail

NODE_COUNT=${NODE_COUNT:-1}
RUNTIME=${RUNTIME:-"containerd"} # docker, containerd, cri-o (containerd what we use in prod)

MINIKUBE_PROFILE_NAME="${MINIKUBE_PROFILE_NAME:-parca-agent}"
function mk() {
    minikube -p "${MINIKUBE_PROFILE_NAME}" "$@"
}

ARCH=$(uname -m)
if [[ "${ARCH}" == "x86_64" ]]; then
    ARCH="amd64"
elif [[ "${ARCH}" == "aarch64" ]]; then
    ARCH="arm64"
fi

if [[ "${OSTYPE}" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "${OSTYPE}" == "darwin"* ]]; then
    OS="darwin"
fi

# Creates a local minikube cluster, and deploys the dev env into the cluster
function up() {
    # Spin up local cluster if one isn't running
    if mk status; then
        echo "----------------------------------------------------------"
        echo "Dev cluster already running"
        echo "Skipping minikube cluster creation"
        echo "----------------------------------------------------------"
    else
        # local_registry

        # kvm2, hyperkit, hyperv, vmwarefu1sion, virtualbox, vmware, xhyve
        DRIVER=kvm2
        if [[ "${OS}" == "darwin" ]] && [[ "${ARCH}" == "arm64" ]]; then
            DRIVER=qemu2
        fi
        echo "---------------------------------------------------------------------------------------------"
        echo "Creating minikube cluster with $NODE_COUNT nodes, using driver: $DRIVER and runtime: $RUNTIME"
        echo "---------------------------------------------------------------------------------------------"
        mk start \
            --driver="${DRIVER}" \
            --container-runtime="${RUNTIME}" \
            --nodes="${NODE_COUNT}" \
            --kubernetes-version=stable \
            --cpus=2 \
            --memory=8gb \
            --disk-size=40gb \
            --delete-on-failure \
            --docker-opt dns=8.8.8.8 \
            --docker-opt default-ulimit=memlock=9223372036854775807:9223372036854775807
    fi
    # Switch kubectl to the minikube context
    mk update-context

    trap 'kill $(jobs -p)' SIGINT SIGTERM EXIT

    # Configure registry in minikube
    minikube_registry

    # Deploy all services into the cluster
    deploy

    # Start the Tilt
    tilt up
}

# Tears down a local minikube cluster
function down() {
    mk delete
}

# Deploys the dev env into the minikube cluster
function deploy() {
    echo "----------------------------------------------------------"
    echo "Deploying dev environment"
    echo "----------------------------------------------------------"
    kubectl create namespace parca --dry-run=client -o yaml | kubectl apply -f -
    kubectl label --overwrite ns parca pod-security.kubernetes.io/enforce=privileged
    kubectl apply -R -f ./deploy/tilt || true
    kubectl rollout -n parca status deployment parca
    kubectl port-forward -n parca svc/parca 7070 &
}

function minikube_registry() {
    mk addons enable registry
    kubectl port-forward -n kube-system svc/registry 5000:80 &
}

reg_name='minikube-registry'
reg_port='5000'

# Configures a registry using localhost docker runtime.
function local_registry() {
    echo "----------------------------------------------------------"
    echo "Checking if registry exists/Creating registry"
    echo "----------------------------------------------------------"
    running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
    if [ "${running}" != 'true' ]; then
        docker run \
            -d --restart=always -p "${reg_port}:5000" --name "${reg_name}" \
            registry:2
    fi
}
