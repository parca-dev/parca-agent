#!/usr/bin/env bash

# Copyright (c) 2022 The Parca Authors
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

# Creates a local minikube cluster, and deploys the dev env into the cluster
function up() {
  # Spin up local cluster if one isn't running
  if minikube status -p parca-agent; then
    echo "----------------------------------------------------------"
    echo "Dev cluster already running. Skipping minikube cluster creation"
    echo "----------------------------------------------------------"
  else
    ctlptl create registry ctlptl-registry || echo 'Registry already exists'
    # kvm2, hyperkit, hyperv, vmwarefusion, virtualbox, vmware, xhyve
    minikube start -p parca-agent \
      --driver=virtualbox \
      --kubernetes-version=v1.22.3 \
      --cpus=4 \
      --memory=16gb \
      --disk-size=20gb \
      --docker-opt dns=8.8.8.8 \
      --docker-opt default-ulimit=memlock=9223372036854775807:9223372036854775807
  fi

  # Deploy all services into the cluster
  deploy

  echo "Now run \"tilt up\" to start developing!"
}

# Tears down a local minikube cluster
function down() {
  minikube delete -p parca-agent
}

# Deploys the dev env into the minikube cluster
function deploy() {
  # Deploy all generated manifests
  kubectl apply -R -f ./deploy/tilt
}
