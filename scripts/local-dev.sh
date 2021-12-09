#!/usr/bin/env bash

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
    FILE=$(pwd)/minikube.iso
    if [ -f "$FILE" ]; then
        echo "$FILE exists."
    else
        echo "$FILE does not exist. Dwonloading..."
        wget https://github.com/eiffel-fl/minikube/releases/download/v42-prerelease/minikube-5.10.iso
        mv minikube-5.10.iso minikube.iso
    fi
    # kvm2, hyperkit, hyperv, vmwarefusion, virtualbox, vmware, xhyve
    minikube start -p parca-agent \
      --driver=kvm2 \
      --iso-url=file://$(pwd)/minikube.iso \
      --kubernetes-version=v1.22.3 \
      --cpus=12 \
      --memory=40gb \
      --disk-size=120gb \
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
