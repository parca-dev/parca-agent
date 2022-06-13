#!/bin/bash

################################################################################
#
# This script is meant to be run from the root of this project
#
################################################################################

set -euo pipefail

function run() {
  # Driver set to virtualbox by default if not specified
  DRIVER=${1-virtualbox}

  minikube_up $DRIVER
  generate_manifests
  deploy
}

# Create local minikube cluster and deploys the dev env for parca and parca agent
function minikube_up(){
  # can be virtualbox, vmwarefusion, kvm2, vmware, none, docker, podman, ssh
  DRIVER=$1

  echo "Spinning up a parca dev cluster"
  minikube start -p parca-e2e \
    --container-runtime=docker \
    --insecure-registry="localhost:5000"\
    --driver=$DRIVER \
    --kubernetes-version=v1.22.3 \
    --cpus=4 \
    --memory=16gb \
    --disk-size=20gb \
    --docker-opt dns=8.8.8.8 \
    --docker-opt default-ulimit=memlock=9223372036854775807:9223372036854775807

  eval $(minikube -p parca-e2e docker-env)
}

# Delete minikube instance
function minikube_down(){
  echo "Deleting parca-e2e cluster"
  minikube delete -p parca-e2e
}

# Configure clusters to run latest commit in Parca agent
function deploy() {
  SERVER_LATEST_VERSION=$(curl -s https://api.github.com/repos/parca-dev/parca/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")' | xargs echo -n)
  echo "Server version: $SERVER_LATEST_VERSION"

  if ! check_ns_parca; then
    kubectl create namespace parca
  fi

  kubectl apply -f https://github.com/parca-dev/parca/releases/download/"$SERVER_LATEST_VERSION"/kubernetes-manifest.yaml
  kubectl -n parca rollout status deployment/parca --timeout=2m

  kubectl apply -f ./manifests/local/manifest-e2e.yaml
  kubectl -n parca rollout status daemonset/parca-agent --timeout=2m

  echo "Connecting to Parca and Parca agent"

  kubectl port-forward -n parca service/parca 7070 &
  kubectl port-forward -n parca $(kubectl get po -n parca | grep parca-agent | awk '{print $1;}') 7071:7071 &
}

function vendor() {
  jb install
}

function check_ns_parca() {
 ns_status=$(kubectl get ns parca)
 if [ $? -ne 0 ]; then
   return 1
 fi
 echo "namespace parca already present"
}

# Build image with latest commit
function generate_manifests() {
  if [ -z ${GITHUB_BRANCH_NAME+x} ]; then
    BRANCH=$(git rev-parse --abbrev-ref HEAD)-
  else
    BRANCH=$(GITHUB_BRANCH_NAME)
  fi

  if [ -z ${GITHUB_SHA+x} ]; then
    COMMIT=$(git describe --no-match --dirty --always --abbrev=8)
  else
    COMMIT=$(echo $(GITHUB_SHA) | cut -c1-8)
  fi

  if [ -z ${RELEASE_TAG+x} ]; then
    VERSION=$(git describe --tags 2>/dev/null || echo '$(BRANCH)$(COMMIT)')
  else
    VERSION=$RELEASE_TAG
  fi

  rm -rf manifests/local
  mkdir -p manifests/local

  jsonnet --tla-str version="$VERSION" -J vendor e2e.jsonnet -m manifests/local | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}'
  awk 'BEGINFILE {print "---"}{print}' manifests/local/* > manifests/local/manifest-e2e.yaml

  GOLANG_BASE=golang:1.18.3-bullseye
  DEBIAN_BASE=debian:bullseye-slim
  LINUX_ARCH=$(uname -p)

  docker build -t localhost:5000/parca-agent:"$VERSION" \
     --build-arg GOLANG_BASE="$GOLANG_BASE" \
     --build-arg DEBIAN_BASE="$DEBIAN_BASE"  \
     --build-arg LINUX_ARCH=$LINUX_ARCH  ./..
}
