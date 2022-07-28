#!/usr/bin/env bash

mkdir -p ./tmp/e2e-dump
cd ./tmp/e2e-dump
kubectl get all -A > ./tmp/e2e-dump/kube-all
kubectl get all -A -o yaml > ./tmp/e2e-dump/kube-all.yaml

list=$(kubectl get pods -A --template '{{range .items}}{{.metadata.namespace}} {{.metadata.name}}{{"\n"}}{{end}}')

IFS=$'\n'

for pod in $list
do
    #depending on logs, this may take a while
    #kubectl logs $pod > $pod.txt
    echo $pod | xargs -n2 sh -c 'kubectl logs --all-containers --ignore-errors --namespace=$0 $1 > $0-$1.logs'
done
