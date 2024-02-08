.PHONY: manifestsmanifests: vendor $(shell find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
	rm -rf manifests tilt
	mkdir -p manifests/openshift manifests/kubernetes tilt
	jsonnet --tla-str version="$(VERSION)" -J vendor main.jsonnet -m manifests/kubernetes | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
	awk 'BEGINFILE {print "---"}{print}' manifests/kubernetes/* > manifests/kubernetes/manifest.yaml
	jsonnet --tla-str version="$(VERSION)" -J vendor openshift.jsonnet -m manifests/openshift | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
	awk 'BEGINFILE {print "---"}{print}' manifests/openshift/* > manifests/openshift/manifest.yaml
	jsonnet --tla-str serverVersion="$(SERVER_VERSION)" -J vendor dev.jsonnet -m tilt | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
