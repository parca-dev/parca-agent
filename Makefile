.PHONY: all crossbuild build build-debug

all: crossbuild

crossbuild:
	DOCKER_CLI_EXPERIMENTAL="enabled" docker run \
		--rm \
		--privileged \
		-v "/var/run/docker.sock:/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-v "$(GOPATH)/pkg/mod":/go/pkg/mod \
		-w "/__w/parca-agent/parca-agent" \
		docker.io/goreleaser/goreleaser-cross:v1.22.4 \
		release --snapshot --clean --skip=publish --verbose

build:
	go build -o parca-agent -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo

build-debug:
	go build -o parca-agent-debug -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo -gcflags "all=-N -l"
