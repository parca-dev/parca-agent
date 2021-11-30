docker_prune_settings(num_builds=5)

## Parca Agent

docker_build(
    'parca.io/parca/parca-agent:dev', '',
     dockerfile='Dockerfile.dev',
     only=['./cmd', './pkg', './3rdparty', './go.mod', './go.sum', './parca-agent.bpf.c', './vmlinux.h', './Makefile'],
)
k8s_yaml('deploy/tilt/parca-agent-daemonSet.yaml')
k8s_resource('parca-agent', port_forwards=[7071])
