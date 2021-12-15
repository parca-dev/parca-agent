docker_prune_settings(num_builds=2)

# allow_k8s_contexts('admin@k8s-festive-perlman')
# default_registry('ttl.sh/tilt-parca-dev')

## Parca Agent

docker_build(
    'parca.io/parca/parca-agent:dev', '',
     dockerfile='Dockerfile.dev',
     only=['./cmd', './pkg', './3rdparty', './go.mod', './go.sum', './bpf', './Makefile'],
)
k8s_yaml('deploy/tilt/parca-agent-daemonSet.yaml')
k8s_resource('parca-agent', port_forwards=[7071, 40000])
