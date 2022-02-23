docker_prune_settings(num_builds=5)

## Parca Agent

docker_build(
    'parca.io/parca/parca-agent:dev', '',
     dockerfile='Dockerfile.dev',
     only=[
         './3rdparty',
         './Makefile',
         './cmd',
         './go.mod',
         './go.sum',
         './internal',
         './parca-agent.bpf.c',
         './pkg',
         './vmlinux.h',
     ],
)
k8s_yaml('deploy/tilt/parca-agent-daemonSet.yaml')
k8s_resource('parca-agent', port_forwards=[7071])
