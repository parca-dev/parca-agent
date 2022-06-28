docker_prune_settings(num_builds=5)

## Parca Agent

docker_build(
    'localhost:5000/parca-agent:dev', '',
     dockerfile='Dockerfile.dev',
     only=[
         './3rdparty',
         './Makefile',
         './bpf',
         './cmd',
         './go.mod',
         './go.sum',
         './internal',
         './pkg',
         './rust-toolchain.toml'
     ],
)

# Build directly in minikube
# custom_build(
#     'localhost:5000/parca-agent:dev',
#     'minikube -p parca-agent image build -f Dockerfile.dev -t $EXPECTED_REF .',
#     [
#          './3rdparty',
#          './Makefile',
#          './bpf',
#          './cmd',
#          './go.mod',
#          './go.sum',
#          './internal',
#          './pkg',
#          './rust-toolchain.toml'
#     ],
#     skips_local_docker=True,
# )


k8s_yaml('deploy/tilt/parca-agent-daemonSet.yaml')
k8s_resource('parca-agent', port_forwards=[7071])
