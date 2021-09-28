local ns = {
  apiVersion: 'v1',
  kind: 'Namespace',
  metadata: {
    name: 'parca',
  },
};

local agent = (import 'parca-agent/parca-agent.libsonnet')({
  name: 'parca-agent',
  namespace: ns.metadata.name,
  version: 'v0.0.1-alpha.3',
  image: 'ghcr.io/parca-dev/parca-agent:v0.0.1-alpha.3',
  stores: [
    'grpc.polarsignals.com:443',
  ],
  token: '<token>',
  tempDir: '/tmp',
  // Available Options:
  //   samplingRatio: 0.5,
  //   podLabelSelector: {
  //       app: 'my-web-app'
  //   },
});

{
  '0namespace': ns,
} + {
  ['parca-agent-' + name]: agent[name]
  for name in std.objectFields(agent)
  if agent[name] != null
}
