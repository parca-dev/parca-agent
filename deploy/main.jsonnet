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
  version: 'dev',
  image: 'ghcr.io/parca-dev/parca-agent:v0.0.1-alpha.1',
  stores: [
    'grpc.polarsignals.com:443',
  ],
  token: 'eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiI4NTc5YzlkZS00YmQzLTQzNzYtYjU3NS00OGExN2QzNGI3OWMiLCJpYXQiOjE2MjYwNzc1NjE5NjA0NDE4NzksImlzcyI6Imh0dHBzOi8vYXBpLnBvbGFyc2lnbmFscy5jb20vIiwianRpIjoiMjJlMjJmODQtZTFjMS00ZGQ1LWExMGItYmYzOGI3MDY0OWMwIiwicHJvamVjdElkIjoiODU3OWM5ZGUtNGJkMy00Mzc2LWI1NzUtNDhhMTdkMzRiNzljIiwidmVyc2lvbiI6IjEuMC4wIiwid3JpdGVQcm9maWxlcyI6dHJ1ZX0.T8XHYuK6IzO2QDs6gJaz5QBMj-GIBRlH6SGbOucrAhf4XDJgXoIWEEoJkXmuv3sQQE44uZ2HaeqvskLhZlWLDQ',
  tempDir: '/tmp',
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
