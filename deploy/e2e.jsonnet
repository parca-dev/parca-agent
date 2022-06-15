function(version='v0.0.1-alpha.3')
  local ns = {
    apiVersion: 'v1',
    kind: 'Namespace',
    metadata: {
      name: 'parca',
      labels: {
        'pod-security.kubernetes.io/enforce': 'privileged',
        'pod-security.kubernetes.io/audit': 'privileged',
        'pod-security.kubernetes.io/warn': 'privileged',
      },
    },
  };

  local agent = (import 'parca-agent/parca-agent.libsonnet')({
    name: 'parca-agent',
    namespace: ns.metadata.name,
    version: version,
    image: 'localhost:5000/parca-agent:' + version,
    // This assumes there's a running parca in the cluster.
    stores: ['parca.parca.svc.cluster.local:7070'],
    insecure: true,
    insecureSkipVerify: true,
    //   token: "<token>",
    //   stores: [
    //     'grpc.polarsignals.com:443',
    //   ],
    tempDir: '/tmp',
    // Available Options:
    //   samplingRatio: 0.5,
    //   Docs for usage of Label Selector
    //   https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    //   podLabelSelector: 'app=my-web-app,version=v1',
  });

  {
    '0namespace': ns,
  } + {
    ['parca-agent-' + name]: agent[name]
    for name in std.objectFields(agent)
    if agent[name] != null
  }
