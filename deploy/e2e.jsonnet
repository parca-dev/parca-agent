function(version='v0.0.1-alpha.3', serverVersion='v0.0.3-alpha.2')
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

  local server = (import 'parca/parca.libsonnet')({
    name: 'parca',
    namespace: ns.metadata.name,
    image: 'ghcr.io/parca-dev/parca:' + self.version,
    version: serverVersion,
    replicas: 1,
    corsAllowedOrigins: '*',
    debugInfodUpstreamServers: ['https://debuginfod.systemtap.org'],
  });

  local agent = (import 'parca-agent/parca-agent.libsonnet')({
    name: 'parca-agent',
    namespace: ns.metadata.name,
    version: version,
    image: 'ghcr.io/parca-dev/parca-agent:' + self.version,
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
    kind: 'List',
    apiVersion: 'v1',
    items:
      [
        ns,
      ] + [
        server[name]
        for name in std.objectFields(server)
        if server[name] != null
      ] + [
        agent[name]
        for name in std.objectFields(agent)
        if agent[name] != null
      ],
  }
