function(version='v0.0.1-alpha.3')
  //  local ns = {
  //    apiVersion: 'v1',
  //    kind: 'Namespace',
  //    metadata: {
  //      name: 'parca',
  //      labels: {
  //        'pod-security.kubernetes.io/enforce': 'privileged',
  //        'pod-security.kubernetes.io/audit': 'privileged',
  //        'pod-security.kubernetes.io/warn': 'privileged',
  //      },
  //    },
  //  };

  local cleanVersion = if std.startsWith(version, 'v') then version[1:] else version;

  local agent = (import 'parca-agent/parca-agent.libsonnet')({
    name: '$name',
    namespace: '$namespace',
    version: cleanVersion,
    image: '$imageRepo:$imageTag',
    stores: ['$remoteStoreAddress'],
    insecure: false,
  });

  {
    ['parca-agent-' + name]: agent[name]
    for name in std.objectFields(agent)
    if agent[name] != null
  }
