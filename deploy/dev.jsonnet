function(serverVersion='v0.4.2')
  local ns = {
    apiVersion: 'v1',
    kind: 'Namespace',
    metadata: {
      name: 'parca',
      labels: {
        'pod-security.kubernetes.io/enforce': 'privileged',
      },
    },
  };

  local server = (import 'parca/parca.libsonnet')({
    name: 'parca',
    namespace: ns.metadata.name,
    image: 'ghcr.io/parca-dev/parca:' + serverVersion,
    version: serverVersion,
    replicas: 1,
    corsAllowedOrigins: '*',
    serviceMonitor: true,
    debugInfodUpstreamServers: ['https://debuginfod.systemtap.org'],
  });

  local agent = (import 'parca-agent/parca-agent.libsonnet')({
    name: 'parca-agent',
    namespace: ns.metadata.name,
    version: 'dev',
    image: 'localhost:5000/parca-agent:dev',
    stores: ['%s.%s.svc.cluster.local:%d' % [server.service.metadata.name, server.service.metadata.namespace, server.config.port]],
    logLevel: 'debug',
    insecure: true,
    insecureSkipVerify: true,
    profilingCPUSamplingFrequency: 97,  // Better it to be a prime number.
    podMonitor: true,
    debuginfoUploadTimeout: '2m',
    // podSecurityPolicy: true,
    // config: {
    //   relabel_configs: [
    //     {
    //       source_labels: ['pid'],
    //       regex: '.*',
    //       action: 'keep',
    //     },
    //   ],
    // },
    //    debuginfoUploadDisable: true,
    //    containerRuntimeSocketPath: '/run/docker.sock',
  });

  {
    '0namespace': ns,
  } + {
    ['parca-server-' + name]: server[name]
    for name in std.objectFields(server)
    if server[name] != null
  } + {
    ['parca-agent-' + name]: agent[name]
    for name in std.objectFields(agent)
    if agent[name] != null
  }
