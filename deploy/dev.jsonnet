function(serverVersion='v0.4.2')
    local ns = {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: {
        name: 'parca',
      },
    };

    local server = (import 'parca/parca.libsonnet')({
        name: 'parca',
        namespace: ns.metadata.name,
        image: 'ghcr.io/parca-dev/parca:' + serverVersion,
        version: serverVersion,
        replicas: 1,
        corsAllowedOrigins: '*',
        logLevel: 'debug',
    });

    local agent = (import 'parca-agent/parca-agent.libsonnet')({
      name: 'parca-agent',
      namespace: ns.metadata.name,
      version: 'dev',
      image: 'parca.io/parca/parca-agent:dev',
      stores: ['%s.%s.svc.cluster.local:%d' % [server.service.metadata.name, server.service.metadata.namespace, server.config.port]],
      logLevel: 'debug',
      insecure: true,
      insecureSkipVerify: true,
      tempDir: '/tmp',
      podLabelSelector: {
        'app.kubernetes.io/name': 'redpanda',
      },
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
