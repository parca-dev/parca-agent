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
    image: 'ghcr.io/parca-dev/parca-agent:' + version,
    // This assumes there's a running parca in the cluster.
    stores: ['parca.parca.svc.cluster.local:7070'],
    insecure: true,
    insecureSkipVerify: true,
    //   token: "<token>",
    //   stores: [
    //     'grpc.polarsignals.com:443',
    //   ],
    tempDir: 'tmp',
    securityContext: {
      capabilities: {
        add: ['SYS_ADMIN'],
      },
      privileged: true,
      runAsUser: 0,
    },
    // Available Options:
    //   samplingRatio: 0.5,
    //   podLabelSelector: {
    //       app: 'my-web-app'
    //   },
  });

  local clusterRole = {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: {
      name: agent.config.name + '-scc',
    },
    rules: [{
      apiGroups: ['security.openshift.io'],
      resourceNames: ['privileged'],
      resources: ['securitycontextconstraints'],
      verbs: ['use'],
    }],
  };

  local clusterRoleBinding = {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: {
      name: agent.config.name + '-scc',
      namespace: agent.config.namespace,
    },
    subjects: [{
      kind: 'ServiceAccount',
      name: agent.config.name,
      namespace: agent.config.namespace,
    }],
    roleRef: {
      kind: 'ClusterRole',
      name: clusterRole.metadata.name,
      apiGroup: 'rbac.authorization.k8s.io',
    },
  };

  {
    '0namespace': ns,
  } + {
    ['parca-agent-' + name]: agent[name]
    for name in std.objectFields(agent)
    if agent[name] != null && name != 'podSecurityPolicy'
  } + {
    'parca-agent-openshift-clusterrole': clusterRole,
    'parca-agent-openshift-clusterrolebinding': clusterRoleBinding,
  }
