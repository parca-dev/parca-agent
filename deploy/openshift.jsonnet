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
    name: 'parca-agent-scc',
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
    name: agent.config.name,
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
  if agent[name] != null
} + {
  'parca-agent-openshift-clusterrole': clusterRole,
  'parca-agent-openshift-clusterrolebinding': clusterRoleBinding,
}
