// These are the defaults for this components configuration.
// When calling the function to generate the component's manifest,
// you can pass an object structured like the default to overwrite default values.
local defaults = {
  local defaults = self,
  name: 'parca-agent',
  namespace: error 'must provide namespace',
  version: error 'must provide version',
  image: error 'must provide image',
  stores: ['dnssrv+_grpc._tcp.parca.%s.svc.cluster.local' % defaults.namespace],

  resources: {},
  port: 7071,

  logLevel: 'info',
  tempDir: '',

  token: '',
  insecure: false,
  insecureSkipVerify: false,

  debugInfoDisable: false,

  samplingRatio: 0.0,

  commonLabels:: {
    'app.kubernetes.io/name': 'parca-agent',
    'app.kubernetes.io/instance': defaults.name,
    'app.kubernetes.io/version': defaults.version,
    'app.kubernetes.io/component': 'observability',
  },

  podLabelSelector:: '',
  externalLabels:: {},

  securityContext:: {
    privileged: true,
    readOnlyRootFilesystem: true,
  },

  podMonitor: false,
};

function(params) {
  local pa = self,

  // Combine the defaults and the passed params to make the component's config.
  config:: defaults + params,
  // Safety checks for combined config of defaults and params
  assert std.isObject(pa.config.resources),
  assert std.isBoolean(pa.config.podMonitor),

  metadata:: {
    name: pa.config.name,
    namespace: pa.config.namespace,
    labels: pa.config.commonLabels,
  },

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: pa.metadata,
  },

  clusterRoleBinding: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: pa.metadata,
    subjects: [{
      kind: 'ServiceAccount',
      name: pa.config.name,
      namespace: pa.config.namespace,
    }],
    roleRef: {
      kind: 'ClusterRole',
      name: pa.config.name,
      apiGroup: 'rbac.authorization.k8s.io',
    },
  },

  clusterRole: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRole',
    metadata: pa.metadata,
    rules: [
      {
        apiGroups: [''],
        resources: ['pods'],
        verbs: ['list', 'watch'],
      },
      {
        apiGroups: [''],
        resources: ['nodes'],
        verbs: ['get'],
      },
    ],
  },

  podSecurityPolicy: {
    apiVersion: 'policy/v1beta1',
    kind: 'PodSecurityPolicy',
    metadata: pa.metadata,
    spec: {
      allowPrivilegeEscalation: true,
      allowedCapabilities: ['*'],
      fsGroup: {
        rule: 'RunAsAny',
      },
      runAsUser: {
        rule: 'RunAsAny',
      },
      seLinux: {
        rule: 'RunAsAny',
      },
      supplementalGroups: {
        rule: 'RunAsAny',
      },
      privileged: true,
      hostIPC: true,
      hostNetwork: true,
      hostPID: true,
      hostPorts: [
        {
          max: pa.config.port,
          min: pa.config.port,
        },
      ],
      readOnlyRootFilesystem: true,
      volumes: [
        'configMap',
        'emptyDir',
        'projected',
        'secret',
        'downwardAPI',
        'persistentVolumeClaim',
        'hostPath',
      ],
      allowedHostPaths+: [
        {
          pathPrefix: '/sys',
        },
        {
          pathPrefix: '/lib/modules',
        },
      ],
    },
  },

  role: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'Role',
    metadata: pa.metadata,
    rules: [
      {
        apiGroups: [
          'policy',
        ],
        resourceNames: [
          pa.config.name,
        ],
        resources: [
          'podsecuritypolicies',
        ],
        verbs: [
          'use',
        ],
      },
    ],
  },

  roleBinding: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'RoleBinding',
    metadata: pa.metadata,
    roleRef: {
      apiGroup: 'rbac.authorization.k8s.io',
      kind: 'Role',
      name: pa.role.metadata.name,
    },
    subjects: [
      {
        kind: 'ServiceAccount',
        name: pa.serviceAccount.metadata.name,
      },
    ],
  },

  daemonSet:
    local c = {
      name: 'parca-agent',
      image: pa.config.image,
      args: [
        '/bin/parca-agent',
        '--log-level=' + pa.config.logLevel,
        '--node=$(NODE_NAME)',
        '--kubernetes',
      ] + (
        if pa.config.token != '' then [
          '--bearer-token=%s' % pa.config.token,
        ] else []
      ) + [
        '--store-address=%s' % store
        for store in pa.config.stores
      ] + (
        if pa.config.samplingRatio != 0.0 then [
          '--sampling-ratio=%.1f' % pa.config.samplingRatio,
        ] else []
      ) + (
        if std.length(pa.config.podLabelSelector) > 0 then [
          '--pod-label-selector=%s' % pa.config.podLabelSelector,
        ] else []
      ) + (
        if pa.config.insecure then [
          '--insecure',
        ] else []
      ) + (
        if pa.config.insecureSkipVerify then [
          '--insecure-skip-verify',
        ] else []
      ) + (
        if pa.config.debugInfoDisable then [
          '--debug-info-disable',
        ] else []
      ) + (
        if pa.config.tempDir != '' then [
          '--temp-dir=' + pa.config.tempDir,
        ] else []
      ) + (
        if std.length(pa.config.externalLabels) > 0 then [
          '--external-label=%s=%s' % [labelName, pa.config.externalLabels[labelName]]
          for labelName in std.objectFields(pa.config.externalLabels)
        ] else []
      ),
      securityContext: pa.config.securityContext,
      ports: [
        {
          name: 'http',
          containerPort: pa.config.port,
          hostPort: pa.config.port,
        },
      ],
      volumeMounts: [
        {
          name: 'tmp',
          mountPath: '/tmp',
        },
        {
          name: 'run',
          mountPath: '/run',
        },
        {
          name: 'modules',
          mountPath: '/lib/modules',
        },
        {
          name: 'debugfs',
          mountPath: '/sys/kernel/debug',
        },
        {
          name: 'cgroup',
          mountPath: '/sys/fs/cgroup',
        },
        {
          name: 'bpffs',
          mountPath: '/sys/fs/bpf',
        },
      ],
      env: [
        {
          name: 'NODE_NAME',
          valueFrom: {
            fieldRef: {
              fieldPath: 'spec.nodeName',
            },
          },
        },
      ],
      resources: if pa.config.resources != {} then pa.config.resources else {},
    };

    {
      apiVersion: 'apps/v1',
      kind: 'DaemonSet',
      metadata: pa.metadata,
      spec: {
        selector: {
          matchLabels: {
            [labelName]: pa.config.commonLabels[labelName]
            for labelName in std.objectFields(pa.config.commonLabels)
            if labelName != 'app.kubernetes.io/version'
          },
        },
        template: {
          metadata: {
            labels: pa.config.commonLabels,
          },
          spec: {
            containers: [c],
            hostPID: true,
            serviceAccountName: pa.serviceAccount.metadata.name,
            nodeSelector: {
              'kubernetes.io/os': 'linux',
              'kubernetes.io/arch': 'amd64',
            },
            tolerations: [
              {
                effect: 'NoSchedule',
                operator: 'Exists',
              },
              {
                effect: 'NoExecute',
                operator: 'Exists',
              },
            ],
            volumes: [
              {
                name: 'tmp',
                emptyDir: {},
              },
              {
                name: 'run',
                hostPath: {
                  path: '/run',
                },
              },
              {
                name: 'cgroup',
                hostPath: {
                  path: '/sys/fs/cgroup',
                },
              },
              {
                name: 'modules',
                hostPath: {
                  path: '/lib/modules',
                },
              },
              {
                name: 'bpffs',
                hostPath: {
                  path: '/sys/fs/bpf',
                },
              },
              {
                name: 'debugfs',
                hostPath: {
                  path: '/sys/kernel/debug',
                },
              },
            ],
          },
        },
      },
    },

  [if std.objectHas(params, 'podMonitor') && params.podMonitor then 'podMonitor']: {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'PodMonitor',
    metadata: {
      name: pa.config.name,
      namespace: pa.config.namespace,
      labels: pa.config.commonLabels,
    },
    spec: {
      podMetricsEndpoints: [{
        port: pa.daemonSet.spec.template.spec.containers[0].ports[0].name,
      }],
      selector: {
        matchLabels: pa.daemonSet.spec.template.metadata.labels,
      },
    },
  },
}
