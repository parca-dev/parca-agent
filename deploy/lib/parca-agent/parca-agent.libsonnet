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

  config: {},
  logLevel: 'info',

  token: '',
  insecure: false,
  insecureSkipVerify: false,

  debugInfoUploadDisable: false,
  socketPath: '',

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
          pathPrefix: '/run',
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

  [if std.length((defaults + params).config) > 0 then 'configMap']: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: pa.metadata,
    data: {
      'parca-agent.yaml': std.manifestYamlDoc(pa.config.config),
    },
  },

  daemonSet:
    local c = {
      name: 'parca-agent',
      image: pa.config.image,
      args: [
        '/bin/parca-agent',
        '--log-level=' + pa.config.logLevel,
        '--node=$(NODE_NAME)',
      ] + (
        if (std.length(pa.config.config) > 0) then [
          '--config-path=/etc/parca/parca-agent.yaml',
        ] else []
      ) + (
        if pa.config.token != '' then [
          '--remote-store-bearer-token=%s' % pa.config.token,
        ] else []
      ) + [
        '--remote-store-address=%s' % store
        for store in pa.config.stores
      ] + (
        if pa.config.insecure then [
          '--remote-store-insecure',
        ] else []
      ) + (
        if pa.config.insecureSkipVerify then [
          '--remote-store-insecure-skip-verify',
        ] else []
      ) + (
        if pa.config.debugInfoUploadDisable then [
          '--remote-store-debug-info-upload-disable',
        ] else []
      ) + (
        if pa.config.socketPath != '' then [
          '--container-runtime-socket-path=' + pa.config.socketPath,
        ] else []
      ) + (
        if std.length(pa.config.externalLabels) > 0 then [
          '--metadata-external-label=%s=%s' % [labelName, pa.config.externalLabels[labelName]]
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
      livenessProbe: {
        httpGet: {
          path: '/healthy',
          port: 'http',
        },
      },
      readinessProbe: {
        httpGet: {
          path: '/ready',
          port: 'http',
        },
      },
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
          name: 'boot',
          mountPath: '/boot',
          readOnly: true,
        },
        {
          name: 'proc',
          mountPath: '/proc',
          readOnly: true,
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
      ] + (
        if std.length(pa.config.config) > 0 then [
          {
            name: 'config',
            mountPath: '/etc/parca',
          },
        ] else []
      ),
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
            },
            tolerations: [
              {
                operator: 'Exists',
              },
            ],
            volumes: [
              {
                name: 'tmp',
                emptyDir: {},
              },
              // Needed for reading the container runtime metadata.
              {
                name: 'run',
                hostPath: {
                  path: '/run',
                },
              },
              // Needed for reading kernel configuration.
              {
                name: 'boot',
                hostPath: {
                  path: '/boot',
                },
              },
              // Needed for reading process information.
              {
                name: 'proc',
                hostPath: {
                  path: '/proc',
                },
              },
              // Deprecated by v0.10.0 release. Remove in a couple of releases.
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
              // Needed for reading the pinned eBPF maps and programs.
              {
                name: 'bpffs',
                hostPath: {
                  path: '/sys/fs/bpf',
                },
              },
              // Needed for writing logs from eBPF programs.
              {
                name: 'debugfs',
                hostPath: {
                  path: '/sys/kernel/debug',
                },
              },
            ] + (
              if std.length(pa.config.config) > 0 then [{
                name: 'config',
                configMap: { name: pa.configMap.metadata.name },
              }] else []
            ),
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
