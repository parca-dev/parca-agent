// These are the defaults for this components configuration.
// When calling the function to generate the component's manifest,
// you can pass an object structured like the default to overwrite default values.
local defaults = {
  local defaults = self,
  name: 'parca-agent',
  namespace: error 'must provide namespace',
  version: error 'must provide version',
  image: error 'must provide image',
  stores: ['dnssrv+_grpc._tcp.parca'],

  resources: {},
  port: 7071,

  config: {
    relabel_configs: [{
      source_labels: ['__meta_process_executable_compiler'],
      target_label: 'compiler',
    }, {
      source_labels: ['__meta_system_kernel_machine'],
      target_label: 'arch',
    }, {
      source_labels: ['__meta_system_kernel_release'],
      target_label: 'kernel_version',
    }, {
      source_labels: ['__meta_kubernetes_namespace'],
      target_label: 'namespace',
    }, {
      source_labels: ['__meta_kubernetes_pod_name'],
      target_label: 'pod',
    }, {
      source_labels: ['__meta_kubernetes_pod_container_name'],
      target_label: 'container',
    }, {
      source_labels: ['__meta_kubernetes_pod_container_image'],
      target_label: 'container_image',
    }, {
      source_labels: ['__meta_kubernetes_node_label_topology_kubernetes_io_region'],
      target_label: 'region',
    }, {
      source_labels: ['__meta_kubernetes_node_label_topology_kubernetes_io_zone'],
      target_label: 'zone',
    }, {
      action: 'labelmap',
      regex: '__meta_kubernetes_pod_label_(.+)',
      replacement: '${1}',
    }, {
      action: 'labeldrop',
      regex: 'apps_kubernetes_io_pod_index|controller_revision_hash|statefulset_kubernetes_io_pod_name|pod_template_hash',

    }],
  },
  logLevel: 'info',
  socketPath: '',

  profilingDuration: '',
  profilingCPUSamplingFrequency: '',

  token: '',
  insecure: false,
  insecureSkipVerify: false,

  metadataDisableCaching: false,

  debuginfoUploadDisable: false,
  debuginfoStrip: true,

  hostDbusSystem: true,
  hostDbusSystemSocket: '/var/run/dbus/system_bus_socket',

  commonLabels:: {
    'app.kubernetes.io/name': 'parca-agent',
    'app.kubernetes.io/instance': defaults.name,
    'app.kubernetes.io/version': defaults.version,
    'app.kubernetes.io/component': 'observability',
  },

  externalLabels:: {},

  // Container level security context.
  securityContext: {
    privileged: true,
    allowPrivilegeEscalation: true,
    capabilities: {
      add: ['SYS_ADMIN'],  // 'BPF', 'PERFMON'
    },
  },

  podMonitor: false,
  podSecurityPolicy: false,
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
        // http-address optionally specifies the TCP address for the server to listen on, in the form "host:port".
        '--http-address=' + ':' + pa.config.port,
        '--node=$(NODE_NAME)',
      ] + (
        if (std.length(pa.config.config) > 0) then [
          '--config-path=/etc/parca-agent/parca-agent.yaml',
        ] else []
      ) + (
        if pa.config.logLevel != 'info' then [
          '--log-level=' + pa.config.logLevel,
        ] else []
      ) + (
        if pa.config.profilingDuration != '' then [
          '--profiling-duration=%s' % pa.config.profilingDuration,
        ] else []
      ) + (
        if pa.config.profilingCPUSamplingFrequency != '' then [
          '--profiling-cpu-sampling-frequency=%s' % pa.config.profilingCPUSamplingFrequency,
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
        if pa.config.debuginfoUploadDisable then [
          '--debuginfo-upload-disable',
        ] else []
      ) + (
        if !pa.config.debuginfoStrip then [
          '--debuginfo-strip=false',
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
      ) + (
        if pa.config.metadataDisableCaching then [
          '--metadata-disable-caching',
        ] else []
      ),
      // Container level security context.
      securityContext: pa.config.securityContext,
      ports: [
        {
          name: 'http',
          containerPort: pa.config.port,
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
          name: 'boot',
          mountPath: '/boot',
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
        if std.length(pa.config.config) > 0 then [{
          name: 'config',
          mountPath: '/etc/parca-agent',
        }] else []
      ) + (
        if pa.config.hostDbusSystem then [{
          name: 'dbus-system',
          mountPath: '/var/run/dbus/system_bus_socket',
        }] else []
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
            // Pod level security context.
            securityContext: {
              seccompProfile: {
                type: 'RuntimeDefault',
              },
            },
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
            ) + (
              if pa.config.hostDbusSystem then [{
                name: 'dbus-system',
                hostPath: {
                  path: pa.config.hostDbusSystemSocket,
                },
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

  [if std.objectHas(params, 'podSecurityPolicy') && params.podSecurityPolicy then 'podSecurityPolicy']: {
    apiVersion: 'policy/v1',
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
          pathPrefix: '/boot',
        },
        {
          pathPrefix: '/var/run/dbus',
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

  [if std.objectHas(params, 'podSecurityPolicy') && params.podSecurityPolicy then 'role']: {
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

  [if std.objectHas(params, 'podSecurityPolicy') && params.podSecurityPolicy then 'roleBinding']: {
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
}
