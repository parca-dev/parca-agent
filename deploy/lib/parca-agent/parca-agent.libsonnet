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

  logLevel: 'info',
  tempDir: '',

  token: '',
  insecure: false,
  insecureSkipVerify: false,

  samplingRatio: 0.0,

  commonLabels:: {
    'app.kubernetes.io/name': 'parca-agent',
    'app.kubernetes.io/instance': defaults.name,
    'app.kubernetes.io/version': defaults.version,
    'app.kubernetes.io/component': 'observability',
  },

  podLabelSelector:: {},

  securityContext:: {
    privileged: true,
  },
};

function(params) {
  local pa = self,

  // Combine the defaults and the passed params to make the component's config.
  config:: defaults + params,

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: pa.config.name,
      namespace: pa.config.namespace,
      labels: pa.config.commonLabels,
    },
  },

  clusterRoleBinding: {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'ClusterRoleBinding',
    metadata: {
      name: pa.config.name,
    },
    subjects: [{
      kind: 'ServiceAccount',
      name: pa.config.name,
      namespace: pa.config.namespace,
    }],
    roleRef: {
      kind: 'ClusterRole',
      name: 'cluster-admin',
      apiGroup: 'rbac.authorization.k8s.io',
    },
  },

  daemonSet:
    local c = {
      name: 'parca-agent',
      image: pa.config.image,
      imagePullPolicy: 'Always',
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
          '--pod-label-selector=%s=%s' % [labelName, pa.config.podLabelSelector[labelName]]
          for labelName in std.objectFields(pa.config.podLabelSelector)
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
        if pa.config.tempDir != '' then [
          '--temp-dir=' + pa.config.tempDir,
        ] else []
      ),
      securityContext: pa.config.securityContext,
      volumeMounts: [
        {
          name: 'root',
          mountPath: '/host/root',
          readOnly: true,
        },
        {
          name: 'proc',
          mountPath: '/host/proc',
          readOnly: true,
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
        {
          name: 'localtime',
          mountPath: '/etc/localtime',
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
    };

    {
      apiVersion: 'apps/v1',
      kind: 'DaemonSet',
      metadata: {
        name: pa.config.name,
        namespace: pa.config.namespace,
        labels: pa.config.commonLabels,
      },
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
                name: 'root',
                hostPath: {
                  path: '/',
                },
              },
              {
                name: 'proc',
                hostPath:
                  { path: '/proc' },
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
              {
                name: 'localtime',
                hostPath: {
                  path: '/etc/localtime',
                },
              },
            ],
          },
        },
      },
    },
}
