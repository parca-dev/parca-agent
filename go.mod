module github.com/parca-dev/parca-agent

go 1.18

require (
	github.com/alecthomas/kong v0.6.1
	github.com/aquasecurity/libbpfgo v0.3.0-libbpf-0.8.0
	github.com/cenkalti/backoff/v4 v4.1.3
	github.com/cespare/xxhash/v2 v2.1.2
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be
	github.com/docker/docker v20.10.17+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/go-kit/log v0.2.1
	github.com/goburrow/cache v0.1.4
	github.com/google/pprof v0.0.0-20220829040838-70bd9ae97f40
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ianlancetaylor/demangle v0.0.0-20220517205856-0058ec4f073c
	github.com/keybase/go-ps v0.0.0-20190827175125-91aafc93ba19
	github.com/minio/highwayhash v1.0.2
	github.com/oklog/run v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/parca-dev/parca v0.12.2-0.20220909184107-c0b8ec6c74c7
	github.com/prometheus/client_golang v1.13.0
	github.com/prometheus/common v0.37.0
	github.com/prometheus/prometheus v1.8.2-0.20220315145411-881111fec433
	github.com/rzajac/flexbuf v0.14.0
	github.com/stretchr/testify v1.8.0
	github.com/xyproto/ainur v1.3.0
	golang.org/x/sys v0.0.0-20220915200043-7b5979e65e41
	google.golang.org/grpc v1.49.0
	google.golang.org/protobuf v1.28.1
	k8s.io/api v0.25.1
	k8s.io/apimachinery v0.25.1
	k8s.io/client-go v0.25.1
	k8s.io/cri-api v0.25.1
)

require github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect

require (
	cloud.google.com/go v0.102.0 // indirect
	cloud.google.com/go/compute v1.7.0 // indirect
	cloud.google.com/go/iam v0.3.0 // indirect
	cloud.google.com/go/storage v1.22.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.1.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.1.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.0.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v0.4.1 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.28 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.21 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.5.1 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/aliyun/aliyun-oss-go-sdk v2.2.2+incompatible // indirect
	github.com/aws/aws-sdk-go-v2 v1.16.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.15.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.11.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.1 // indirect
	github.com/aws/smithy-go v1.11.1 // indirect
	github.com/baidubce/bce-sdk-go v0.9.111 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/clbanning/mxj v1.8.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/efficientgo/tools/core v0.0.0-20220817170617-6c25e3b627dd // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/go-delve/delve v1.9.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt v3.2.1+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.1.0 // indirect
	github.com/googleapis/gax-go/v2 v2.4.0 // indirect
	github.com/googleapis/go-type-adapters v1.0.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.11.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/minio/md5-simd v1.1.0 // indirect
	github.com/minio/minio-go/v7 v7.0.23 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mozillazg/go-httpheader v0.2.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nanmu42/limitio v1.0.0 // indirect
	github.com/ncw/swift v1.0.53 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/oracle/oci-go-sdk/v65 v65.13.0 // indirect
	github.com/pkg/browser v0.0.0-20210115035449-ce105d075bb4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/rs/xid v1.2.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/sony/gobreaker v0.5.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tencentyun/cos-go-sdk-v5 v0.7.34 // indirect
	github.com/thanos-io/objstore v0.0.0-20220825160751-a53cb72ffecc // indirect
	go.opencensus.io v0.23.0 // indirect
	go.opentelemetry.io/otel v1.9.0 // indirect
	go.opentelemetry.io/otel/trace v1.9.0 // indirect
	go.uber.org/goleak v1.1.12 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220826154423-83b083e8dc8b // indirect
	golang.org/x/oauth2 v0.0.0-20220822191816-0ebed06d0094 // indirect
	golang.org/x/sync v0.0.0-20220819030929-7fc1605a5dde // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
	google.golang.org/api v0.91.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220822174746-9e6da59bd2fc // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.6 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.70.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1 // indirect
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

// Prometheus v2.32.1
replace github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20211217191541-41f1a8125e66

// required by https://github.com/grpc-ecosystem/grpc-gateway/releases/tag/v2.10.3
replace cloud.google.com/go/storage v1.19.0 => cloud.google.com/go/storage v1.10.0
