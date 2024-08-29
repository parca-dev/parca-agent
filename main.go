package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	debuginfogrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/debuginfo/v1alpha1/debuginfov1alpha1grpc"
	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	telemetrygrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/telemetry/v1alpha1/telemetryv1alpha1grpc"
	telemetrypb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/telemetry/v1alpha1"
	"github.com/apache/arrow/go/v16/arrow/memory"
	"github.com/armon/circbuf"
	"github.com/common-nighthawk/go-figure"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	otelreporter "github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/times"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracehandler"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer"
	tracertypes "github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer/types"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promconfig "github.com/prometheus/common/config"
	"github.com/prometheus/prometheus/model/relabel"
	log "github.com/sirupsen/logrus"
	"github.com/tklauser/numcpus"
	"github.com/zcalusic/sysinfo"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/analytics"
	"github.com/parca-dev/parca-agent/config"
	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/reporter"
)

var (
	version string
	commit  string
	date    string
	goArch  string
)

type buildInfo struct {
	GoArch, GoOs, VcsRevision, VcsTime string
	VcsModified                        bool
}

func fetchBuildInfo() (*buildInfo, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("can't read the build info")
	}

	buildInfo := buildInfo{}

	for _, setting := range bi.Settings {
		key := setting.Key
		value := setting.Value

		switch key {
		case "GOARCH":
			buildInfo.GoArch = value
		case "GOOS":
			buildInfo.GoOs = value
		case "vcs.revision":
			buildInfo.VcsRevision = value
		case "vcs.time":
			buildInfo.VcsTime = value
		case "vcs.modified":
			buildInfo.VcsModified = value == "true"
		}
	}

	return &buildInfo, nil
}

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() flags.ExitCode {
	ctx := context.Background()

	// Fetch build info such as the git revision we are based off
	buildInfo, err := fetchBuildInfo()
	if err != nil {
		fmt.Println("failed to fetch build info: %w", err) //nolint:forbidigo
		os.Exit(1)
	}

	if commit == "" {
		commit = buildInfo.VcsRevision
	}
	if date == "" {
		date = buildInfo.VcsTime
	}
	if goArch == "" {
		goArch = buildInfo.GoArch
	}

	f, err := flags.Parse()
	if err != nil {
		log.Errorf("Failed to parse flags: %v", err)
		return flags.ExitParseError
	}

	runtime.SetBlockProfileRate(f.BlockProfileRate)
	runtime.SetMutexProfileFraction(f.MutexProfileFraction)

	if f.Version {
		fmt.Printf("parca-agent, version %s (commit: %s, date: %s), arch: %s\n", version, commit, date, goArch) //nolint:forbidigo
		return flags.ExitSuccess
	}

	if code := f.Validate(); code != flags.ExitSuccess {
		return code
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(
			collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll),
		),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Initialize tracing.
	var (
		exporter flags.Exporter
		tp       trace.TracerProvider = noop.NewTracerProvider()
	)
	if f.OTLP.Address != "" {
		var err error

		exporter, err = flags.NewExporter(f.OTLP.Exporter, f.OTLP.Address)
		if err != nil {
			log.Errorf("failed to create tracing exporter: %v", err)
		}
		// NewExporter always returns a non-nil exporter and non-nil error.
		tp, err = flags.NewProvider(ctx, version, exporter)
		if err != nil {
			log.Errorf("failed to create tracing provider: %v", err)
		}
	}

	grpcConn, err := f.RemoteStore.WaitGrpcEndpoint(ctx, reg, tp)
	if err != nil {
		log.Errorf("failed to connect to server: %v", err)
		return flags.ExitFailure
	}
	defer grpcConn.Close()

	presentCores, err := numcpus.GetPresent()
	if err != nil {
		return flags.Failure("Failed to read CPU file: %v", err)
	}

	promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Name: "parca_agent_num_cpu",
		Help: "Number of CPUs",
	}).Set(float64(presentCores))

	if !f.Telemetry.DisablePanicReporting && len(f.RemoteStore.Address) > 0 {
		// Spawn ourselves in a child process but disabling telemetry in it.
		argsCopy := make([]string, 0, len(os.Args)+1)
		argsCopy = append(argsCopy, os.Args...)
		argsCopy = append(argsCopy, "--telemetry-disable-panic-reporting")

		buf, _ := circbuf.NewBuffer(f.Telemetry.StderrBufferSizeKb)

		cmd := exec.Command(argsCopy[0], argsCopy[1:]...) //nolint:gosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(os.Stderr, buf)

		// Run garbage collector to minimize the amount of memory that the parent
		// telemetry process uses.
		runtime.GC()
		err := cmd.Run()
		if err != nil {
			log.Error("======================= unexpected error =======================")
			log.Error(buf.String())
			log.Error("================================================================")
			log.Error("about to report error to server")

			telemetryClient := telemetrygrpc.NewTelemetryServiceClient(grpcConn)
			_, err = telemetryClient.ReportPanic(context.Background(), &telemetrypb.ReportPanicRequest{
				Stderr:   buf.String(),
				Metadata: getTelemetryMetadata(int(presentCores)),
			})
			if err != nil {
				log.Errorf("failed to call ReportPanic(): %v", err)
				return flags.ExitFailure
			}

			log.Info("report sent successfully")

			if exiterr, ok := err.(*exec.ExitError); ok { //nolint: errorlint
				return flags.ExitCode(exiterr.ExitCode())
			}

			return flags.ExitParseError
		}

		return flags.ExitSuccess
	}

	intro := figure.NewColorFigure("Parca Agent ", "roman", "yellow", true)
	intro.Print()

	// Context to drive main goroutine and the Tracer monitors.
	mainCtx, mainCancel := signal.NotifyContext(ctx,
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if f.HTTPAddress != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			//nolint:gosec
			if err = http.ListenAndServe(f.HTTPAddress, mux); err != nil {
				log.Errorf("Serving pprof on %s failed: %s", f.HTTPAddress, err)
			}
		}()
	}

	if err = tracer.ProbeBPFSyscall(); err != nil {
		return flags.Failure(fmt.Sprintf("Failed to probe eBPF syscall: %v", err))
	}

	if err = tracer.ProbeTracepoint(); err != nil {
		return flags.Failure("Failed to probe tracepoint: %v", err)
	}

	externalLabels := reporter.Labels{}
	if len(f.Metadata.ExternalLabels) > 0 {
		for name, value := range f.Metadata.ExternalLabels {
			externalLabels = append(externalLabels, reporter.Label{
				Name:  name,
				Value: value,
			})
		}
	}
	log.Infof("External labels: %s", externalLabels.String())

	log.Debugf("Determining tracers to include")
	includeTracers, err := tracertypes.Parse(f.Tracers)
	if err != nil {
		return flags.Failure("Failed to parse the included tracers: %s", err)
	}

	var relabelConfigs []*relabel.Config
	if f.ConfigPath == "" {
		log.Info("no config file provided, using default config")
	} else {
		cfgFile, err := config.LoadFile(f.ConfigPath)
		if err != nil {
			if !errors.Is(err, config.ErrEmptyConfig) {
				return flags.Failure("failed to read config: %v", err)
			}
			log.Info("config file is empty, using default config")
		}
		if cfgFile != nil {
			log.Infof("using config file: %s", f.ConfigPath)
			relabelConfigs = cfgFile.RelabelConfigs
		}
	}

	traceHandlerCacheSize :=
		traceCacheSize(f.Profiling.Duration, f.Profiling.CPUSamplingFrequency, uint16(presentCores))

	intervals := times.New(5*time.Second, f.Profiling.Duration, f.Profiling.ProbabilisticInterval)
	times.StartRealtimeSync(mainCtx, f.ClockSyncInterval)

	// Network operations to CA start here
	// Connect to the collection agent
	parcaReporter, err := reporter.New(
		memory.DefaultAllocator,
		profilestoregrpc.NewProfileStoreServiceClient(grpcConn),
		debuginfogrpc.NewDebuginfoServiceClient(grpcConn),
		externalLabels,
		f.Profiling.Duration,
		f.Debuginfo.Strip,
		f.Debuginfo.UploadMaxParallel,
		f.Debuginfo.UploadDisable,
		int64(f.Profiling.CPUSamplingFrequency),
		traceHandlerCacheSize,
		f.Debuginfo.UploadQueueSize,
		f.Debuginfo.TempDir,
		f.Node,
		relabelConfigs,
		buildInfo.VcsRevision,
	)
	if err != nil {
		return flags.Failure("Failed to start reporting: %v", err)
	}
	parcaReporter.Run(mainCtx)
	var rep otelreporter.Reporter = parcaReporter

	// Load the eBPF code and map definitions
	trc, err := tracer.NewTracer(mainCtx, &tracer.Config{
		Reporter:               rep,
		Intervals:              intervals,
		IncludeTracers:         includeTracers,
		SamplesPerSecond:       f.Profiling.CPUSamplingFrequency,
		MapScaleFactor:         f.BPF.MapScaleFactor,
		FilterErrorFrames:      !f.Profiling.EnableErrorFrames,
		KernelVersionCheck:     !f.Hidden.IgnoreUnsafeKernelVersion,
		BPFVerifierLogLevel:    f.BPF.VerifierLogLevel,
		BPFVerifierLogSize:     f.BPF.VerifierLogSize,
		ProbabilisticInterval:  f.Profiling.ProbabilisticInterval,
		ProbabilisticThreshold: f.Profiling.ProbabilisticThreshold,
		CollectCustomLabels:    f.CollectCustomLabels,
	})
	if err != nil {
		return flags.Failure("Failed to load eBPF tracer: %v", err)
	}
	log.Printf("eBPF tracer loaded")
	defer trc.Close()

	// Initial scan of /proc filesystem to list currently-active PIDs and have them processed.
	if err = trc.StartPIDEventProcessor(mainCtx); err != nil {
		log.Errorf("Failed to list processes from /proc: %v", err)
	}
	log.Debug("Completed initial PID listing")

	// Attach our tracer to the perf event
	if err := trc.AttachTracer(); err != nil {
		return flags.Failure("Failed to attach to perf event: %v", err)
	}
	log.Info("Attached tracer program")

	if f.Profiling.ProbabilisticThreshold < tracer.ProbabilisticThresholdMax {
		trc.StartProbabilisticProfiling(mainCtx)
		log.Printf("Enabled probabilistic profiling")
	} else {
		if err := trc.EnableProfiling(); err != nil {
			return flags.Failure("Failed to enable perf events: %v", err)
		}
	}

	if err := trc.AttachSchedMonitor(); err != nil {
		return flags.Failure("Failed to attach scheduler monitor: %v", err)
	}

	// This log line is used in our system tests to verify if that the agent has started. So if you
	// change this log line update also the system test.
	log.Printf("Attached sched monitor")

	if !f.AnalyticsOptOut {
		c := analytics.NewClient(
			tp,
			&http.Client{
				Transport: otelhttp.NewTransport(
					promconfig.NewUserAgentRoundTripper(
						"parca.dev/analytics-client/"+version,
						http.DefaultTransport),
				),
			},
			"parca-agent",
			time.Second*5,
		)

		var si sysinfo.SysInfo
		si.GetSysInfo()
		a := analytics.NewSender(
			c,
			runtime.GOARCH,
			int(presentCores),
			version,
			si,
			true,
		)
		go func() { a.Run(mainCtx) }()
	}

	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return flags.Failure("Failed to start map monitors: %v", err)
	}

	if _, err := tracehandler.Start(ctx, rep, trc.TraceProcessor(),
		traceCh, intervals, traceHandlerCacheSize); err != nil {
		return flags.Failure("Failed to start trace handler: %v", err)
	}

	// Block waiting for a signal to indicate the program should terminate
	<-mainCtx.Done()

	log.Info("Stop processing ...")
	rep.Stop()
	if err := grpcConn.Close(); err != nil {
		log.Fatalf("Stopping connection of OTLP client client failed: %v", err)
	}

	log.Info("Exiting ...")
	return flags.ExitSuccess
}

func getTelemetryMetadata(numCPU int) map[string]string {
	r := make(map[string]string)
	var si sysinfo.SysInfo
	si.GetSysInfo()

	r["git_commit"] = commit
	r["agent_version"] = version
	r["go_arch"] = runtime.GOARCH
	r["kernel_release"] = si.Kernel.Release
	r["cpu_cores"] = strconv.Itoa(numCPU)

	return r
}

// traceCacheSize defines the maximum number of elements for the caches in tracehandler.
//
// The caches in tracehandler have a size-"processing overhead" trade-off: Every cache miss will
// trigger additional processing for that trace in userspace (Go). For most maps, we use
// maxElementsPerInterval as a base sizing factor. For the tracehandler caches, we also multiply
// with traceCacheIntervals. For typical/small values of maxElementsPerInterval, this can lead to
// non-optimal map sizing (reduced cache_hit:cache_miss ratio and increased processing overhead).
// Simply increasing traceCacheIntervals is problematic when maxElementsPerInterval is large
// (e.g. too many CPU cores present) as we end up using too much memory. A minimum size is
// therefore used here.
func traceCacheSize(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	const (
		traceCacheIntervals = 6
		traceCacheMinSize   = 65536
	)

	maxElements := maxElementsPerInterval(monitorInterval, samplesPerSecond, presentCPUCores)

	size := maxElements * uint32(traceCacheIntervals)
	if size < traceCacheMinSize {
		size = traceCacheMinSize
	}
	return util.NextPowerOfTwo(size)
}

func maxElementsPerInterval(monitorInterval time.Duration, samplesPerSecond int,
	presentCPUCores uint16) uint32 {
	return uint32(samplesPerSecond) * uint32(monitorInterval.Seconds()) * uint32(presentCPUCores)
}
