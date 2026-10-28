package main

import (
	"os"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestTracerLabelsAndSymbolization(t *testing.T) {
	for _, tc := range []struct {
		tracers                         string
		symbolize                       bool
		goLabels, nativeLabels, symbols bool
	}{
		{tracers: "labels", goLabels: true, nativeLabels: true},
		{tracers: "all", goLabels: true, nativeLabels: true},
		{tracers: "python,hotspot,php,ruby,perl,v8,dotnet,beam,luajit,labels", goLabels: true, nativeLabels: true},
		{tracers: "python,hotspot"},
		{tracers: "go"},
		{tracers: "python", symbolize: true},
		{tracers: "go", symbolize: true, symbols: true},
		{tracers: "labels", symbolize: true, goLabels: true, nativeLabels: true},
		{tracers: "go,labels", symbolize: true, goLabels: true, nativeLabels: true, symbols: true},
		{tracers: "all", symbolize: true, goLabels: true, nativeLabels: true, symbols: true},
	} {
		t.Run(tc.tracers+"/symbolize="+strconv.FormatBool(tc.symbolize), func(t *testing.T) {
			cfg, err := parseTracers(tc.tracers, tc.symbolize)
			require.NoError(t, err)
			require.Equal(t, tc.goLabels, !cfg.Go.IsLabelsDisabled(), "Go label loader must remain active without symbolization")
			require.Equal(t, tc.nativeLabels, !cfg.CustomLabels.IsDisabled())
			require.Equal(t, tc.symbols, !cfg.Go.IsSymbolizationDisabled(), "native Go frames must reach the backend unless symbolization is explicitly opted into")
			require.Equal(t, tc.goLabels || tc.symbols, !cfg.Go.IsDisabled())
		})
	}
	_, err := parseTracers("unknown", false)
	require.Error(t, err)
}

type labelTestBPF struct{ interpreter.EbpfHandler }

func (labelTestBPF) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}
func (labelTestBPF) DeleteProcData(libpf.InterpreterType, libpf.PID) error { return nil }

// Run the selected Go loader on this real Go executable, without loading eBPF.
// Enabling labels must install the label program but not consume native frames.
func TestGoLabelLoaderLeavesFramesNative(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	pid := libpf.PID(os.Getpid())
	ref := pfelf.NewReference(exe, process.New(pid, pid))
	defer ref.Close()
	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)
	for _, symbolize := range []bool{false, true} {
		tracers := "labels"
		if symbolize {
			tracers = "go,labels"
		}
		cfg, err := parseTracers(tracers, symbolize)
		require.NoError(t, err)
		loaders := cfg.Loaders()
		require.Len(t, loaders, 1)
		var labelProgram bool
		for _, resource := range loaders[0].Resources() {
			labelProgram = labelProgram || resource.ProgID == uint32(support.ProgGoLabels)
		}
		require.True(t, labelProgram)
		data, err := loaders[0].Load(nil, interpreter.NewLoaderInfo(host.FileID(42), ref, nil))
		require.NoError(t, err)
		require.NotNil(t, data)
		instance, err := data.Attach(labelTestBPF{}, pid, 0, remotememory.NewProcessVirtualMemory(pid))
		require.NoError(t, err)
		frame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, uint64(pc))
		frame[1] = 42
		var frames libpf.Frames
		err = instance.Symbolize(frame, &frames, libpf.FrameMapping{})
		if symbolize {
			require.NoError(t, err)
			require.Len(t, frames, 1)
			require.Contains(t, frames[0].Value().FunctionName.String(), "TestGoLabelLoaderLeavesFramesNative")
		} else {
			require.ErrorIs(t, err, interpreter.ErrMismatchInterpreterType)
			require.Empty(t, frames, "the process manager must keep the original native frame")
		}
		require.NoError(t, instance.Detach(labelTestBPF{}, pid))
		data.Unload(labelTestBPF{})
	}
}
