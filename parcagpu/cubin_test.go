package parcagpu

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Two instructions in an sm_90 ELF, including the toolkit-specific e_version.
// Keep the fixture independent of the cubin parser and opcode-table lookup.
func sampleCubin() []byte {
	b := make([]byte, 320)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)
	le.PutUint16(b[18:], 190)
	le.PutUint32(b[20:], 129)
	le.PutUint64(b[40:], 128)
	le.PutUint32(b[48:], 0x55a)
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[58:], 64)
	le.PutUint16(b[60:], 3)
	le.PutUint16(b[62:], 2)
	// NOP followed by MOV, so an incorrect section offset is observable.
	copy(b[64:], []byte{0x18, 0x79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xf, 0})
	copy(b[80:], []byte{0x02, 0x78, 0x0a, 0, 0xe4, 0x32, 0x2c, 0x3a, 0, 0xf, 0, 0, 0, 0xe4, 0xf, 0})
	copy(b[96:], "\x00.text.kernel\x00.shstrtab\x00")
	text := b[192:256]
	le.PutUint32(text, 1)
	le.PutUint32(text[4:], 1)
	le.PutUint64(text[8:], 6)
	le.PutUint64(text[16:], 0x1000)
	le.PutUint64(text[24:], 64)
	le.PutUint64(text[32:], 32)
	names := b[256:]
	le.PutUint32(names, 14)
	le.PutUint32(names[4:], 3)
	le.PutUint64(names[24:], 96)
	le.PutUint64(names[32:], 24)
	return b
}

type cubinReports struct {
	executable *reporter.ExecutableMetadata
	traces     []*libpf.Trace
	meta       []*samples.TraceEventMeta
}

func (r *cubinReports) ReportExecutable(m *reporter.ExecutableMetadata) { r.executable = m }
func (r *cubinReports) ReportTraceEvent(tr *libpf.Trace, m *samples.TraceEventMeta) error {
	r.traces = append(r.traces, tr)
	r.meta = append(r.meta, m)
	return nil
}

func TestCubinSamplesAndUploads(t *testing.T) {
	for i, mode := range []string{"original", "legacy", "missing", "mismatch", "no-upload"} {
		t.Run(mode, func(t *testing.T) {
			data := sampleCubin()
			path := filepath.Join(t.TempDir(), "kernel.cubin")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			original := bytes.Clone(data)
			if mode == "legacy" || mode == "no-upload" {
				path = ""
			} else if mode == "missing" {
				require.NoError(t, os.Remove(path))
			} else if mode == "mismatch" {
				wrong := bytes.Clone(data)
				wrong[80] ^= 1
				require.NoError(t, os.WriteFile(path, wrong, 0o600))
			}
			ev := gpu.CuptiCubinEvent{
				Pid: uint32(os.Getpid()), CubinCRC: uint64(0xc001 + i),
				CubinPtr: uint64(uintptr(unsafe.Pointer(&data[0]))), CubinSize: uint64(len(data)),
			}
			r := &cubinReports{}
			if mode == "no-upload" {
				handleCubinLoaded(ev, path, nil)
			} else {
				handleCubinLoaded(ev, path, r)
			}
			runtime.KeepAlive(data)
			info, ok := gpu.LoadCubin(ev.CubinCRC)
			require.True(t, ok, "missing code must not take the missing-cubin sample-drop path")
			// Independent FileID calculation for this <4 KiB fixture.
			h := sha256.New()
			h.Write(original)
			h.Write(original)
			require.NoError(t, binary.Write(h, binary.BigEndian, uint64(len(original))))
			wantID, err := libpf.FileIDFromBytes(h.Sum(nil)[:16])
			require.NoError(t, err)
			require.Equal(t, wantID, info.FileID)
			for _, text := range info.Texts {
				require.Empty(t, text.Data, "PC metadata must not retain executable bytes")
			}
			require.Equal(t, mode == "original", info.Source != nil)

			pc := &gpu.CuptiPCSampleEvent{Pid: ev.Pid}
			pc.Data.CubinCRC, pc.Data.PCOffset = ev.CubinCRC, 16
			pc.Data.StallReasonCount = 3
			copy(pc.FunctionName[:], "kernel")
			pc.StallReasons[0] = gpu.CuptiStallReason{Index: 11, Samples: 3}
			pc.StallReasons[1] = gpu.CuptiStallReason{Index: 12, Samples: 0}
			pc.StallReasons[2] = gpu.CuptiStallReason{Index: 13, Samples: 7}
			checkSamples := func(mnemonic string) {
				t.Helper()
				r.traces, r.meta = nil, nil
				gpu.HandlePCSample(pc, r)
				require.Len(t, r.traces, 2)
				for j, stall := range []string{"stall_reason_11", "stall_reason_13"} {
					frame := r.traces[j].Frames[0].Value()
					require.Equal(t, libpf.CUDAPCFrame, frame.Type)
					require.Equal(t, libpf.AddressOrLineno(16), frame.AddressOrLineno)
					require.Equal(t, "kernel", frame.FunctionName.String())
					require.Equal(t, wantID, frame.Mapping.Value().File.Value().FileID)
					require.Equal(t, stall, r.traces[j].CustomLabels[libpf.Intern("cuda_stall_reason")].String())
					require.Equal(t, mnemonic, r.traces[j].CustomLabels[libpf.Intern("cuda_sass_instruction")].String())
					require.Equal(t, []uint64{[]uint64{3, 7}[j]}, r.meta[j].ContextValues)
					require.Equal(t, gpu.ProfileTypeGpuPC, r.meta[j].ProfileType)
				}
			}
			mnemonic := ""
			if mode == "original" {
				mnemonic = "MOV"
			}
			checkSamples(mnemonic)
			if mode == "no-upload" {
				require.Nil(t, r.executable)
				return
			}
			require.NotNil(t, r.executable)
			require.Equal(t, wantID, r.executable.MappingFile.Value().FileID)
			f, err := r.executable.Process.OpenMappingFile(r.executable.Mapping)
			require.NoError(t, err)
			defer f.Close()
			uploaded, err := io.ReadAll(f)
			require.NoError(t, err)
			binary.LittleEndian.PutUint32(original[20:], 1)
			require.Equal(t, original, uploaded, "same upload image and ELF normalization as legacy")
			_, err = elf.NewFile(f.(io.ReaderAt))
			require.NoError(t, err)
			if mode == "original" {
				require.NoError(t, os.Remove(path))
				checkSamples("") // Only enrichment disappears, never identity/counts.
				_, err = r.executable.Process.OpenMappingFile(r.executable.Mapping)
				require.Error(t, err, "file-backed uploads must not retain a hidden byte fallback")
			} else {
				// Legacy/memory-only uploads intentionally retain their buffer.
				f2, err := r.executable.Process.OpenMappingFile(r.executable.Mapping)
				require.NoError(t, err)
				f2.Close()
			}
		})
	}
}
