package frame

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"
)

func TestParseCIE(t *testing.T) {
	ctx := &parseContext{
		buf:    bytes.NewBuffer([]byte{3, 0, 1, 124, 16, 12, 7, 8, 5, 16, 2, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 16, 64, 0, 0, 0, 0, 0}),
		common: &CommonInformationEntry{Length: 12},
		length: 12,
	}
	ctx.totalLen = ctx.buf.Len()
	_ = parseCIE(ctx)

	common := ctx.common

	if common.Version != 3 {
		t.Fatalf("Expected Version 3, but get %d", common.Version)
	}
	if common.Augmentation != "" {
		t.Fatalf("Expected Augmentation \"\", but get %s", common.Augmentation)
	}
	if common.CodeAlignmentFactor != 1 {
		t.Fatalf("Expected CodeAlignmentFactor 1, but get %d", common.CodeAlignmentFactor)
	}
	if common.DataAlignmentFactor != -4 {
		t.Fatalf("Expected DataAlignmentFactor -4, but get %d", common.DataAlignmentFactor)
	}
	if common.ReturnAddressRegister != 16 {
		t.Fatalf("Expected ReturnAddressRegister 16, but get %d", common.ReturnAddressRegister)
	}
	initialInstructions := []byte{12, 7, 8, 5, 16, 2, 0}
	if !bytes.Equal(common.InitialInstructions, initialInstructions) {
		t.Fatalf("Expected InitialInstructions %v, but get %v", initialInstructions, common.InitialInstructions)
	}
}

func TestParse(t *testing.T) {
	type args struct {
		path        string
		staticBase  uint64
		sectionName string
	}
	tests := []struct {
		name string
		args args
		// want    FrameDescriptionEntries
		want int
	}{
		{
			name: "Statically linked CGO binary",
			args: args{
				path:        "testdata/cgo-static",
				sectionName: ".eh_frame",
			},
			want: 2330,
		},
		// TODO(kakkoyun): Could be a DWARF64 format issue.
		// Length of record. Read 4 bytes. If they are not 0xffffffff, they are the length of the CIE or FDE record.
		// Otherwise the next 64 bits holds the length, and this is a 64-bit DWARF format. This is like .debug_frame.
		// {
		// 	name: "Statically linked CGO binary with DWARF",
		// 	args: args{
		// 		path:        "testdata/cgo-static",
		// 		sectionName: ".zdebug_frame",
		// 	},
		// 	want: 2330,
		// },
		{
			name: "Position independent shared object",
			args: args{
				path:        "testdata/pio-static",
				sectionName: ".eh_frame",
			},
			want: 3721,
		},
		{
			name: "Dynamically linked C++ position independent executable",
			args: args{
				path:        "testdata/pie-dynamic",
				sectionName: ".eh_frame",
			},
			want: 44543,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := elf.Open(tt.args.path)
			if err != nil {
				t.Fatalf("failed to open elf: %v", err)
			}
			t.Cleanup(func() {
				obj.Close()
			})

			sec := obj.Section(tt.args.sectionName)
			if sec == nil {
				t.Fatalf("failed to find section %s", tt.args.sectionName)
			}

			data, err := sec.Data()
			if err != nil {
				t.Fatalf("failed to read %s section: %v", tt.args.sectionName, err)
			}

			var ehFrameAddr uint64 = 0
			var byteOrder = obj.ByteOrder
			if tt.args.sectionName == ".eh_frame" {
				ehFrameAddr = sec.Addr
			} else {
				byteOrder = DwarfEndian(data)
			}

			fde, err := Parse(data, byteOrder, tt.args.staticBase, ptrSizeByRuntimeArch(), ehFrameAddr)
			if err != nil {
				t.Fatalf("failed to parse frame data: %v", err)
			}

			got := len(fde)
			if got != tt.want {
				t.Errorf("Parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	f, err := os.Open("testdata/frame")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(data, binary.BigEndian, 0, ptrSizeByRuntimeArch(), 0)
	}
}
