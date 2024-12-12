package uploader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	profilestorepb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/profilestore/v1alpha1"
	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/apache/arrow/go/v16/arrow/memory"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/reporter"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/otel/trace/noop"
)

type stacktraceCursor struct {
	batchIdx int
	idx      int
}

type locationsReader struct {
	Locations                      *array.List
	Location                       *array.Struct
	Address                        *array.Uint64
	FrameType                      *array.RunEndEncoded
	FrameTypeDict                  *array.Dictionary
	FrameTypeDictValues            *array.Binary
	MappingStart                   *array.RunEndEncoded
	MappingStartValues             *array.Uint64
	MappingLimit                   *array.RunEndEncoded
	MappingLimitValues             *array.Uint64
	MappingOffset                  *array.RunEndEncoded
	MappingOffsetValues            *array.Uint64
	MappingFile                    *array.RunEndEncoded
	MappingFileDict                *array.Dictionary
	MappingFileDictValues          *array.Binary
	MappingBuildID                 *array.RunEndEncoded
	MappingBuildIDDict             *array.Dictionary
	MappingBuildIDDictValues       *array.Binary
	Lines                          *array.List
	Line                           *array.Struct
	LineNumber                     *array.Int64
	LineFunctionName               *array.Dictionary
	LineFunctionNameDict           *array.Binary
	LineFunctionSystemName         *array.Dictionary
	LineFunctionSystemNameDict     *array.Binary
	LineFunctionFilename           *array.RunEndEncoded
	LineFunctionFilenameDict       *array.Dictionary
	LineFunctionFilenameDictValues *array.Binary
	LineFunctionStartLine          *array.Int64
}

func getREEUint64(arr arrow.Array, fieldName string) (*array.RunEndEncoded, *array.Uint64, error) {
	ree, ok := arr.(*array.RunEndEncoded)
	if !ok {
		return nil, nil, fmt.Errorf("expected column %q to be of type RunEndEncoded, got %T", fieldName, arr)
	}

	uint64Arr, ok := ree.Values().(*array.Uint64)
	if !ok {
		return nil, nil, fmt.Errorf("expected column %q to be of type RunEndEncoded with Uint64 Values, got %T", fieldName, arr)
	}

	return ree, uint64Arr, nil
}

func getREEBinaryDict(arr arrow.Array, fieldName string) (*array.RunEndEncoded, *array.Dictionary, *array.Binary, error) {
	ree, ok := arr.(*array.RunEndEncoded)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected column %q to be of type RunEndEncoded, got %T", fieldName, arr)
	}

	dict, ok := ree.Values().(*array.Dictionary)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected column %q to be of type RunEndEncedod with Dictionary Values, got %T", fieldName, arr)
	}

	binDict, ok := dict.Dictionary().(*array.Binary)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected column %q to be a RunEndEncoded with Dictionary Values of type Binary, got %T", fieldName, dict.Dictionary())
	}

	return ree, dict, binDict, nil
}

func getBinaryDict(arr arrow.Array, fieldName string) (*array.Dictionary, *array.Binary, error) {
	dict, ok := arr.(*array.Dictionary)
	if !ok {
		return nil, nil, fmt.Errorf("expected column %q to be of type Dictionary, got %T", fieldName, arr)
	}

	binDict, ok := dict.Dictionary().(*array.Binary)
	if !ok {
		return nil, nil, fmt.Errorf("expected column %q to be a Dictionary with Values of type Binary, got %T", fieldName, dict.Dictionary())
	}

	return dict, binDict, nil
}

func getLocationsReader(locations *array.List) (*locationsReader, error) {
	location, ok := locations.ListValues().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("expected column %q to be of type Struct, got %T", "locations", locations.ListValues())
	}

	const expectedLocationFields = 8
	if location.NumField() != expectedLocationFields {
		return nil, fmt.Errorf("expected location struct column to have %d fields, got %d", expectedLocationFields, location.NumField())
	}

	address, ok := location.Field(0).(*array.Uint64)
	if !ok {
		return nil, fmt.Errorf("expected column address to be of type Uint64, got %T", location.Field(0))
	}

	frameType, frameTypeDict, frameTypeDictValues, err := getREEBinaryDict(location.Field(1), "frame_type")

	mappingStart, mappingStartValues, err := getREEUint64(location.Field(2), "mapping_start")
	if err != nil {
		return nil, err
	}

	mappingLimit, mappingLimitValues, err := getREEUint64(location.Field(3), "mapping_limit")
	if err != nil {
		return nil, err
	}

	mappingOffset, mappingOffsetValues, err := getREEUint64(location.Field(4), "mapping_offset")
	if err != nil {
		return nil, err
	}

	mappingFile, mappingFileDict, mappingFileDictValues, err := getREEBinaryDict(location.Field(5), "mapping_file")
	if err != nil {
		return nil, err
	}

	mappingBuildID, mappingBuildIDDict, mappingBuildIDValues, err := getREEBinaryDict(location.Field(6), "mapping_build_id")
	if err != nil {
		return nil, err
	}

	lines, ok := location.Field(7).(*array.List)
	if !ok {
		return nil, fmt.Errorf("expected column lines to be of type List, got %T", location.Field(7))
	}

	line, ok := lines.ListValues().(*array.Struct)
	if !ok {
		return nil, fmt.Errorf("expected column line to be of type Struct, got %T", lines.ListValues())
	}

	const expectedLineFields = 5
	if line.NumField() != expectedLineFields {
		return nil, fmt.Errorf("expected line struct column to have %d fields, got %d", expectedLineFields, line.NumField())
	}

	lineNumber, ok := line.Field(0).(*array.Int64)
	if !ok {
		return nil, fmt.Errorf("expected column line_number to be of type Int64, got %T", line.Field(0))
	}

	lineFunctionName, lineFunctionNameDict, err := getBinaryDict(line.Field(1), "line_function_name")
	if err != nil {
		return nil, err
	}

	lineFunctionSystemName, lineFunctionSystemNameDict, err := getBinaryDict(line.Field(2), "line_function_system_name")
	if err != nil {
		return nil, err
	}

	lineFunctionFilename, lineFunctionFilenameDict, lineFunctionFilenameDictValues, err := getREEBinaryDict(line.Field(3), "line_function_filename")
	if err != nil {
		return nil, err
	}

	lineFunctionStartLine, ok := line.Field(4).(*array.Int64)
	if !ok {
		return nil, fmt.Errorf("expected column line_function_start_line to be of type Int64, got %T", line.Field(4))
	}

	return &locationsReader{
		Locations:                      locations,
		Location:                       location,
		Address:                        address,
		FrameType:                      frameType,
		FrameTypeDict:                  frameTypeDict,
		FrameTypeDictValues:            frameTypeDictValues,
		MappingStart:                   mappingStart,
		MappingStartValues:             mappingStartValues,
		MappingLimit:                   mappingLimit,
		MappingLimitValues:             mappingLimitValues,
		MappingOffset:                  mappingOffset,
		MappingOffsetValues:            mappingOffsetValues,
		MappingFile:                    mappingFile,
		MappingFileDict:                mappingFileDict,
		MappingFileDictValues:          mappingFileDictValues,
		MappingBuildID:                 mappingBuildID,
		MappingBuildIDDict:             mappingBuildIDDict,
		MappingBuildIDDictValues:       mappingBuildIDValues,
		Lines:                          lines,
		Line:                           line,
		LineNumber:                     lineNumber,
		LineFunctionName:               lineFunctionName,
		LineFunctionNameDict:           lineFunctionNameDict,
		LineFunctionSystemName:         lineFunctionSystemName,
		LineFunctionSystemNameDict:     lineFunctionSystemNameDict,
		LineFunctionFilename:           lineFunctionFilename,
		LineFunctionFilenameDict:       lineFunctionFilenameDict,
		LineFunctionFilenameDictValues: lineFunctionFilenameDictValues,
		LineFunctionStartLine:          lineFunctionStartLine,
	}, nil
}

func reeDictValueString(i int, ree *array.RunEndEncoded, dict *array.Dictionary, values *array.Binary) string {
	return values.ValueString(dict.GetValueIndex(ree.GetPhysicalIndex(int(i))))
}

func (rdr *locationsReader) frameString(i int) string {
	return reeDictValueString(i, rdr.FrameType, rdr.FrameTypeDict, rdr.FrameTypeDictValues)
}

func (rdr *locationsReader) mappingFileString(i int) string {
	return reeDictValueString(i, rdr.MappingFile, rdr.MappingFileDict, rdr.MappingFileDictValues)
}

func (rdr *locationsReader) mappingBuildIDString(i int) string {
	return reeDictValueString(i, rdr.MappingBuildID, rdr.MappingBuildIDDict, rdr.MappingBuildIDDictValues)
}

func (rdr *locationsReader) functionFilenameString(i int) string {
	return reeDictValueString(i, rdr.LineFunctionFilename, rdr.LineFunctionFilenameDict, rdr.LineFunctionFilenameDictValues)
}

func (rdr *locationsReader) functionNameString(i int) string {
	return rdr.LineFunctionNameDict.ValueString(rdr.LineFunctionName.GetValueIndex(i))
}

func (rdr *locationsReader) functionSystemNameString(i int) string {
	return rdr.LineFunctionSystemNameDict.ValueString(rdr.LineFunctionSystemName.GetValueIndex(i))
}

type stacktraceReader struct {
	record     arrow.Record
	ids        *array.Binary
	locations  *locationsReader
	isComplete *array.Boolean
}

func newStacktraceReader(rec arrow.Record) (stacktraceReader, error) {
	schema := rec.Schema()
	var (
		stacktraceIDs *array.Binary
		locations     *array.List
		isComplete    *array.Boolean
		ok            bool
	)

	for i, field := range schema.Fields() {
		switch field.Name {
		case "stacktrace_id":
			stacktraceIDs, ok = rec.Column(i).(*array.Binary)
			if !ok {
				return stacktraceReader{}, fmt.Errorf("expected column %q to be of type Binary, got %T", field.Name, rec.Column(i))
			}

		case "locations":
			locations, ok = rec.Column(i).(*array.List)
			if !ok {
				return stacktraceReader{}, fmt.Errorf("expected column %q to be of type List, got %T", field.Name, rec.Column(i))
			}
		}

		if field.Name == "is_complete" {
			isComplete, ok = rec.Column(i).(*array.Boolean)
			if !ok {
				return stacktraceReader{}, fmt.Errorf("expected column %q to be of type Boolean, got %T", field.Name, rec.Column(i))
			}
		}
	}

	if stacktraceIDs == nil {
		return stacktraceReader{}, errors.New("missing column stacktrace_id")
	}

	if locations == nil {
		return stacktraceReader{}, errors.New("missing column locations")
	}

	if isComplete == nil {
		return stacktraceReader{}, errors.New("missing column is_complete")
	}

	rdr, err := getLocationsReader(locations)
	if err != nil {
		return stacktraceReader{}, err
	}
	return stacktraceReader{
		record:     rec,
		ids:        stacktraceIDs,
		isComplete: isComplete,
		locations:  rdr,
	}, nil
}

func filterTraces(stacktraceIds *array.Binary, stacktraceReaders []stacktraceReader, idToStacktrace map[libpf.TraceHash]stacktraceCursor, mem memory.Allocator) (arrow.Record, error) {
	w := reporter.NewLocationsWriter(mem)

	for i := 0; i < stacktraceIds.Len(); i++ {
		if !stacktraceIds.IsValid(i) {
			w.LocationsList.Append(false)
			w.IsComplete.Append(false)
			continue
		}
		stacktraceId, err := libpf.TraceHashFromBytes(stacktraceIds.Value(i))
		if err != nil {
			return nil, err
		}
		cur, ok := idToStacktrace[stacktraceId]
		if !ok {
			w.LocationsList.Append(false)
			w.IsComplete.Append(false)
			log.Errorf("Location not found for id: %v", stacktraceId)
			continue
		}

		rdr := stacktraceReaders[cur.batchIdx]

		if !rdr.locations.Locations.IsValid(cur.idx) {
			w.LocationsList.Append(false)
			w.IsComplete.Append(false)
			continue
		}
		w.IsComplete.Append(rdr.isComplete.Value(cur.idx))
		locStart, locEnd := rdr.locations.Locations.ValueOffsets(cur.idx)
		if locEnd-locStart <= 0 {
			w.LocationsList.Append(false)
		} else {
			w.LocationsList.Append(true)
			for j := locStart; j < locEnd; j++ {
				w.Locations.Append(true)
				w.Address.Append(rdr.locations.Address.Value(int(j)))
				w.FrameType.AppendString(rdr.locations.frameString(int(j)))
				w.MappingFile.AppendString(rdr.locations.mappingFileString(int(j)))
				w.MappingBuildID.AppendString(rdr.locations.mappingBuildIDString(int(j)))

				// there are actually possibly N lines per location,
				// but we only produce at most one today.
				lineStart, lineEnd := rdr.locations.Lines.ValueOffsets(int(j))
				hasLine := lineEnd > lineStart
				if hasLine {
					w.Lines.Append(true)
					w.Line.Append(true)

					w.FunctionFilename.AppendString(rdr.locations.functionFilenameString(int(lineStart)))
					w.LineNumber.Append(rdr.locations.LineNumber.Value(int(lineStart)))
					w.FunctionName.AppendString(rdr.locations.functionNameString(int(lineStart)))
					w.FunctionSystemName.AppendString(rdr.locations.functionSystemNameString(int(lineStart)))
					w.FunctionStartLine.Append(rdr.locations.LineFunctionStartLine.Value(int(lineStart)))
				} else {
					w.Lines.Append(false)
				}
			}
		}
	}
	return w.NewRecord(stacktraceIds), nil
}

// like io.Reader, but lets you
// skip forward.
type readSkipper interface {
	io.Reader
	Skip(uint) error
}

type skippableFile struct {
	f *os.File
}

func (f skippableFile) Read(p []byte) (n int, err error) {
	return f.f.Read(p)
}

func (f skippableFile) Skip(distance uint) error {
	_, err := f.f.Seek(int64(distance), io.SeekCurrent)
	return err
}

type skippableZstdStream struct {
	s *zstd.Decoder
}

func (s skippableZstdStream) Read(p []byte) (n int, err error) {
	return s.s.Read(p)
}

func (s skippableZstdStream) Skip(distance uint) error {
	// we could refactor this to avoid an allocation,
	// but who cares -- it will only be called at most twice per
	// batch.
	ignored := make([]byte, distance)
	_, err := s.s.Read(ignored)
	return err
}

func UploadLog(ctx context.Context, r readSkipper, rpc profilestoregrpc.ProfileStoreServiceClient, buf *bytes.Buffer, mem memory.Allocator) (error, uint64, uint64) {
	// buf := make([]byte, 4)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("err reading magic: %w", err), 0, 0
	}
	if magic != 0xA6E7CCCA {
		return errors.New("Incorrect magic number"), 0, 0
	}

	var formatVersion uint16
	if err := binary.Read(r, binary.BigEndian, &formatVersion); err != nil {
		return fmt.Errorf("err reading format version: %w", err), 0, 0
	}
	if formatVersion != 0 {
		return fmt.Errorf("unexpected format version: %d", formatVersion), 0, 0
	}

	var nBatches uint16
	if err := binary.Read(r, binary.BigEndian, &nBatches); err != nil {
		return fmt.Errorf("err reading num of batches: %w", err), 0, 0
	}
	log.Infof("uploading %d batches", nBatches)

	stacktraceReaders := make([]stacktraceReader, 0)
	idToStacktrace := make(map[libpf.TraceHash]stacktraceCursor)

	var bytesSamples, bytesSts uint64
	for i := 0; i < int(nBatches); i++ {
		var sz uint32
		log.Debugf("reading batch %d/%d", i+1, nBatches)
		if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
			return fmt.Errorf("err reading samples size: %w", err), bytesSamples, bytesSts
		}

		buf.Reset()
		if _, err := io.CopyN(buf, r, int64(sz)); err != nil {
			return fmt.Errorf("err reading %d bytes for samples: %w", sz, err), bytesSamples, bytesSts
		}

		client, err := rpc.Write(ctx)
		if err != nil {
			return fmt.Errorf("err getting write request client: %w", err), bytesSamples, bytesSts
		}
		if err := client.Send(&profilestorepb.WriteRequest{
			Record: buf.Bytes(),
		}); err != nil {
			return fmt.Errorf("err making write request for samples: %w", err), bytesSamples, bytesSts
		}
		bytesSamples += uint64(sz)

		resp, err := client.Recv()
		if err != nil && err != io.EOF {
			return fmt.Errorf("err on recv: %w", err), bytesSamples, bytesSts
		}
		reader, err := ipc.NewReader(
			bytes.NewReader(resp.Record),
			ipc.WithAllocator(mem),
		)
		if err != nil {
			return err, bytesSamples, bytesSts
		}
		defer reader.Release()

		if !reader.Next() {
			return errors.New("arrow/ipc: could not read record from stream"), bytesSamples, bytesSts
		}

		if reader.Err() != nil {
			return fmt.Errorf("err reading response: %w", reader.Err()), bytesSamples, bytesSts
		}

		rec := reader.Record()
		defer rec.Release()

		fields := rec.Schema().Fields()
		if len(fields) != 1 {
			return fmt.Errorf("arrow/ipc: invalid number of fields in record (got=%d, want=1)", len(fields)), bytesSamples, bytesSts
		}

		if fields[0].Name != "stacktrace_id" {
			return fmt.Errorf("arrow/ipc: invalid field name in record (got=%s, want=stacktrace_id)", fields[0].Name), bytesSamples, bytesSts
		}

		stacktraceIDs, ok := rec.Column(0).(*array.Binary)
		if !ok {
			return fmt.Errorf("arrow/ipc: invalid column type in record (got=%T, want=*array.Binary)", rec.Column(0)), bytesSamples, bytesSts
		}

		if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
			return fmt.Errorf("err reading stacktraces size: %w", err), bytesSamples, bytesSts
		}

		lim := io.LimitReader(r, int64(sz))
		stsReader, err := ipc.NewReader(
			lim,
			ipc.WithAllocator(mem),
		)
		if err != nil {
			return fmt.Errorf("err creating stacktraces reader: %w", err), bytesSamples, bytesSts
		}

		defer stsReader.Release()

		if !stsReader.Next() {
			return errors.New("arrow/ipc: could not read stacktraces from file"), bytesSamples, bytesSts
		}

		if stsReader.Err() != nil {
			return fmt.Errorf("err from stacktraces reader: %w", stsReader.Err()), bytesSamples, bytesSts
		}

		stsRec := stsReader.Record()
		stReader, err := newStacktraceReader(stsRec)
		if err != nil {
			return fmt.Errorf("err constructing stacktrace reader: %w", err), bytesSamples, bytesSts
		}
		stacktraceReaders = append(stacktraceReaders, stReader)
		defer stsRec.Release()

		r.Skip(uint(lim.(*io.LimitedReader).N))

		idsInStacktracesRecord, ok := stsRec.Column(0).(*array.Binary)
		if !ok {
			return fmt.Errorf("arrow/ipc: invalid column type in record (got=%T, want=*array.Binary)", stsRec.Column(0)), bytesSamples, bytesSts
		}

		for j := 0; j < idsInStacktracesRecord.Len(); j++ {
			if idsInStacktracesRecord.IsValid(j) {
				hash, err := libpf.TraceHashFromBytes(idsInStacktracesRecord.Value(j))
				if err != nil {
					return fmt.Errorf("err computing stacktrace ID: %w", err), bytesSamples, bytesSts
				}
				idToStacktrace[hash] = stacktraceCursor{i, j}
			}
		}
		filtered, err := filterTraces(stacktraceIDs, stacktraceReaders, idToStacktrace, mem)
		if err != nil {
			return fmt.Errorf("err filtering traces: %w", err), bytesSamples, bytesSts
		}
		defer filtered.Release()

		buf.Reset()
		w := ipc.NewWriter(buf,
			ipc.WithSchema(filtered.Schema()),
			ipc.WithAllocator(mem),
		)

		if err := w.Write(filtered); err != nil {
			return fmt.Errorf("err writing stacktraces to buffer: %w", err), bytesSamples, bytesSts
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("err closing ipc writer for stacktraces: %w", err), bytesSamples, bytesSts
		}

		if err := client.Send(&profilestorepb.WriteRequest{
			Record: buf.Bytes(),
		}); err != nil {
			return fmt.Errorf("err making write request for stacktraces: %w", err), bytesSamples, bytesSts
		}

		bytesSts += uint64(buf.Len())

		if err := client.CloseSend(); err != nil {
			return fmt.Errorf("err closing send channel: %w", err), bytesSamples, bytesSts
		}
	}
	return nil, bytesSamples, bytesSts
}

func OfflineModeDoUpload(f flags.Flags) (flags.ExitCode, error) {
	mem := memory.DefaultAllocator
	ctx := context.TODO()
	reg := prometheus.NewRegistry()
	tp := noop.NewTracerProvider()
	log.SetLevel(log.TraceLevel)
	grpcConn, err := f.RemoteStore.WaitGrpcEndpoint(ctx, reg, tp)
	if err != nil {
		return flags.ExitFailure, err
	}
	defer grpcConn.Close()
	client := profilestoregrpc.NewProfileStoreServiceClient(grpcConn)
	files, err := os.ReadDir(f.OfflineMode.StoragePath)
	if err != nil {
		return flags.ExitFailure, fmt.Errorf("failed to enumerate files in storage path: %w", err)
	}
	var buf bytes.Buffer

	var totalBytesSamples, totalBytesSts uint64
	var doneFiles uint
	for _, file := range files {
		var r readSkipper
		fname := file.Name()
		if !file.Type().IsRegular() {
			log.Warnf("Directory or special file %s in storage path. Skipping", fname)
			continue
		}
		if strings.HasSuffix(fname, reporter.DATA_FILE_COMPRESSED_EXTENSION) {
			f, err := os.Open(filepath.Join(f.OfflineMode.StoragePath, fname))
			if err != nil {
				log.Errorf("Failed to open file %s: %v. Skipping.", fname, err)
				continue
			}
			s, err := zstd.NewReader(f)
			if err != nil {
				log.Errorf("Failed to decode zstd file %s: %v. Skipping.", fname, err)
				continue
			}
			r = skippableZstdStream{s}
		} else if strings.HasSuffix(fname, reporter.DATA_FILE_EXTENSION) {
			f, err := os.Open(filepath.Join(f.OfflineMode.StoragePath, fname))
			if err != nil {
				log.Errorf("Failed to open file %s: %v. Skipping.", fname, err)
				continue
			}
			r = skippableFile{f}
		} else {
			log.Warnf("Unrecognized file %s. Skipping", fname)
			continue
		}
		log.Infof("Uploading %s", fname)
		err, bytesSamples, bytesSts := UploadLog(ctx, r, client, &buf, mem)
		if err != nil {
			return flags.ExitFailure, err
		}
		doneFiles += 1
		log.Infof("successfully uploaded %s. Bytes in samples: %d; in stacktraces: %d", fname, bytesSamples, bytesSts)
		totalBytesSamples += bytesSamples
		totalBytesSts += bytesSts

		err = os.Remove(filepath.Join(f.OfflineMode.StoragePath, fname))
		if err != nil {
			log.Errorf("failed to remove file %s.", fname)
		}
	}
	log.Infof("uploaded %d files. Total bytes in samples: %s; in stacktraces: %s\n", doneFiles, humanize.IBytes(totalBytesSamples), humanize.IBytes(totalBytesSts))
	return flags.ExitSuccess, nil
}
