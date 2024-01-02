// Copyright 2022-2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Specification:
//   https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jitdump-specification.txt
// Perf implementation:
//   https://github.com/torvalds/linux/blob/master/tools/perf/util/jitdump.c
//   https://github.com/torvalds/linux/blob/master/tools/perf/util/jitdump.h

// Package jit provides a parser for Perf's JITDUMP files
package jit

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var (
	// ErrWrongJITDumpMagic is the error returned when the magic in the JITDUMP header is not recognized.
	ErrWrongJITDumpMagic = errors.New("wrong JITDUMP magic")
	// ErrWrongJITDumpVersion is the error returned when the version in the JITDUMP header is not 1.
	ErrWrongJITDumpVersion = errors.New("wrong JITDUMP version")
)

// JITHeader represent a jitdump file header.
type JITHeader struct {
	Magic     uint32 // a magic number tagging the file type
	Version   uint32 // a 4-byte value representing the format version. It is currently set to 1
	TotalSize uint32 // size in bytes of file header
	ElfMach   uint32 // ELF architecture encoding (ELF e_machine value as specified in /usr/include/elf.h)
	Pad1      uint32 // padding. Reserved for future use
	Pid       uint32 // JIT runtime process identification (OS specific)
	Timestamp uint64 // timestamp of when the file was created
	Flags     uint64 // a bitmask of flags
}

// JITHeaderVersion is the supported version of the JITDUMP specification.
const JITHeaderVersion = 1

// JITRecordType is the value identifying the record type.
type JITRecordType uint32

const (
	JITCodeLoad          JITRecordType = 0    // record describing a jitted function
	JITCodeMove                        = 1    // record describing an already jitted function which is moved
	JITCodeDebugInfo                   = 2    // record describing the debug information for a jitted function
	JITCodeClose                       = 3    // record marking the end of the jit runtime (optional)
	JITCodeUnwindingInfo               = 4    // record describing a function unwinding information
	JITCodeMax                         = iota // maximum record type
)

// JRPrefix describes the record that follows.
type JRPrefix struct {
	ID        JITRecordType // a value identifying the record type
	TotalSize uint32        // the size in bytes of the record including the header
	Timestamp uint64        // a timestamp of when the record was created
}

const jrPrefixSize int = 16 // size of JRPrefix type

// JRCodeLoad represents a JITCodeLoad record.
type JRCodeLoad struct {
	Prefix    *JRPrefix // the record header
	PID       uint32    // OS process id of the runtime generating the jitted code
	TID       uint32    // OS thread identification of the runtime thread generating the jitted code
	VMA       uint64    // virtual address of jitted code start
	CodeAddr  uint64    // code start address for the jitted code. By default VMA = CodeAddr
	CodeSize  uint64    // size in bytes of the generated jitted code
	CodeIndex uint64    // unique identifier for the jitted code
	Name      string    // function name in ASCII
	Code      []byte    // raw byte encoding of the jitted code
}

// JRCodeMove represents a JITCodeMove record.
type JRCodeMove struct {
	Prefix      *JRPrefix // the record header
	PID         uint32    // OS process id of the runtime generating the jitted code
	TID         uint32    // OS thread identification of the runtime thread generating the jitted code
	VMA         uint64    // new virtual address of jitted code start
	OldCodeAddr uint64    // previous code address for the same function
	NewCodeAddr uint64    // alternate new code started address for the jitted code. By default it should be equal to the VMA address.
	CodeSize    uint64    // size in bytes of the jitted code
	CodeIndex   uint64    // index referring to the JRCodeLoad CodeIndex record of when the function was initially jitted
}

// DebugEntry reprensents an entry from a JITCodeDebugInfo record.
type DebugEntry struct {
	Addr    uint64 // address of function for which the debug information is generated
	Lineno  uint32 // source file line number (starting at 1)
	Discrim uint32 // column discriminator, 0 is default
	Name    string // source file name in ASCII
}

const debugEntryFixedSize int = 16 // size of DebugEntry fixed-sized fields

// JRCodeDebugInfo represents a JITCodeDebugInfo record.
type JRCodeDebugInfo struct {
	Prefix   *JRPrefix     // the record header
	CodeAddr uint64        // address of function for which the debug information is generated
	NREntry  uint64        // number of debug entries for the function
	Entries  []*DebugEntry // array of NREntry debug entries for the function
}

const jrCodeDebugInfoFixedSize int = jrPrefixSize + 16 // size of JRCodeDebugInfo fixed-sized fields

// JRCodeUnwindingInfo represents a JITCodeUnwindingInfo record.
type JRCodeUnwindingInfo struct {
	Prefix         *JRPrefix // the record header
	UnwindingSize  uint64    // the size in bytes of the unwinding data table at the end of the record
	EHFrameHDRSize uint64    // the size in bytes of the DWARF EH Frame Header at the start of the unwinding data table at the end of the record
	MappedSize     uint64    // the size of the unwinding data mapped in memory
	UnwindingData  []byte    // an array of unwinding data, consisting of the EH Frame Header, followed by the actual EH Frame
}

const jrCodeUnwindingInfoFixedSize int = jrPrefixSize + 24 // size of JRCodeUnwindingInfo fixed-sized fields

// nolint: musttag // JSON is used for testing only
// JITDump represents the loaded jitdump.
type JITDump struct {
	Header        *JITHeader             // the jitdump file header
	CodeLoads     []*JRCodeLoad          // JITCodeLoad records
	CodeMoves     []*JRCodeMove          // JITCodeMove records
	DebugInfo     []*JRCodeDebugInfo     // JITCodeDebugInfo records
	UnwindingInfo []*JRCodeUnwindingInfo // JITCodeUnwindingInfo records
}

// jitDumpParser is used to parse a jitdump file.
type jitDumpParser struct {
	logger     log.Logger       // logger
	buf        *bufio.Reader    // JITDUMP buffered io.Reader
	endianness binary.ByteOrder // JITDUMP byte order

	bUint32 []byte // read buffer for uint32
	bUint64 []byte // read buffer for uint64
}

// newParser initializes a jitDumpParser.
func newParser(logger log.Logger, rd io.Reader) (*jitDumpParser, error) {
	p := &jitDumpParser{
		logger:  logger,
		bUint32: make([]byte, 4),
		bUint64: make([]byte, 8),
	}

	p.buf = bufio.NewReader(rd)

	magic, err := p.buf.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("failed to read magic number from jitdump file: %w", err)
	}

	switch {
	case bytes.Equal(magic, []byte{'J', 'i', 'T', 'D'}):
		p.endianness = binary.BigEndian
	case bytes.Equal(magic, []byte{'D', 'T', 'i', 'J'}):
		p.endianness = binary.LittleEndian
	default:
		return nil, fmt.Errorf("%w: %#x", ErrWrongJITDumpMagic, magic)
	}

	return p, nil
}

// isUnexpectedIOError ensures all EOF are unexpected EOF errors.
func isUnexpectedIOError(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readUint32 reads a uint32 from the jitdump file into n.
func (p *jitDumpParser) readUint32(n *uint32) error {
	if _, err := io.ReadFull(p.buf, p.bUint32); err != nil {
		return err
	}
	*n = p.endianness.Uint32(p.bUint32)
	return nil
}

// readUint64 reads a uint64 from the jitdump file into n.
func (p *jitDumpParser) readUint64(n *uint64) error {
	if _, err := io.ReadFull(p.buf, p.bUint64); err != nil {
		return err
	}
	*n = p.endianness.Uint64(p.bUint64)
	return nil
}

// readString reads a string (until its null termination) from the jitdump file.
func (p *jitDumpParser) readString() (string, error) {
	s, err := p.buf.ReadString(0) // read until the null termination
	if err != nil {
		// EOF is always unexpected, strings should always end by a null termination
		return s, isUnexpectedIOError(err)
	}
	return s[:len(s)-1], nil // trim the null termination
}

func (p *jitDumpParser) parseJITHeader() (*JITHeader, error) {
	header := &JITHeader{}

	if err := p.readUint32(&header.Magic); err != nil {
		return nil, fmt.Errorf("magic: %w", err)
	}
	if err := p.readUint32(&header.Version); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if err := p.readUint32(&header.TotalSize); err != nil {
		return nil, fmt.Errorf("totalSize: %w", err)
	}
	if err := p.readUint32(&header.ElfMach); err != nil {
		return nil, fmt.Errorf("elfMach: %w", err)
	}
	if err := p.readUint32(&header.Pad1); err != nil {
		return nil, fmt.Errorf("pad1: %w", err)
	}
	if err := p.readUint32(&header.Pid); err != nil {
		return nil, fmt.Errorf("pid: %w", err)
	}
	if err := p.readUint64(&header.Timestamp); err != nil {
		return nil, fmt.Errorf("timestamp: %w", err)
	}
	if err := p.readUint64(&header.Flags); err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}

	if header.Version > JITHeaderVersion {
		return nil, fmt.Errorf("%w: %d (expected: %d)", ErrWrongJITDumpVersion, header.Version, JITHeaderVersion)
	}

	return header, nil
}

func (p *jitDumpParser) parseJRPrefix() (*JRPrefix, error) {
	prefix := &JRPrefix{}

	if err := p.readUint32((*uint32)(&prefix.ID)); err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	if err := p.readUint32(&prefix.TotalSize); err != nil {
		return nil, fmt.Errorf("totalSize: %w", isUnexpectedIOError(err))
	}
	if err := p.readUint64(&prefix.Timestamp); err != nil {
		return nil, fmt.Errorf("timestamp: %w", isUnexpectedIOError(err))
	}

	return prefix, nil
}

func (p *jitDumpParser) parseJRCodeLoad(prefix *JRPrefix) (*JRCodeLoad, error) {
	jr := &JRCodeLoad{Prefix: prefix}

	if err := p.readUint32(&jr.PID); err != nil {
		return nil, fmt.Errorf("pid: %w", err)
	}
	if err := p.readUint32(&jr.TID); err != nil {
		return nil, fmt.Errorf("tid: %w", err)
	}
	if err := p.readUint64(&jr.VMA); err != nil {
		return nil, fmt.Errorf("vma: %w", err)
	}
	if err := p.readUint64(&jr.CodeAddr); err != nil {
		return nil, fmt.Errorf("codeAddr: %w", err)
	}
	if err := p.readUint64(&jr.CodeSize); err != nil {
		return nil, fmt.Errorf("codeSize: %w", err)
	}
	if err := p.readUint64(&jr.CodeIndex); err != nil {
		return nil, fmt.Errorf("codeIndex: %w", err)
	}

	var err error
	jr.Name, err = p.readString()
	if err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}

	jr.Code = make([]byte, jr.CodeSize)
	if _, err := io.ReadFull(p.buf, jr.Code); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}

	return jr, nil
}

func (p *jitDumpParser) parseJRCodeMove(prefix *JRPrefix) (*JRCodeMove, error) {
	jr := &JRCodeMove{Prefix: prefix}

	if err := p.readUint32(&jr.PID); err != nil {
		return nil, fmt.Errorf("pid: %w", err)
	}
	if err := p.readUint32(&jr.TID); err != nil {
		return nil, fmt.Errorf("tid: %w", err)
	}
	if err := p.readUint64(&jr.VMA); err != nil {
		return nil, fmt.Errorf("vma: %w", err)
	}
	if err := p.readUint64(&jr.OldCodeAddr); err != nil {
		return nil, fmt.Errorf("oldCodeAddr: %w", err)
	}
	if err := p.readUint64(&jr.NewCodeAddr); err != nil {
		return nil, fmt.Errorf("newCodeAddr: %w", err)
	}
	if err := p.readUint64(&jr.CodeSize); err != nil {
		return nil, fmt.Errorf("codeSize: %w", err)
	}
	if err := p.readUint64(&jr.CodeIndex); err != nil {
		return nil, fmt.Errorf("codeIndex: %w", err)
	}

	return jr, nil
}

func (p *jitDumpParser) parseJRCodeDebugInfo(prefix *JRPrefix) (*JRCodeDebugInfo, error) {
	jr := &JRCodeDebugInfo{Prefix: prefix}

	if err := p.readUint64(&jr.CodeAddr); err != nil {
		return nil, fmt.Errorf("codeAddr: %w", err)
	}
	if err := p.readUint64(&jr.NREntry); err != nil {
		return nil, fmt.Errorf("nrEntry: %w", err)
	}

	size := jrCodeDebugInfoFixedSize + debugEntryFixedSize*int(jr.NREntry)

	jr.Entries = make([]*DebugEntry, jr.NREntry)
	for i := uint64(0); i < jr.NREntry; i++ {
		jr.Entries[i] = &DebugEntry{}

		if err := p.readUint64(&jr.Entries[i].Addr); err != nil {
			return nil, fmt.Errorf("entries[%d].addr: %w", i, err)
		}
		if err := p.readUint32(&jr.Entries[i].Lineno); err != nil {
			return nil, fmt.Errorf("entries[%d].lineno: %w", i, err)
		}
		if err := p.readUint32(&jr.Entries[i].Discrim); err != nil {
			return nil, fmt.Errorf("entries[%d].discrim: %w", i, err)
		}

		var err error
		jr.Entries[i].Name, err = p.readString()
		if err != nil {
			return nil, fmt.Errorf("entries[%d].name: %w", i, err)
		}
		size += len(jr.Entries[i].Name) + 1 // +1 accounts for trimmed null termination
	}

	// Discard padding if any
	if _, err := p.buf.Discard(int(jr.Prefix.TotalSize) - size); err != nil {
		return nil, fmt.Errorf("failed to discard JIT Code Debug Info record padding: %w", err)
	}

	return jr, nil
}

func (p *jitDumpParser) parseJRCodeUnwindingInfo(prefix *JRPrefix) (*JRCodeUnwindingInfo, error) {
	jr := &JRCodeUnwindingInfo{Prefix: prefix}

	jr.Prefix = prefix

	if err := p.readUint64(&jr.UnwindingSize); err != nil {
		return nil, fmt.Errorf("unwindingSize: %w", err)
	}
	if err := p.readUint64(&jr.EHFrameHDRSize); err != nil {
		return nil, fmt.Errorf("ehFrameHDRSize: %w", err)
	}
	if err := p.readUint64(&jr.MappedSize); err != nil {
		return nil, fmt.Errorf("mappedSize: %w", err)
	}

	jr.UnwindingData = make([]byte, jr.UnwindingSize)
	if _, err := io.ReadFull(p.buf, jr.UnwindingData); err != nil {
		return nil, fmt.Errorf("unwindingData: %w", err)
	}

	// Discard padding if any
	if _, err := p.buf.Discard(int(jr.Prefix.TotalSize) - jrCodeUnwindingInfoFixedSize - int(jr.UnwindingSize)); err != nil {
		return nil, fmt.Errorf("failed to discard JIT Code Unwinding Info record padding: %w", err)
	}

	return jr, nil
}

func (p *jitDumpParser) parse(dump *JITDump) error {
	var err error
	dump.Header, err = p.parseJITHeader()
	if err != nil {
		return fmt.Errorf("failed to read JIT dump header: %w", isUnexpectedIOError(err))
	}

	// Initialize or reset slices in jitdump
	if dump.CodeLoads == nil {
		dump.CodeLoads = make([]*JRCodeLoad, 0)
	} else {
		dump.CodeLoads = dump.CodeLoads[:0]
	}
	if dump.CodeMoves == nil {
		dump.CodeMoves = make([]*JRCodeMove, 0)
	} else {
		dump.CodeMoves = dump.CodeMoves[:0]
	}
	if dump.DebugInfo == nil {
		dump.DebugInfo = make([]*JRCodeDebugInfo, 0)
	} else {
		dump.DebugInfo = dump.DebugInfo[:0]
	}
	if dump.UnwindingInfo == nil {
		dump.UnwindingInfo = make([]*JRCodeUnwindingInfo, 0)
	} else {
		dump.UnwindingInfo = dump.UnwindingInfo[:0]
	}

	for {
		prefix, err := p.parseJRPrefix()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to read JIT Record Prefix: %w", err)
		}

		if prefix.ID >= JITCodeMax {
			level.Warn(p.logger).Log("msg", "unknown JIT record type, skipping", "ID", prefix.ID)
			if _, err := p.buf.Discard(int(prefix.TotalSize)); err != nil {
				return fmt.Errorf("failed to discard unknown JIT record: %w", isUnexpectedIOError(err))
			}
			continue
		}

		switch prefix.ID {
		case JITCodeLoad:
			jr, err := p.parseJRCodeLoad(prefix)
			if err != nil {
				return fmt.Errorf("failed to read JIT Code Load: %w", isUnexpectedIOError(err))
			}
			dump.CodeLoads = append(dump.CodeLoads, jr)
		case JITCodeMove:
			jr, err := p.parseJRCodeMove(prefix)
			if err != nil {
				return fmt.Errorf("failed to read JIT Code Move: %w", isUnexpectedIOError(err))
			}
			dump.CodeMoves = append(dump.CodeMoves, jr)
		case JITCodeDebugInfo:
			jr, err := p.parseJRCodeDebugInfo(prefix)
			if err != nil {
				return fmt.Errorf("failed to read JIT Code Debug Info: %w", isUnexpectedIOError(err))
			}
			dump.DebugInfo = append(dump.DebugInfo, jr)
		case JITCodeClose:
			level.Debug(p.logger).Log("msg", "reached JIT Code Close record")
			return nil
		case JITCodeUnwindingInfo:
			jr, err := p.parseJRCodeUnwindingInfo(prefix)
			if err != nil {
				return fmt.Errorf("failed to read JIT Code Unwinding Info: %w", isUnexpectedIOError(err))
			}
			dump.UnwindingInfo = append(dump.UnwindingInfo, jr)
		default:
			// skip unknown record (we have read them)
			level.Debug(p.logger).Log("msg", "skipped unknown JIT record", "prefix", prefix)
		}
	}
}

// LoadJITDump loads a jitdump file into dump.
func LoadJITDump(logger log.Logger, rd io.Reader, dump *JITDump) error {
	parser, err := newParser(logger, rd)
	if err != nil {
		return fmt.Errorf("failed to instantiate JIT dump parser: %w", err)
	}

	err = parser.parse(dump)
	if err != nil {
		return fmt.Errorf("failed to parse JIT dump: %w", err)
	}

	return nil
}
