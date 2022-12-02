// Copyright 2022 The Parca Authors
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
	logger     log.Logger
	buf        *bufio.Reader
	endianness binary.ByteOrder
}

// newParser initializes a jitDumpParser.
func newParser(logger log.Logger, rd io.Reader) (*jitDumpParser, error) {
	p := &jitDumpParser{
		logger: logger,
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
		return nil, fmt.Errorf("failed to detect JIT dump endianness from %#x magic number: %w", magic, err)
	}

	return p, nil
}

// read reads structured binary data from the jitdump file into data.
func (p *jitDumpParser) read(data any) error {
	return binary.Read(p.buf, p.endianness, data)
}

func (p *jitDumpParser) readString() (string, error) {
	s, err := p.buf.ReadString(0) // read the null termination
	if err != nil {
		return s, err
	}
	return s[:len(s)-1], nil // trim the null termination
}

func (p *jitDumpParser) parseJITHeader() (*JITHeader, error) {
	header := &JITHeader{}
	if err := p.read(header); err != nil {
		return nil, fmt.Errorf("failed to read jitdump header: %w", err)
	}

	if header.Version > JITHeaderVersion {
		return nil, fmt.Errorf("wrong jitdump version: %d (expected: %d)", header.Version, JITHeaderVersion)
	}

	return header, nil
}

func (p *jitDumpParser) parseJRCodeLoad(prefix *JRPrefix) *JRCodeLoad {
	jr := &JRCodeLoad{Prefix: prefix}

	if err := p.read(&jr.PID); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load PID", "err", err)
	}
	if err := p.read(&jr.TID); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load TID", "err", err)
	}
	if err := p.read(&jr.VMA); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load VMA", "err", err)
	}
	if err := p.read(&jr.CodeAddr); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load CodeAddr", "err", err)
	}
	if err := p.read(&jr.CodeSize); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load CodeSize", "err", err)
	}
	if err := p.read(&jr.CodeIndex); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load CodeIndex", "err", err)
	}

	var err error
	jr.Name, err = p.readString()
	if err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load Name", "err", err)
	}

	jr.Code = make([]byte, jr.CodeSize)
	if _, err := io.ReadAtLeast(p.buf, jr.Code, len(jr.Code)); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Load Code", "err", err)
	}

	return jr
}

func (p *jitDumpParser) parseJRCodeMove(prefix *JRPrefix) *JRCodeMove {
	jr := &JRCodeMove{Prefix: prefix}

	if err := p.read(&jr.PID); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move PID", "err", err)
	}
	if err := p.read(&jr.TID); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move TID", "err", err)
	}
	if err := p.read(&jr.VMA); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move VMA", "err", err)
	}
	if err := p.read(&jr.OldCodeAddr); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move OldCodeAddr", "err", err)
	}
	if err := p.read(&jr.NewCodeAddr); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move NewCodeAddr", "err", err)
	}
	if err := p.read(&jr.CodeSize); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move CodeSize", "err", err)
	}
	if err := p.read(&jr.CodeIndex); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Move CodeIndex", "err", err)
	}

	return jr
}

func (p *jitDumpParser) parseJRCodeDebugInfo(prefix *JRPrefix) *JRCodeDebugInfo {
	jr := &JRCodeDebugInfo{Prefix: prefix}

	if err := p.read(&jr.CodeAddr); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Debug Info CodeAddr", "err", err)
	}
	if err := p.read(&jr.NREntry); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Debug Info NREntry", "err", err)
	}

	size := jrCodeDebugInfoFixedSize + debugEntryFixedSize*int(jr.NREntry)

	jr.Entries = make([]*DebugEntry, jr.NREntry)
	for i := uint64(0); i < jr.NREntry; i++ {
		jr.Entries[i] = &DebugEntry{}

		if err := p.read(&jr.Entries[i].Addr); err != nil {
			level.Warn(p.logger).Log("msg", "error while reading Debug Entry Addr", "err", err)
		}
		if err := p.read(&jr.Entries[i].Lineno); err != nil {
			level.Warn(p.logger).Log("msg", "error while reading Debug Entry Lineno", "err", err)
		}
		if err := p.read(&jr.Entries[i].Discrim); err != nil {
			level.Warn(p.logger).Log("msg", "error while reading Debug Entry Discrim", "err", err)
		}

		var err error
		jr.Entries[i].Name, err = p.readString()
		if err != nil {
			level.Warn(p.logger).Log("msg", "error while reading Debug Entry Name", "err", err)
		}
		size += len(jr.Entries[i].Name) + 1 // +1 accounts for trimmed null termination
	}

	// Discard padding if any
	if _, err := p.buf.Discard(int(jr.Prefix.TotalSize) - size); err != nil {
		level.Warn(p.logger).Log("msg", "failed to discard JIT Code Debug Info record padding", "err", err)
	}

	return jr
}

func (p *jitDumpParser) parseJRCodeUnwindingInfo(prefix *JRPrefix) *JRCodeUnwindingInfo {
	jr := &JRCodeUnwindingInfo{Prefix: prefix}

	jr.Prefix = prefix

	if err := p.read(&jr.UnwindingSize); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Unwinding Info UnwindingSize", "err", err)
	}
	if err := p.read(&jr.EHFrameHDRSize); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Unwinding Info EHFrameHDRSize", "err", err)
	}
	if err := p.read(&jr.MappedSize); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Unwinding Info MappedSize", "err", err)
	}

	jr.UnwindingData = make([]byte, jr.UnwindingSize)
	if _, err := io.ReadAtLeast(p.buf, jr.UnwindingData, len(jr.UnwindingData)); err != nil {
		level.Warn(p.logger).Log("msg", "error while reading JIT Code Unwinding Info UnwindingData", "err", err)
	}

	// Discard padding if any
	if _, err := p.buf.Discard(int(jr.Prefix.TotalSize) - jrCodeUnwindingInfoFixedSize - int(jr.UnwindingSize)); err != nil {
		level.Warn(p.logger).Log("msg", "failed to discard JIT Code Unwinding Info record padding", "err", err)
	}

	return jr
}

func (p *jitDumpParser) parse() (*JITDump, error) {
	dump := &JITDump{}
	var err error
	dump.Header, err = p.parseJITHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read JIT dump header: %w", err)
	}

	dump.CodeLoads = make([]*JRCodeLoad, 0)
	dump.CodeMoves = make([]*JRCodeMove, 0)
	dump.DebugInfo = make([]*JRCodeDebugInfo, 0)
	dump.UnwindingInfo = make([]*JRCodeUnwindingInfo, 0)

	for {
		prefix := &JRPrefix{}
		if err := p.read(prefix); errors.Is(err, io.EOF) {
			return dump, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to read JIT record prefix: %w", err)
		}

		if prefix.ID >= JITCodeMax {
			level.Warn(p.logger).Log("msg", "unknown JIT record type, skipping", "ID", prefix.ID)
			if _, err := p.buf.Discard(int(prefix.TotalSize)); err != nil {
				level.Warn(p.logger).Log("msg", "failed to discard unknown JIT record", "err", err)
			}
			continue
		}

		switch prefix.ID {
		case JITCodeLoad:
			jr := p.parseJRCodeLoad(prefix)
			dump.CodeLoads = append(dump.CodeLoads, jr)
		case JITCodeMove:
			jr := p.parseJRCodeMove(prefix)
			dump.CodeMoves = append(dump.CodeMoves, jr)
		case JITCodeDebugInfo:
			jr := p.parseJRCodeDebugInfo(prefix)
			dump.DebugInfo = append(dump.DebugInfo, jr)
		case JITCodeClose:
			level.Debug(p.logger).Log("msg", "reached JIT Code Close record")
			return dump, nil
		case JITCodeUnwindingInfo:
			jr := p.parseJRCodeUnwindingInfo(prefix)
			dump.UnwindingInfo = append(dump.UnwindingInfo, jr)
		default:
			// skip unknown record (we have read them)
			level.Debug(p.logger).Log("msg", "skipped unknown JIT record", "prefix", prefix)
		}
	}
}

// LoadJITDump loads a jitdump file.
func LoadJITDump(logger log.Logger, rd io.Reader) (*JITDump, error) {
	parser, err := newParser(logger, rd)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate JIT dump parser: %w", err)
	}

	dump, err := parser.parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse JIT dump: %w", err)
	}

	return dump, nil
}
