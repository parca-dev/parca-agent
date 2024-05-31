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
//

package unwind

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var (
	ErrNoFDEsFound     = errors.New("no FDEs found")
	ErrSectionNotFound = errors.New("failed to find section")
	ErrNoRegisterFound = errors.New("architecture not supported")
)

type UnwindContext struct {
	logger           log.Logger
	pool             *objectfile.Pool
	finder           *debuginfo.Finder
	debugFrameErrors prometheus.Counter
}

func NewContext(logger log.Logger, pool *objectfile.Pool, finder *debuginfo.Finder, debugFrameErrors prometheus.Counter) *UnwindContext {
	return &UnwindContext{
		logger:           logger,
		pool:             pool,
		finder:           finder,
		debugFrameErrors: debugFrameErrors,
	}
}

// From 3.6.2 DWARF Register Number Mapping for x86_64, Fig 3.36
// https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
var x86_64Regs = []string{
	"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15", "rip", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
	"xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
	"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "mm0", "mm1", "mm2", "mm3",
	"mm4", "mm5", "mm6", "mm7", "rflags", "es", "cs", "ss", "ds", "fs", "gs",
	"unused1", "unused2", "fs.base", "gs.base", "unused3", "unused4", "tr", "ldtr",
	"mxcsr", "fcw", "fsw",
}

// From 4.1 DWARF Register Names for Aarch64/Arm64
// https://github.com/ARM-software/abi-aa/blob/2023q1-release/aadwarf64/aadwarf64.rst#dwarf-register-names
// maybe r0...r30 will also work, but x0..x30 preferred for 64 bit archs and
// what `gdb` shows on passing `info all-registers`:
// x29 -> fp
// x30 -> lr
// x31 -> sp
// x32 -> pc
// x33 -> cpsr.
var arm64Regs = []string{
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	"x12", "x13", "x14", "x15", "x16", "x17", "x18", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "pc", "cpsr",
}

func registerToString(reg uint64, arch elf.Machine) string {
	if arch == elf.EM_X86_64 {
		return x86_64Regs[reg]
	} else if arch == elf.EM_AARCH64 {
		return arm64Regs[reg]
	}

	return ErrNoRegisterFound.Error()
}

// PrintTable is a debugging helper that prints the unwinding table to the given io.Writer.
func PrintTable(uc *UnwindContext, writer io.Writer, exe string, compact bool, pc *uint64) error {
	fdes, arch, err := ReadRawFDEs(uc, "/", exe)
	if err != nil {
		return err
	}
	// The frame package can raise in case of malformed unwind data.
	defer func() {
		if r := recover(); r != nil {
			level.Info(uc.logger).Log("msg", "recovered a panic in PrintTable", "stack", r)
		}
	}()

	unwindContext := frame.NewContext()
	for _, fde := range fdes {
		if pc != nil {
			if fde.Begin() > *pc || *pc > fde.End() {
				continue
			}
		}

		fmt.Fprintf(writer, "=> Function start: %x, Function end: %x\n", fde.Begin(), fde.End())

		frameContext, err := frame.ExecuteDWARFProgram(fde, unwindContext)
		if err != nil {
			return err
		}

		for {
			insCtx, err := frameContext.Next()
			if err != nil {
				return err
			}
			if !frameContext.HasNext() {
				break
			}

			unwindRow := unwindTableRow(insCtx)

			if unwindRow == nil {
				break
			}

			if compact {
				compactRow, err := rowToCompactRow(unwindRow, arch)
				if err != nil {
					return err
				}

				showLr := arch == elf.EM_AARCH64
				fmt.Fprintf(writer, "\t%s\n", compactRow.ToString(showLr))
			} else {
				//nolint:exhaustive
				switch unwindRow.CFA.Rule {
				case frame.RuleCFA:
					CFAReg := registerToString(unwindRow.CFA.Reg, arch)
					fmt.Fprintf(writer, "\tLoc: %x CFA: $%s=%-4d", unwindRow.Loc, CFAReg, unwindRow.CFA.Offset)
				case frame.RuleExpression:
					expressionID := ExpressionIdentifier(unwindRow.CFA.Expression, arch)
					if expressionID == ExpressionUnknown {
						fmt.Fprintf(writer, "\tLoc: %x CFA: exp     ", unwindRow.Loc)
					} else {
						fmt.Fprintf(writer, "\tLoc: %x CFA: exp (plt %d)", unwindRow.Loc, expressionID)
					}
				default:
					return errors.New("CFA rule is not valid. This should never happen")
				}

				// RuleRegister
				//nolint:exhaustive
				switch unwindRow.RBP.Rule {
				case frame.RuleUndefined, frame.RuleUnknown:
					fmt.Fprintf(writer, "\tRBP: u")
				case frame.RuleRegister:
					RBPReg := registerToString(unwindRow.RBP.Reg, arch)
					fmt.Fprintf(writer, "\tRBP: $%s", RBPReg)
				case frame.RuleOffset:
					// Interesting we end up here and register is not assigned
					// TODO(sylfrena): verify if this is expected
					fmt.Fprintf(writer, "\tRBP: c%-4d", unwindRow.RBP.Offset)
				case frame.RuleExpression:
					fmt.Fprintf(writer, "\tRBP: exp")
				default:
					panic(fmt.Sprintf("Got rule %d for RBP, which wasn't expected", unwindRow.RBP.Rule))
				}

				//nolint:exhaustive
				switch unwindRow.RA.Rule {
				case frame.RuleUndefined, frame.RuleUnknown:
					// RA is ideally always defined for arm64
					if arch == elf.EM_AARCH64 {
						fmt.Fprintf(writer, "\tRA($%s): u", arch.String())
					}
				case frame.RuleRegister:
					RAReg := registerToString(unwindRow.RA.Reg, arch)
					if arch == elf.EM_AARCH64 {
						fmt.Fprintf(writer, "\tRA: $%s", RAReg)
					}
				case frame.RuleOffset:
					// Note: This condition is also executed(with offset 0 -> c0) when it is the last frame for an FDE
					// `readelf` shows RA as undefined here but clearly the offset is considered 0 here in arm64
					if arch == elf.EM_AARCH64 {
						fmt.Fprintf(writer, "\tRA: c%-4d", unwindRow.RA.Offset)
					}
				case frame.RuleExpression:
					if arch == elf.EM_AARCH64 {
						fmt.Fprintf(writer, "\tRA: exp")
					}
				default:
					panic(fmt.Sprintf("Got rule %d for RA, which wasn't expected", unwindRow.RA.Rule))
				}

				fmt.Fprintf(writer, "\n")
			}
		}
	}

	return nil
}

func readAllFDEs(uc *UnwindContext, root, exe string) (frame.FrameDescriptionEntries, frame.FrameDescriptionEntries, frame.FrameDescriptionEntries, elf.Machine, error) {
	isUnexpected := func(err error) bool {
		return err != nil && !errors.Is(err, ErrSectionNotFound) && !errors.Is(err, ErrNoFDEsFound)
	}

	file, err := uc.pool.Open(exe)
	if err != nil {
		return nil, nil, nil, elf.EM_NONE, err
	}

	obj, err := file.ELF()
	if err != nil {
		return nil, nil, nil, elf.EM_NONE, fmt.Errorf("failed to open elf: %w", err)
	}

	ehFrameFDEs, arch, err := readFDEsFromSection(obj, ".eh_frame")
	if isUnexpected(err) {
		return nil, nil, nil, elf.EM_NONE, err
	}

	var debugFrameFDEs frame.FrameDescriptionEntries
	isGo, err := isGoBinary(file)
	if err != nil {
		level.Warn(uc.logger).Log("msg", "failed to detect whether file is a Go binary, defaulting to not use .debug_frame", "path", file.Path, "err", err)
		isGo = true
	}
	if !isGo {
		fdes, arch2, err := readFDEsFromSection(obj, ".debug_frame")
		if isUnexpected(err) {
			// don't bail here, just fall back to using only .eh_frame.
			// The reason is because .debug_frame parsing is a somewhat
			// untested feature, and if it's buggy we don't want to break unwinding for the
			// .eh_frame-based cases where it worked before.
			//
			// If real users run this for a while and it turns out these errors aren't seen in real life,
			// we can be more conservative here.

			level.Warn(uc.logger).Log("msg", "failed to parse .debug_frame", "err", err)
			uc.debugFrameErrors.Inc()
			fdes = nil
			arch2 = arch
		} else if err != nil {
			level.Debug(uc.logger).Log("msg", "failed to parse .debug_frame", "err", err)
		}
		if arch != arch2 {
			// see above, we should ultimately bail here,
			// but for now just ignore .debug_frame
			level.Warn(uc.logger).Log("msg", "failed to parse .debug_frame: mismatched arch", "ehFrameArch", arch, "debugFrameArch", arch2)
			uc.debugFrameErrors.Inc()
			fdes = nil
		}
		debugFrameFDEs = fdes
	}

	// Add FDEs from debuglink, this is necessary for stripped binaries with no frame pointers
	// and external debuginfo's.
	var debugLinkFDEs frame.FrameDescriptionEntries
	if uc.finder != nil {
		debugPath, err := uc.finder.Find(context.TODO(), root, file)
		if err != nil {
			log := level.Warn
			if errors.Is(err, os.ErrNotExist) {
				log = level.Debug
			}
			log(uc.logger).Log("msg", "no .debug file found for ", "exe", exe, "err", err)
		} else if debugPath != "" {
			debugFile, err := os.Open(debugPath)
			if err != nil {
				return nil, nil, nil, elf.EM_NONE, fmt.Errorf("failed to open file: %w", err)
			}
			obj, err := elf.NewFile(debugFile)
			if err != nil {
				return nil, nil, nil, elf.EM_NONE, fmt.Errorf("failed to open elf: %w", err)
			}
			defer obj.Close()
			// Alpine .debug images use .debug_frame but not sure if that's universal...
			fdes, arch3, err := readFDEsFromSection(obj, ".debug_frame")

			if err != nil {
				if isUnexpected(err) {
					level.Warn(uc.logger).Log("msg", "error reading FDEs from .debug_frame section in debuglink", "err", err, "exe", exe, "debuglink", debugPath)
				}
			} else if len(fdes) > 0 {
				if arch != arch3 {
					// see above, we should ultimately bail here,
					// but for now just ignore .debug_frame
					level.Warn(uc.logger).Log("msg", "failed to parse .debug_frame: mismatched arch", "ehFrameArch", arch, "debugFrameArch", arch3)
					uc.debugFrameErrors.Inc()
				} else {
					level.Info(uc.logger).Log("msg", "found FDEs from .debug_frame section in debuglink", "exe", exe, "debuglink", debugPath)
					// Sometimes there's eh frames in the exe and the debug link, just merge them.
					debugLinkFDEs = fdes
				}
			}
		}
	}

	return ehFrameFDEs, debugFrameFDEs, debugLinkFDEs, arch, nil
}

func ReadRawFDEs(uc *UnwindContext, root, exe string) (frame.FrameDescriptionEntries, elf.Machine, error) {
	ehFrameFDEs, debugFrameFDEs, debugLinkFDEs, arch, err := readAllFDEs(uc, root, exe)
	if err != nil {
		return nil, elf.EM_NONE, err
	}

	fdes := make(frame.FrameDescriptionEntries, 0, len(ehFrameFDEs)+len(debugFrameFDEs)+len(debugLinkFDEs))
	fdes = append(fdes, ehFrameFDEs...)
	fdes = append(fdes, debugFrameFDEs...)
	fdes = append(fdes, debugLinkFDEs...)

	return fdes, arch, nil
}

func ReadFDEs(uc *UnwindContext, root, exe string) (frame.FrameDescriptionEntries, elf.Machine, error) {
	ehFrameFDEs, debugFrameFDEs, debugLinkFDEs, arch, err := readAllFDEs(uc, root, exe)
	if err != nil {
		return nil, elf.EM_NONE, err
	}

	fdes := make(frame.FrameDescriptionEntries, 0, len(ehFrameFDEs)+len(debugFrameFDEs)+len(debugLinkFDEs))
	fdes = append(fdes, ehFrameFDEs...)
	fdes = append(fdes, debugFrameFDEs...)
	fdes = append(fdes, debugLinkFDEs...)

	// merge the sections.
	sort.Sort(fdes)
	// make sure there are no overlaps; if so, something is screwed up,
	// and we fall back to just using .eh_frame .
	fdesDeduplicated := make(frame.FrameDescriptionEntries, 0, len(fdes))
	for i := 0; i < len(fdes); i++ {
		// I don't know what these Begin == 0 entries are but they can overlap hitting
		// error below and we discard them in our compact unwind tables anyways.
		fde := fdes[i]
		if fde.Begin() == 0 || fde.Begin() == fde.End() {
			continue
		}
		if i > 0 {
			// if it's an exact match, just take one arbitrarily and don't complain
			last := fdes[i-1]
			if last.End() > fde.Begin() {
				if fde.End() == last.End() && fde.Begin() == last.Begin() {
					continue
				}
				level.Warn(uc.logger).Log("msg", "error parsing .debug_frame: overlapping records:", "fde1", fmt.Sprintf("%d:%d", last.Begin(), last.End()), "fde2", fmt.Sprintf("%d:%d", fde.Begin(), fde.End()))
				uc.debugFrameErrors.Inc()
				fdesDeduplicated = ehFrameFDEs
				sort.Sort(fdesDeduplicated)
				break
			}
		}
		fdesDeduplicated = append(fdesDeduplicated, fdes[i])
	}

	return fdesDeduplicated, arch, nil
}

func readFDEsFromSection(obj *elf.File, section string) (frame.FrameDescriptionEntries, elf.Machine, error) {
	arch := obj.Machine
	sec := obj.Section(section)
	if sec == nil {
		return nil, arch, ErrSectionNotFound
	}

	// TODO: Needs to support DWARF64 as well.
	secData, err := sec.Data()
	if err != nil {
		return nil, arch, fmt.Errorf("failed to read %s section: %w", section, err)
	}

	ehFrameAddr := sec.Addr
	if section == ".debug_frame" {
		ehFrameAddr = 0
	}

	// TODO: Byte order of a DWARF section can be different.
	fdes, err := frame.Parse(secData, obj.ByteOrder, 0, pointerSize(obj.Machine), ehFrameAddr, arch)
	if err != nil {
		return nil, arch, fmt.Errorf("failed to parse frame data: %w", err)
	}

	if len(fdes) == 0 {
		return nil, arch, ErrNoFDEsFound
	}

	return fdes, arch, nil
}

func BuildUnwindTable(fdes frame.FrameDescriptionEntries) (UnwindTable, error) {
	// The frame package can raise in case of malformed unwind data.
	table := make(UnwindTable, 0, 4*len(fdes)) // heuristic

	for _, fde := range fdes {
		frameContext, err := frame.ExecuteDWARFProgram(fde, nil)
		if err != nil {
			return UnwindTable{}, err
		}

		for {
			insCtx, err := frameContext.Next()
			if err != nil {
				return UnwindTable{}, err
			}

			if !frameContext.HasNext() {
				break
			}
			table = append(table, *unwindTableRow(insCtx))
		}
	}
	return table, nil
}

// UnwindTableRow represents a single row in the unwind table.
// x86_64: rip (instruction pointer register), rsp (stack pointer register), rbp (base pointer/frame pointer register)
// aarch64: lr(link register), sp(stack pointer register), fp(frame pointer register)
type UnwindTableRow struct {
	// The address of the machine instruction.
	// Each row covers a range of machine instruction, from its address (Loc) to that of the row below.
	Loc uint64
	// CFA, the value of the stack pointer in the previous frame.
	CFA frame.DWRule
	// The value of the RBP register.
	RBP frame.DWRule
	// The value of the saved return address. This is not needed in x86_64 as it's part of the ABI but is necessary
	// in arm64.
	RA frame.DWRule
}

type UnwindTable []UnwindTableRow

func (t UnwindTable) Len() int           { return len(t) }
func (t UnwindTable) Less(i, j int) bool { return t[i].Loc < t[j].Loc }
func (t UnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func unwindTableRow(instructionContext *frame.InstructionContext) *UnwindTableRow {
	if instructionContext == nil {
		return nil
	}

	return &UnwindTableRow{
		Loc: instructionContext.Loc(),
		CFA: instructionContext.CFA,
		RA:  instructionContext.Regs.SavedReturn,
		RBP: instructionContext.Regs.FramePointer,
	}
}

func pointerSize(arch elf.Machine) int {
	//nolint:exhaustive
	switch arch {
	case elf.EM_386:
		return 4
	case elf.EM_AARCH64, elf.EM_X86_64:
		return 8
	default:
		return 0
	}
}
