//nolint:stylecheck
package frame

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
)

// Rule rule defined for register values.
type Rule byte

const (
	RuleUnknown Rule = iota
	RuleUndefined
	RuleSameVal
	RuleOffset
	RuleValOffset
	RuleRegister
	RuleExpression
	RuleValExpression
	RuleCFA // Value is rule.Reg + rule.Offset
)

// NOTE:
// Each register in arm64 or x86 has a DWARF Register Number mapped
// to its architecture specific Register Name defined in its respective spec.
// The register numbers are not arbitrary constants but obtained from the spec
// linked below for each architecture.
//
// From 3.4.1 Initial Stack and Register State for x86_64
// https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
// From 4.1 DWARF Register Names for Aarch64/Arm64
// https://github.com/ARM-software/abi-aa/blob/2023q1-release/aadwarf64/aadwarf64.rst#dwarf-register-names
const (
	X86_64FramePointer = 6  // $rbp
	X86_64StackPointer = 7  // $rsp
	Arm64FramePointer  = 29 // $fp // assumption: frame pointers are not stripped
	Arm64StackPointer  = 31 // $sp or $r31
	Arm64LinkRegister  = 30 // $x30 or $lr
	// Arm64ProgramCounter = 32 //$x32; may be needed later while unwinding.
)

// DWRule wrapper of rule defined for register values.
type DWRule struct {
	Rule       Rule
	Offset     int64
	Reg        uint64
	Expression []byte
}

type UnwindRegisters struct {
	StackPointer DWRule
	FramePointer DWRule
	SavedReturn  DWRule // save LinkRegister in here TODO(sylfrena)
}

// InstructionContext represents each object code instruction
// that we have unwind information for.
type InstructionContext struct {
	loc           uint64 // holds the PC
	CFA           DWRule
	Regs          UnwindRegisters
	initialRegs   UnwindRegisters
	cie           *CommonInformationEntry
	RetAddrReg    uint64
	codeAlignment uint64
	dataAlignment int64
}

func (instructionContext *InstructionContext) Loc() uint64 {
	return instructionContext.loc
}

type InstructionContextIterator struct {
	ctx         *Context
	lastReached bool
	done        bool
}

func (ici *InstructionContextIterator) HasNext() bool {
	return !ici.done
}

func (ici *InstructionContextIterator) Next() *InstructionContext {
	for ici.ctx.buf.Len() > 0 {
		lastPcBefore := ici.ctx.lastInsCtx.loc
		executeDWARFInstruction(ici.ctx)
		lastPcAfter := ici.ctx.lastInsCtx.loc
		// We are at an instruction boundary when there's a program counter change.
		if lastPcBefore != lastPcAfter {
			return ici.ctx.lastInsCtx
		}
	}

	// Account for the last instruction boundary.
	if !ici.lastReached {
		ici.lastReached = true
		return ici.ctx.currInsCtx
	}

	// We are done iterating.
	ici.done = true
	return nil
}

// RowState is a stack where `DW_CFA_remember_state` pushes
// its CFA and registers state and `DW_CFA_restore_state`
// pops them.
type RowState struct {
	cfa  DWRule
	regs UnwindRegisters
}

type StateStack struct {
	items []RowState
}

func newStateStack() *StateStack {
	return &StateStack{
		items: make([]RowState, 0),
	}
}

func (stack *StateStack) push(state RowState) {
	stack.items = append(stack.items, state)
}

func (stack *StateStack) pop() RowState {
	restored := stack.items[len(stack.items)-1]
	stack.items = stack.items[0 : len(stack.items)-1]
	return restored
}

func (stack *StateStack) reset() {
	stack.items = stack.items[0:0]
}

// Context represents a function.
type Context struct {
	currInsCtx      *InstructionContext
	lastInsCtx      *InstructionContext
	rememberedState *StateStack
	// The buffer where we store the dwarf unwind entries to be parsed for this function.
	buf   *bytes.Reader
	order binary.ByteOrder
}

func (ctx *Context) currentInstruction() *InstructionContext {
	return ctx.currInsCtx
}

func (frame *Context) reset(cie *CommonInformationEntry) {
	frame.currInsCtx.cie = cie
	frame.currInsCtx.Regs = UnwindRegisters{}
	frame.currInsCtx.RetAddrReg = cie.ReturnAddressRegister
	frame.currInsCtx.codeAlignment = cie.CodeAlignmentFactor
	frame.currInsCtx.dataAlignment = cie.DataAlignmentFactor

	frame.lastInsCtx.cie = cie
	frame.lastInsCtx.Regs = UnwindRegisters{}
	frame.lastInsCtx.RetAddrReg = cie.ReturnAddressRegister
	frame.lastInsCtx.codeAlignment = cie.CodeAlignmentFactor
	frame.lastInsCtx.dataAlignment = cie.DataAlignmentFactor

	frame.buf.Reset(cie.InitialInstructions)
	frame.rememberedState.reset()
}

// Instructions used to recreate the table from the .debug_frame data.
const (
	DW_CFA_nop                = 0x0        // No ops
	DW_CFA_set_loc            = 0x01       // op1: address
	DW_CFA_advance_loc1       = iota       // op1: 1-bytes delta
	DW_CFA_advance_loc2                    // op1: 2-byte delta
	DW_CFA_advance_loc4                    // op1: 4-byte delta
	DW_CFA_offset_extended                 // op1: ULEB128 register, op2: ULEB128 offset
	DW_CFA_restore_extended                // op1: ULEB128 register
	DW_CFA_undefined                       // op1: ULEB128 register
	DW_CFA_same_value                      // op1: ULEB128 register
	DW_CFA_register                        // op1: ULEB128 register, op2: ULEB128 register
	DW_CFA_remember_state                  // No ops
	DW_CFA_restore_state                   // No ops
	DW_CFA_def_cfa                         // op1: ULEB128 register, op2: ULEB128 offset
	DW_CFA_def_cfa_register                // op1: ULEB128 register
	DW_CFA_def_cfa_offset                  // op1: ULEB128 offset
	DW_CFA_def_cfa_expression              // op1: BLOCK
	DW_CFA_expression                      // op1: ULEB128 register, op2: BLOCK
	DW_CFA_offset_extended_sf              // op1: ULEB128 register, op2: SLEB128 BLOCK
	DW_CFA_def_cfa_sf                      // op1: ULEB128 register, op2: SLEB128 offset
	DW_CFA_def_cfa_offset_sf               // op1: SLEB128 offset
	DW_CFA_val_offset                      // op1: ULEB128, op2: ULEB128
	DW_CFA_val_offset_sf                   // op1: ULEB128, op2: SLEB128
	DW_CFA_val_expression                  // op1: ULEB128, op2: BLOCK
	DW_CFA_lo_user            = 0x1c       // op1: BLOCK
	DW_CFA_hi_user            = 0x3f       // op1: ULEB128 register, op2: BLOCK
	DW_CFA_advance_loc        = (0x1 << 6) // High 2 bits: 0x1, low 6: delta
	DW_CFA_offset             = (0x2 << 6) // High 2 bits: 0x2, low 6: register
	DW_CFA_restore            = (0x3 << 6) // High 2 bits: 0x3, low 6: register
	// TODO(kakkoyun): Find corresponding values in the spec.
	DW_CFA_MIPS_advance_loc8            = 0x1d
	DW_CFA_GNU_window_save              = 0x2d // DW_CFA_AARCH64_negate_ra_state shares this value too.
	DW_CFA_GNU_args_size                = 0x2e
	DW_CFA_GNU_negative_offset_extended = 0x2f
)

func CFAString(b byte) string {
	m := map[byte]string{
		DW_CFA_nop:                          "DW_CFA_nop",
		DW_CFA_set_loc:                      "DW_CFA_set_loc",
		DW_CFA_advance_loc1:                 "DW_CFA_advance_loc1",
		DW_CFA_advance_loc2:                 "DW_CFA_advance_loc2",
		DW_CFA_advance_loc4:                 "DW_CFA_advance_loc4",
		DW_CFA_offset_extended:              "DW_CFA_offset_extended",
		DW_CFA_restore_extended:             "DW_CFA_restore_extended",
		DW_CFA_undefined:                    "DW_CFA_undefined",
		DW_CFA_same_value:                   "DW_CFA_same_value",
		DW_CFA_register:                     "DW_CFA_register",
		DW_CFA_remember_state:               "DW_CFA_remember_state",
		DW_CFA_restore_state:                "DW_CFA_restore_state",
		DW_CFA_def_cfa:                      "DW_CFA_def_cfa",
		DW_CFA_def_cfa_register:             "DW_CFA_def_cfa_register",
		DW_CFA_def_cfa_offset:               "DW_CFA_def_cfa_offset",
		DW_CFA_def_cfa_expression:           "DW_CFA_def_cfa_expression",
		DW_CFA_expression:                   "DW_CFA_expression",
		DW_CFA_offset_extended_sf:           "DW_CFA_offset_extended_sf",
		DW_CFA_def_cfa_sf:                   "DW_CFA_def_cfa_sf",
		DW_CFA_def_cfa_offset_sf:            "DW_CFA_def_cfa_offset_sf",
		DW_CFA_val_offset:                   "DW_CFA_val_offset",
		DW_CFA_val_offset_sf:                "DW_CFA_val_offset_sf",
		DW_CFA_val_expression:               "DW_CFA_val_expression",
		DW_CFA_lo_user:                      "DW_CFA_lo_user",
		DW_CFA_hi_user:                      "DW_CFA_hi_user",
		DW_CFA_advance_loc:                  "DW_CFA_advance_loc",
		DW_CFA_offset:                       "DW_CFA_offset",
		DW_CFA_restore:                      "DW_CFA_restoree",
		DW_CFA_MIPS_advance_loc8:            "DW_CFA_MIPS_advance_loc8",
		DW_CFA_GNU_window_save:              "DW_CFA_GNU_window_save",
		DW_CFA_GNU_args_size:                "DW_CFA_GNU_args_size",
		DW_CFA_GNU_negative_offset_extended: "DW_CFA_GNU_negative_offset_extended",
	}

	str, ok := m[b]
	if !ok {
		return "<unknown CFA value>"
	}
	return str
}

const low_6_offset = 0x3f

type instruction func(ctx *Context)

func NewContext() *Context {
	return &Context{
		currInsCtx:      &InstructionContext{},
		lastInsCtx:      &InstructionContext{},
		buf:             &bytes.Reader{},
		rememberedState: newStateStack(),
	}
}

func executeCIEInstructions(cie *CommonInformationEntry, context *Context) *Context {
	if context == nil {
		context = NewContext()
	}

	context.reset(cie)
	context.executeDWARFProgram()
	return context
}

// ExecuteDWARFProgram evaluates the unwind opcodes for a function.
func ExecuteDWARFProgram(fde *FrameDescriptionEntry, context *Context) *InstructionContextIterator {
	ctx := executeCIEInstructions(fde.CIE, context)
	ctx.order = fde.order
	frame := ctx.currentInstruction()
	frame.loc = fde.Begin()
	return ctx.Execute(fde.Instructions)
}

func (ctx *Context) executeDWARFProgram() {
	for ctx.buf.Len() > 0 {
		executeDWARFInstruction(ctx)
	}
}

// Execute execute dwarf instructions.
func (ctx *Context) Execute(instructions []byte) *InstructionContextIterator {
	ctx.buf = bytes.NewReader(instructions)

	return &InstructionContextIterator{
		ctx: ctx,
	}
}

func executeDWARFInstruction(ctx *Context) {
	instruction, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read from instruction buffer")
	}

	if instruction == DW_CFA_nop {
		return
	}

	fn := lookupFunc(instruction, ctx)
	fn(ctx)
}

func lookupFunc(instruction byte, ctx *Context) instruction {
	const high_2_bits = 0xc0
	var restoreOpcode bool

	buf := ctx.buf

	// Special case the 3 opcodes that have their argument encoded in the opcode itself.
	switch instruction & high_2_bits {
	case DW_CFA_advance_loc:
		instruction = DW_CFA_advance_loc
		restoreOpcode = true

	case DW_CFA_offset:
		instruction = DW_CFA_offset
		restoreOpcode = true

	case DW_CFA_restore:
		instruction = DW_CFA_restore
		restoreOpcode = true
	}

	if restoreOpcode {
		// Restore the last byte as it actually contains the argument for the opcode.
		err := buf.UnreadByte()
		if err != nil {
			panic("Could not unread byte")
		}
	}

	var fn func(ctx *Context)

	switch instruction {
	case DW_CFA_advance_loc:
		fn = advanceloc
	case DW_CFA_offset:
		fn = offset
	case DW_CFA_restore:
		fn = restore
	case DW_CFA_set_loc:
		fn = setloc
	case DW_CFA_advance_loc1:
		fn = advanceloc1
	case DW_CFA_advance_loc2:
		fn = advanceloc2
	case DW_CFA_advance_loc4:
		fn = advanceloc4
	case DW_CFA_offset_extended:
		fn = offsetextended
	case DW_CFA_restore_extended:
		fn = restoreextended
	case DW_CFA_undefined:
		fn = undefined
	case DW_CFA_same_value:
		fn = samevalue
	case DW_CFA_register:
		fn = register
	case DW_CFA_remember_state:
		fn = rememberstate
	case DW_CFA_restore_state:
		fn = restorestate
	case DW_CFA_def_cfa:
		fn = defcfa
	case DW_CFA_def_cfa_register:
		fn = defcfaregister
	case DW_CFA_def_cfa_offset:
		fn = defcfaoffset
	case DW_CFA_def_cfa_expression:
		fn = defcfaexpression
	case DW_CFA_expression:
		fn = expression
	case DW_CFA_offset_extended_sf:
		fn = offsetextendedsf
	case DW_CFA_def_cfa_sf:
		fn = defcfasf
	case DW_CFA_def_cfa_offset_sf:
		fn = defcfaoffsetsf
	case DW_CFA_val_offset:
		fn = valoffset
	case DW_CFA_val_offset_sf:
		fn = valoffsetsf
	case DW_CFA_val_expression:
		fn = valexpression
	case DW_CFA_lo_user:
		fn = louser
	case DW_CFA_hi_user:
		fn = hiuser
	case DW_CFA_GNU_args_size:
		fn = gnuargsize
	case DW_CFA_GNU_window_save:
		fn = gnuwindowsave
	default:
		panic(fmt.Sprintf("Encountered an unexpected DWARF CFA opcode: %#v", instruction))
	}

	return fn
}

// TODO(sylfrena): Reuse types.
func setRule(reg uint64, frame *InstructionContext, rule DWRule) {
	switch reg {
	case Arm64StackPointer, X86_64StackPointer:
		frame.Regs.StackPointer = rule
	case Arm64FramePointer, X86_64FramePointer:
		frame.Regs.FramePointer = rule
	case Arm64LinkRegister, frame.RetAddrReg: // TODO(sylfrena): should I just let it remain or reuse?
		frame.Regs.SavedReturn = rule
	}
}

func restoreRule(reg uint64, frame *InstructionContext) {
	switch reg {
	// TODO(sylfrena): Reuse types
	case Arm64StackPointer, X86_64StackPointer:
		if frame.initialRegs.StackPointer.Rule == RuleUnknown {
			frame.Regs.StackPointer = DWRule{Rule: RuleUndefined}
		} else {
			frame.Regs.StackPointer = DWRule{Offset: frame.initialRegs.StackPointer.Offset, Rule: RuleOffset}
		}
	case Arm64FramePointer, X86_64FramePointer:
		if frame.initialRegs.FramePointer.Rule == RuleUnknown {
			frame.Regs.FramePointer = DWRule{Rule: RuleUndefined}
		} else {
			frame.Regs.FramePointer = DWRule{Offset: frame.initialRegs.FramePointer.Offset, Rule: RuleOffset}
		}
	case frame.RetAddrReg:
		frame.Regs.SavedReturn = DWRule{Offset: frame.initialRegs.SavedReturn.Offset, Rule: RuleOffset}
	}
}

// advanceContext returns a pointer to the current instruction context.
// It must be called on every advanceloc* opcode.
func advanceContext(ctx *Context) *InstructionContext {
	*ctx.lastInsCtx = *ctx.currInsCtx
	return ctx.currInsCtx
}

func advanceloc(ctx *Context) {
	frame := advanceContext(ctx)

	b, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	delta := b & low_6_offset
	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc1(ctx *Context) {
	frame := advanceContext(ctx)

	delta, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc2(ctx *Context) {
	frame := advanceContext(ctx)

	var delta uint16
	err := binary.Read(ctx.buf, ctx.order, &delta)
	if err != nil {
		panic("Could not read from buffer")
	}
	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc4(ctx *Context) {
	frame := advanceContext(ctx)

	var delta uint32
	err := binary.Read(ctx.buf, ctx.order, &delta)
	if err != nil {
		panic("Could not read from buffer")
	}

	frame.loc += uint64(delta) * frame.codeAlignment
}

func offset(ctx *Context) {
	frame := ctx.currentInstruction()

	b, err := ctx.buf.ReadByte()
	if err != nil {
		panic(err)
	}

	var (
		reg       = b & low_6_offset
		offset, _ = util.DecodeULEB128(ctx.buf)
	)

	rule := DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
	setRule(uint64(reg), frame, rule)
}

func restore(ctx *Context) {
	frame := ctx.currentInstruction()

	b, err := ctx.buf.ReadByte()
	if err != nil {
		panic(err)
	}

	reg := uint64(b & low_6_offset)
	restoreRule(reg, frame)
}

func setloc(ctx *Context) {
	frame := ctx.currentInstruction()

	var loc uint64
	err := binary.Read(ctx.buf, ctx.order, &loc)
	if err != nil {
		panic("Could not read from buffer")
	}
	frame.loc = loc + frame.cie.staticBase
}

func offsetextended(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeULEB128(ctx.buf)
	)

	rule := DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
	setRule(reg, frame, rule)
}

func undefined(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	rule := DWRule{Rule: RuleUndefined}
	setRule(reg, frame, rule)
}

func samevalue(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	rule := DWRule{Rule: RuleSameVal}
	setRule(reg, frame, rule)
}

func register(ctx *Context) {
	frame := ctx.currentInstruction()

	reg1, _ := util.DecodeULEB128(ctx.buf)
	reg2, _ := util.DecodeULEB128(ctx.buf)
	rule := DWRule{Reg: reg2, Rule: RuleRegister}
	setRule(reg1, frame, rule)
}

func rememberstate(ctx *Context) {
	frame := ctx.currentInstruction()

	state := RowState{
		cfa:  frame.CFA,
		regs: UnwindRegisters{},
	}
	state.regs = frame.Regs

	ctx.rememberedState.push(state)
}

func restorestate(ctx *Context) {
	frame := ctx.currentInstruction()
	restored := ctx.rememberedState.pop()

	frame.CFA = restored.cfa
	frame.Regs = restored.regs
}

func restoreextended(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	restoreRule(reg, frame)
}

func defcfa(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	offset, _ := util.DecodeULEB128(ctx.buf)

	frame.CFA.Rule = RuleCFA
	frame.CFA.Reg = reg
	frame.CFA.Offset = int64(offset)
}

func defcfaregister(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	frame.CFA.Reg = reg
}

func defcfaoffset(ctx *Context) {
	frame := ctx.currentInstruction()

	offset, _ := util.DecodeULEB128(ctx.buf)
	frame.CFA.Offset = int64(offset)
}

func defcfasf(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	offset, _ := util.DecodeSLEB128(ctx.buf)

	frame.CFA.Rule = RuleCFA
	frame.CFA.Reg = reg
	frame.CFA.Offset = offset * frame.dataAlignment
}

func defcfaoffsetsf(ctx *Context) {
	frame := ctx.currentInstruction()

	offset, _ := util.DecodeSLEB128(ctx.buf)
	offset *= frame.dataAlignment
	frame.CFA.Offset = offset
}

func defcfaexpression(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		l, _ = util.DecodeULEB128(ctx.buf)
		expr = make([]byte, int(l))
	)

	if _, err := ctx.buf.Read(expr); err != nil {
		panic(err)
	}

	frame.CFA.Expression = expr
	frame.CFA.Rule = RuleExpression
}

func expression(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _ = util.DecodeULEB128(ctx.buf)
		l, _   = util.DecodeULEB128(ctx.buf)
	)

	expr := make([]byte, int(l))
	if _, err := ctx.buf.Read(expr); err != nil {
		panic(err)
	}

	rule := DWRule{Rule: RuleExpression, Expression: expr}
	setRule(reg, frame, rule)
}

func offsetextendedsf(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeSLEB128(ctx.buf)
	)

	rule := DWRule{Offset: offset * frame.dataAlignment, Rule: RuleOffset}
	setRule(reg, frame, rule)
}

func valoffset(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeULEB128(ctx.buf)
	)

	rule := DWRule{Offset: int64(offset), Rule: RuleValOffset}
	setRule(reg, frame, rule)
}

func valoffsetsf(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeSLEB128(ctx.buf)
	)

	rule := DWRule{Offset: offset * frame.dataAlignment, Rule: RuleValOffset}
	setRule(reg, frame, rule)
}

func valexpression(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _ = util.DecodeULEB128(ctx.buf)
		l, _   = util.DecodeULEB128(ctx.buf)
	)

	expr := make([]byte, int(l))
	if _, err := ctx.buf.Read(expr); err != nil {
		panic(err)
	}

	rule := DWRule{Rule: RuleValExpression, Expression: expr}
	setRule(reg, frame, rule)
}

func louser(ctx *Context) {
	if _, err := ctx.buf.ReadByte(); err != nil {
		panic(err)
	}
}

func hiuser(ctx *Context) {
	if _, err := ctx.buf.ReadByte(); err != nil {
		panic(err)
	}
}

func gnuargsize(ctx *Context) {
	// The DW_CFA_GNU_args_size instruction takes an unsigned LEB128 operand representing an argument size.
	// Just read and do nothing.
	// TODO(kakkoyun): Implement this.
	_, _ = util.DecodeSLEB128(ctx.buf)
}

// DW_CFA_GNU_window_save and DW_CFA_GNU_NegateRAState have the same value but the latter
// is used in arm64 for return address signing.
func gnuwindowsave(ctx *Context) {
	// Read from buffer but do nothing.
	_, _ = util.DecodeSLEB128(ctx.buf)
}
