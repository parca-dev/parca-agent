//nolint:stylecheck,deadcode,unused
package frame

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
)

// DWRule wrapper of rule defined for register values.
type DWRule struct {
	Rule       Rule
	Offset     int64
	Reg        uint64
	Expression []byte
}

// InstructionContext represents each object code instruction
// that we have unwind information for.
type InstructionContext struct {
	loc           uint64
	address       uint64
	CFA           DWRule
	Regs          map[uint64]DWRule
	initialRegs   map[uint64]DWRule
	cie           *CommonInformationEntry
	RetAddrReg    uint64
	codeAlignment uint64
	dataAlignment int64
}

func (instructionContext *InstructionContext) Loc() uint64 {
	return instructionContext.loc
}

// RowState is a stack where `DW_CFA_remember_state` pushes
// its CFA and registers state and `DW_CFA_restore_state`
// pops them.
type RowState struct {
	cfa  DWRule
	regs map[uint64]DWRule
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

// Context represents a function.
type Context struct {
	// An entry for each object code instruction that we have unwind information for.
	instructions    []InstructionContext
	rememberedState *StateStack
	// The buffer where we store the dwarf unwind entries to be parsed for this function.
	buf   *bytes.Buffer
	order binary.ByteOrder
}

func (ctx *Context) currentInstruction() *InstructionContext {
	return &ctx.instructions[len(ctx.instructions)-1]
}

func (ctx *Context) InstructionContexts() []InstructionContext {
	return ctx.instructions
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
	DW_CFA_GNU_window_save              = 0x2d
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

// Rule rule defined for register values.
type Rule byte

const (
	RuleUndefined Rule = iota
	RuleSameVal
	RuleOffset
	RuleValOffset
	RuleRegister
	RuleExpression
	RuleValExpression
	RuleArchitectural
	RuleCFA          // Value is rule.Reg + rule.Offset
	RuleFramePointer // Value is stored at address rule.Reg + rule.Offset, but only if it's less than the current CFA, otherwise same value
)

const low_6_offset = 0x3f

type instruction func(ctx *Context)

// Mapping from DWARF opcode to function.
var fnlookup = map[byte]instruction{
	DW_CFA_advance_loc:        advanceloc,
	DW_CFA_offset:             offset,
	DW_CFA_restore:            restore,
	DW_CFA_set_loc:            setloc,
	DW_CFA_advance_loc1:       advanceloc1,
	DW_CFA_advance_loc2:       advanceloc2,
	DW_CFA_advance_loc4:       advanceloc4,
	DW_CFA_offset_extended:    offsetextended,
	DW_CFA_restore_extended:   restoreextended,
	DW_CFA_undefined:          undefined,
	DW_CFA_same_value:         samevalue,
	DW_CFA_register:           register,
	DW_CFA_remember_state:     rememberstate,
	DW_CFA_restore_state:      restorestate,
	DW_CFA_def_cfa:            defcfa,
	DW_CFA_def_cfa_register:   defcfaregister,
	DW_CFA_def_cfa_offset:     defcfaoffset,
	DW_CFA_def_cfa_expression: defcfaexpression,
	DW_CFA_expression:         expression,
	DW_CFA_offset_extended_sf: offsetextendedsf,
	DW_CFA_def_cfa_sf:         defcfasf,
	DW_CFA_def_cfa_offset_sf:  defcfaoffsetsf,
	DW_CFA_val_offset:         valoffset,
	DW_CFA_val_offset_sf:      valoffsetsf,
	DW_CFA_val_expression:     valexpression,
	DW_CFA_lo_user:            louser,
	DW_CFA_hi_user:            hiuser,
	DW_CFA_GNU_args_size:      gnuargsize,
}

func executeCIEInstructions(cie *CommonInformationEntry) *Context {
	initialInstructions := make([]byte, len(cie.InitialInstructions))
	copy(initialInstructions, cie.InitialInstructions)

	frames := make([]InstructionContext, 0)
	frames = append(frames, InstructionContext{
		cie:           cie,
		Regs:          make(map[uint64]DWRule),
		RetAddrReg:    cie.ReturnAddressRegister,
		codeAlignment: cie.CodeAlignmentFactor,
		dataAlignment: cie.DataAlignmentFactor,
	})

	frame := &Context{
		instructions:    frames,
		buf:             bytes.NewBuffer(initialInstructions),
		rememberedState: newStateStack(),
	}
	frame.executeDwarfProgram()
	return frame
}

// Unwind the stack to find the return address register.
func executeDwarfProgramUntilPC(fde *FrameDescriptionEntry, pc uint64) *Context {
	ctx := executeCIEInstructions(fde.CIE)
	frame := ctx.currentInstruction()
	ctx.order = fde.order
	frame.loc = fde.Begin()
	frame.address = pc
	return ctx
}

// ExecuteDwarfProgram unwinds the stack to find the return address register.
func ExecuteDwarfProgram(fde *FrameDescriptionEntry) *Context {
	ctx := executeCIEInstructions(fde.CIE)
	ctx.order = fde.order
	frame := ctx.currentInstruction()
	frame.loc = fde.Begin()
	// frame.address = pc
	ctx.Execute(fde.Instructions)
	return ctx
}

func (ctx *Context) executeDwarfProgram() {
	for ctx.buf.Len() > 0 {
		executeDwarfInstruction(ctx)
	}
}

// ExecuteUntilPC execute dwarf instructions.
func (ctx *Context) ExecuteUntilPC(instructions []byte) {
	ctx.buf.Truncate(0)
	ctx.buf.Write(instructions)

	// We only need to execute the instructions until
	// ctx.loc > ctx.address (which is the address we
	// are currently at in the traced process).
	frame := ctx.currentInstruction()
	for frame.address >= frame.loc && ctx.buf.Len() > 0 {
		executeDwarfInstruction(ctx)
	}
}

// Execute execute dwarf instructions.
func (ctx *Context) Execute(instructions []byte) {
	ctx.buf.Truncate(0)
	ctx.buf.Write(instructions)

	for ctx.buf.Len() > 0 {
		_ = executeDwarfInstruction(ctx)
		// fmt.Fprintf(os.Stderr, "----------- dwarf instruction: %s at index %d\n", CFAString(ins), len(ctx.instructions))
	}
}

func executeDwarfInstruction(ctx *Context) byte {
	instruction, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read from instruction buffer")
	}

	if instruction == DW_CFA_nop {
		return instruction
	}

	fn, instruction := lookupFunc(instruction, ctx.buf)
	fn(ctx)

	return instruction
}

func lookupFunc(instruction byte, buf *bytes.Buffer) (instruction, byte) {
	const high_2_bits = 0xc0
	var restore bool

	// Special case the 3 opcodes that have their argument encoded in the opcode itself.
	switch instruction & high_2_bits {
	case DW_CFA_advance_loc:
		instruction = DW_CFA_advance_loc
		restore = true

	case DW_CFA_offset:
		instruction = DW_CFA_offset
		restore = true

	case DW_CFA_restore:
		instruction = DW_CFA_restore
		restore = true
	}

	if restore {
		// Restore the last byte as it actually contains the argument for the opcode.
		err := buf.UnreadByte()
		if err != nil {
			panic("Could not unread byte")
		}
	}

	fn, ok := fnlookup[instruction]
	if !ok {
		panic(fmt.Sprintf("Encountered an unexpected DWARF CFA opcode: %#v", instruction))
	}

	return fn, instruction
}

// newContext set a new instruction context. This must
// be called on every advanceloc* opcode.
func newContext(ctx *Context) *InstructionContext {
	lastFrame := ctx.currentInstruction()
	ctx.instructions = append(ctx.instructions,
		InstructionContext{
			loc:           lastFrame.loc,
			cie:           lastFrame.cie,
			Regs:          make(map[uint64]DWRule, len(lastFrame.Regs)),
			RetAddrReg:    lastFrame.cie.ReturnAddressRegister,
			CFA:           lastFrame.CFA,
			initialRegs:   make(map[uint64]DWRule, len(lastFrame.initialRegs)),
			codeAlignment: lastFrame.cie.CodeAlignmentFactor,
			dataAlignment: lastFrame.cie.DataAlignmentFactor,
		},
	)

	// Copy registers from the current frame to the new one.
	frame := ctx.currentInstruction()
	for k, v := range lastFrame.Regs {
		frame.Regs[k] = v
	}
	for k, v := range lastFrame.initialRegs {
		frame.initialRegs[k] = v
	}

	return frame
}

func advanceloc(ctx *Context) {
	frame := newContext(ctx)

	b, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	delta := b & low_6_offset
	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc1(ctx *Context) {
	frame := newContext(ctx)

	delta, err := ctx.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc2(ctx *Context) {
	frame := newContext(ctx)

	var delta uint16
	err := binary.Read(ctx.buf, ctx.order, &delta)
	if err != nil {
		panic("Could not read from buffer")
	}
	frame.loc += uint64(delta) * frame.codeAlignment
}

func advanceloc4(ctx *Context) {
	frame := newContext(ctx)

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

	frame.Regs[uint64(reg)] = DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
}

func restore(ctx *Context) {
	frame := ctx.currentInstruction()

	b, err := ctx.buf.ReadByte()
	if err != nil {
		panic(err)
	}

	reg := uint64(b & low_6_offset)
	oldrule, ok := frame.initialRegs[reg]
	if ok {
		frame.Regs[reg] = DWRule{Offset: oldrule.Offset, Rule: RuleOffset}
	} else {
		frame.Regs[reg] = DWRule{Rule: RuleUndefined}
	}
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

	frame.Regs[reg] = DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
}

func undefined(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	frame.Regs[reg] = DWRule{Rule: RuleUndefined}
}

func samevalue(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)
	frame.Regs[reg] = DWRule{Rule: RuleSameVal}
}

func register(ctx *Context) {
	frame := ctx.currentInstruction()

	reg1, _ := util.DecodeULEB128(ctx.buf)
	reg2, _ := util.DecodeULEB128(ctx.buf)
	frame.Regs[reg1] = DWRule{Reg: reg2, Rule: RuleRegister}
}

func rememberstate(ctx *Context) {
	frame := ctx.currentInstruction()

	state := RowState{
		cfa:  frame.CFA,
		regs: make(map[uint64]DWRule),
	}
	for k, v := range frame.Regs {
		state.regs[k] = v
	}

	ctx.rememberedState.push(state)
}

func restorestate(ctx *Context) {
	frame := ctx.currentInstruction()
	restored := ctx.rememberedState.pop()

	frame.CFA = restored.cfa
	for k, v := range restored.regs {
		frame.Regs[k] = v
	}
}

func restoreextended(ctx *Context) {
	frame := ctx.currentInstruction()

	reg, _ := util.DecodeULEB128(ctx.buf)

	oldrule, ok := frame.initialRegs[reg]
	if ok {
		frame.Regs[reg] = DWRule{Offset: oldrule.Offset, Rule: RuleOffset}
	} else {
		frame.Regs[reg] = DWRule{Rule: RuleUndefined}
	}
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
		expr = ctx.buf.Next(int(l))
	)

	frame.CFA.Expression = expr
	frame.CFA.Rule = RuleExpression
}

func expression(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _ = util.DecodeULEB128(ctx.buf)
		l, _   = util.DecodeULEB128(ctx.buf)
		expr   = ctx.buf.Next(int(l))
	)

	frame.Regs[reg] = DWRule{Rule: RuleExpression, Expression: expr}
}

func offsetextendedsf(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeSLEB128(ctx.buf)
	)

	frame.Regs[reg] = DWRule{Offset: offset * frame.dataAlignment, Rule: RuleOffset}
}

func valoffset(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeULEB128(ctx.buf)
	)

	frame.Regs[reg] = DWRule{Offset: int64(offset), Rule: RuleValOffset}
}

func valoffsetsf(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _    = util.DecodeULEB128(ctx.buf)
		offset, _ = util.DecodeSLEB128(ctx.buf)
	)

	frame.Regs[reg] = DWRule{Offset: offset * frame.dataAlignment, Rule: RuleValOffset}
}

func valexpression(ctx *Context) {
	frame := ctx.currentInstruction()

	var (
		reg, _ = util.DecodeULEB128(ctx.buf)
		l, _   = util.DecodeULEB128(ctx.buf)
		expr   = ctx.buf.Next(int(l))
	)

	frame.Regs[reg] = DWRule{Rule: RuleValExpression, Expression: expr}
}

func louser(ctx *Context) {
	ctx.buf.Next(1)
}

func hiuser(ctx *Context) {
	ctx.buf.Next(1)
}

func gnuargsize(ctx *Context) {
	// The DW_CFA_GNU_args_size instruction takes an unsigned LEB128 operand representing an argument size.
	// Just read and do nothing.
	// TODO(kakkoyun): Implement this.
	_, _ = util.DecodeSLEB128(ctx.buf)
}
