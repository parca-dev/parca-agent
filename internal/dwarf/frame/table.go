// nolint:stylecheck,deadcode
package frame

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
)

// TODO(javierhonduco): Add source
const RBPRegister = 6

// DWRule wrapper of rule defined for register values.
type DWRule struct {
	Rule Rule
	// TODO(javierhonduco): replace with a smaller data type
	Offset int64
	// TODO(javierhonduco):
	// - replace with a smaller data type
	// - use 0 as a sentinel value to indicate that it was never
	//   set and store registers starting from 1
	Reg        uint64
	Expression []byte
}

// Represents each object code instruction, rather than
// DWARF opcodes.
//
// Notes:
// - probs many of these fields should be (re)moved.
// - in another step we would remove redundant entries, e.g.:
// 		0000000000401121 rsp+16   c-16  c-8
// 		0000000000401124 rbp+16   c-16  c-8
// 	 by grouping them together.
type InstructionContext struct {
	loc     uint64
	address uint64
	CFA     DWRule
	// TODO(javierhonduco): do we need all these fields above?
	Regs        map[uint64]DWRule
	initialRegs map[uint64]DWRule
	prevRegs    map[uint64]DWRule
	cie         *CommonInformationEntry
	// TODO(javierhonduco): replace with a smaller data types
	RetAddrReg    uint64
	codeAlignment uint64
	dataAlignment int64
}

func (instructionContext *InstructionContext) Loc() uint64 {
	return instructionContext.loc
}

// Represents a whole native function.
type FrameContext struct {
	// An entry for each machine code instruction (not DWARF instructions)
	instructions []InstructionContext
	// The buffer where we store the .eh_frame entries to be parsed for this function.
	buf   *bytes.Buffer
	order binary.ByteOrder
}

func (frameContext *FrameContext) getCurrentInstruction() *InstructionContext {
	return &frameContext.instructions[len(frameContext.instructions)-1]
}

func (frameContext *FrameContext) GetAllInstructionContexts() []InstructionContext {
	return frameContext.instructions
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
	// TODO(kakkoyun): Implement noop funcs that skips corresponding bytes.
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

type instruction func(frameContext *FrameContext)

// // Mapping from DWARF opcode to function.
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

func executeCIEInstructions(cie *CommonInformationEntry) *FrameContext {
	initialInstructions := make([]byte, len(cie.InitialInstructions))
	copy(initialInstructions, cie.InitialInstructions)

	frames := make([]InstructionContext, 0)
	frames = append(frames, InstructionContext{
		cie:           cie,
		Regs:          make(map[uint64]DWRule),
		RetAddrReg:    cie.ReturnAddressRegister,
		initialRegs:   make(map[uint64]DWRule),
		prevRegs:      make(map[uint64]DWRule),
		codeAlignment: cie.CodeAlignmentFactor,
		dataAlignment: cie.DataAlignmentFactor,
	})

	frame := &FrameContext{
		instructions: frames,
		buf:          bytes.NewBuffer(initialInstructions),
	}
	// TODO: Uncommenting this as this gets us the correct first row
	// but 2nd row is still incorrect. executeDwarfProgram needs to be
	// fixed.
	frame.executeDwarfProgram()
	return frame
}

// Unwind the stack to find the return address register.
func executeDwarfProgramUntilPC(fde *DescriptionEntry, pc uint64) *FrameContext {
	frameContext := executeCIEInstructions(fde.CIE)
	frame := frameContext.getCurrentInstruction()
	frameContext.order = fde.order
	frame.loc = fde.Begin()
	frame.address = pc

	return frameContext
}

// ExecuteDwarfProgram unwinds the stack to find the return address register.
func ExecuteDwarfProgram(fde *DescriptionEntry) *FrameContext {
	frameContext := executeCIEInstructions(fde.CIE)
	frameContext.order = fde.order
	frame := frameContext.getCurrentInstruction()
	frame.loc = fde.Begin()
	// frame.address = pc
	frameContext.Execute(fde.Instructions)
	return frameContext
}

func (frameContext *FrameContext) executeDwarfProgram() {
	for frameContext.buf.Len() > 0 {
		executeDwarfInstruction(frameContext)
	}
}

// ExecuteUntilPC execute dwarf instructions.
func (frameContext *FrameContext) ExecuteUntilPC(instructions []byte) {
	frameContext.buf.Truncate(0)
	frameContext.buf.Write(instructions)

	// We only need to execute the instructions until
	// ctx.loc > ctx.address (which is the address we
	// are currently at in the traced process).
	frame := frameContext.getCurrentInstruction()
	// TODO CHANGE
	for frame.address >= frame.loc && frameContext.buf.Len() > 0 {
		executeDwarfInstruction(frameContext)
	}
}

// Execute execute dwarf instructions.
func (frameContext *FrameContext) Execute(instructions []byte) {
	frameContext.buf.Truncate(0)
	frameContext.buf.Write(instructions)

	// TODO(kakkoyun): Cleanup.

	// We only need to execute the instructions until
	// ctx.loc > ctx.address (which is the address we
	// are currently at in the traced process).
	// for frame.address >= frame.loc &&

	for frameContext.buf.Len() > 0 {
		/* ins :=  */ executeDwarfInstruction(frameContext)
		// Just for debugging:
		// fmt.Fprintf(os.Stderr, "----------- dwarf instruction: %s at index %d\n", CFAString(ins), len(frameContext.instructions))
	}
}

func executeDwarfInstruction(frameContext *FrameContext) byte {
	instruction, err := frameContext.buf.ReadByte()
	if err != nil {
		panic("Could not read from instruction buffer")
	}

	if instruction == DW_CFA_nop {
		return instruction
	}

	fn, instruction := lookupFunc(instruction, frameContext.buf)
	fn(frameContext)

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
		// msg := fmt.Sprintf("Encountered an unexpected DWARF CFA opcode: %#v", instruction)
		// fmt.Println(msg)
		// return unknown

		// TODO(kakkoyun): Why do we have to panic?
		panic(fmt.Sprintf("Encountered an unexpected DWARF CFA opcode: %#v", instruction))
	}

	return fn, instruction
}

// new inst!
func advanceloc(frameContext *FrameContext) {
	currentFrame := frameContext.getCurrentInstruction()

	// HACK?(javierhonduco): reusing prev frame stuff.
	// Have to look into what should be reset, if anything.
	frameContext.instructions = append(frameContext.instructions,
		InstructionContext{
			loc:           currentFrame.loc,
			cie:           currentFrame.cie,
			Regs:          make(map[uint64]DWRule),
			RetAddrReg:    currentFrame.cie.ReturnAddressRegister,
			CFA:           currentFrame.CFA,
			initialRegs:   make(map[uint64]DWRule),
			prevRegs:      make(map[uint64]DWRule),
			codeAlignment: currentFrame.cie.CodeAlignmentFactor,
			dataAlignment: currentFrame.cie.DataAlignmentFactor,
		},
	)

	frame := frameContext.getCurrentInstruction()

	b, err := frameContext.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	delta := b & low_6_offset
	frame.loc += uint64(delta) * frame.codeAlignment

	// Copy registers from the current frame to the new one.
	for k, v := range currentFrame.Regs {
		frame.Regs[k] = v
	}
}

func advanceloc1(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()
	delta, err := frameContext.buf.ReadByte()
	if err != nil {
		panic("Could not read byte")
	}

	frame.loc += uint64(delta) * frame.codeAlignment

}

func advanceloc2(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var delta uint16
	_ = binary.Read(frameContext.buf, frameContext.order, &delta)

	frame.loc += uint64(delta) * frame.codeAlignment

}

func advanceloc4(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var delta uint32
	_ = binary.Read(frameContext.buf, frameContext.order, &delta)

	frame.loc += uint64(delta) * frame.codeAlignment

}

func offset(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	b, err := frameContext.buf.ReadByte()
	if err != nil {
		panic(err)
	}

	var (
		reg       = b & low_6_offset
		offset, _ = util.DecodeULEB128(frameContext.buf)
	)

	// fmt.Println("register", reg, "set to dwrule ...")
	frame.Regs[uint64(reg)] = DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
}

func restore(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	b, err := frameContext.buf.ReadByte()
	if err != nil {
		panic(err)
	}

	reg := uint64(b & low_6_offset)
	oldrule, ok := frame.initialRegs[reg]
	if ok {
		// fmt.Println("register", reg, "set to dwrule ---")
		frame.Regs[reg] = DWRule{Offset: oldrule.Offset, Rule: RuleOffset}
	} else {
		frame.Regs[reg] = DWRule{Rule: RuleUndefined}
	}
}

func setloc(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var loc uint64
	_ = binary.Read(frameContext.buf, frameContext.order, &loc)

	frame.loc = loc + frame.cie.staticBase

}

func offsetextended(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _    = util.DecodeULEB128(frameContext.buf)
		offset, _ = util.DecodeULEB128(frameContext.buf)
	)

	// fmt.Println("register", reg, "set to offsete")
	frame.Regs[reg] = DWRule{Offset: int64(offset) * frame.dataAlignment, Rule: RuleOffset}
}

func undefined(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)
	// fmt.Println("register", reg, "set to undefined")
	frame.Regs[reg] = DWRule{Rule: RuleUndefined}
}

func samevalue(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)
	// fmt.Println("register", reg, "set to sameval")
	frame.Regs[reg] = DWRule{Rule: RuleSameVal}
}

func register(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg1, _ := util.DecodeULEB128(frameContext.buf)
	reg2, _ := util.DecodeULEB128(frameContext.buf)
	// fmt.Println("register", reg1, "set to ", reg2)
	frame.Regs[reg1] = DWRule{Reg: reg2, Rule: RuleRegister}
}

func rememberstate(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	frame.prevRegs = frame.Regs
}

func restorestate(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	// fmt.Println("registers restore")
	frame.Regs = frame.prevRegs
}

func restoreextended(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)

	oldrule, ok := frame.initialRegs[reg]
	if ok {
		// fmt.Println("register", reg, "set to oldrule")

		frame.Regs[reg] = DWRule{Offset: oldrule.Offset, Rule: RuleOffset}
	} else {
		frame.Regs[reg] = DWRule{Rule: RuleUndefined}
	}
}

func defcfa(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)
	offset, _ := util.DecodeULEB128(frameContext.buf)

	frame.CFA.Rule = RuleCFA
	frame.CFA.Reg = reg
	frame.CFA.Offset = int64(offset)
}

func defcfaregister(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)
	frame.CFA.Reg = reg
}

func defcfaoffset(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	offset, _ := util.DecodeULEB128(frameContext.buf)
	frame.CFA.Offset = int64(offset)
}

func defcfasf(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	reg, _ := util.DecodeULEB128(frameContext.buf)
	offset, _ := util.DecodeSLEB128(frameContext.buf)

	frame.CFA.Rule = RuleCFA
	frame.CFA.Reg = reg
	frame.CFA.Offset = offset * frame.dataAlignment
}

func defcfaoffsetsf(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	offset, _ := util.DecodeSLEB128(frameContext.buf)
	offset *= frame.dataAlignment
	frame.CFA.Offset = offset
}

func defcfaexpression(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		l, _ = util.DecodeULEB128(frameContext.buf)
		expr = frameContext.buf.Next(int(l))
	)

	frame.CFA.Expression = expr
	frame.CFA.Rule = RuleExpression
}

func expression(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _ = util.DecodeULEB128(frameContext.buf)
		l, _   = util.DecodeULEB128(frameContext.buf)
		expr   = frameContext.buf.Next(int(l))
	)

	// fmt.Println("register", reg, "set to expression")
	frame.Regs[reg] = DWRule{Rule: RuleExpression, Expression: expr}
}

func offsetextendedsf(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _    = util.DecodeULEB128(frameContext.buf)
		offset, _ = util.DecodeSLEB128(frameContext.buf)
	)

	// fmt.Println("register", reg, "set to dwrule")
	frame.Regs[reg] = DWRule{Offset: offset * frame.dataAlignment, Rule: RuleOffset}
}

func valoffset(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _    = util.DecodeULEB128(frameContext.buf)
		offset, _ = util.DecodeULEB128(frameContext.buf)
	)

	// fmt.Println("register", reg, "set to dwrule")
	frame.Regs[reg] = DWRule{Offset: int64(offset), Rule: RuleValOffset}
}

func valoffsetsf(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _    = util.DecodeULEB128(frameContext.buf)
		offset, _ = util.DecodeSLEB128(frameContext.buf)
	)

	// fmt.Println("register", reg, "set to offset")
	frame.Regs[reg] = DWRule{Offset: offset * frame.dataAlignment, Rule: RuleValOffset}
}

func valexpression(frameContext *FrameContext) {
	frame := frameContext.getCurrentInstruction()

	var (
		reg, _ = util.DecodeULEB128(frameContext.buf)
		l, _   = util.DecodeULEB128(frameContext.buf)
		expr   = frameContext.buf.Next(int(l))
	)

	frame.Regs[reg] = DWRule{Rule: RuleValExpression, Expression: expr}
}

func louser(frameContext *FrameContext) {
	frameContext.buf.Next(1)
}

func hiuser(frameContext *FrameContext) {
	frameContext.buf.Next(1)
}

func gnuargsize(frameContext *FrameContext) {

	// The DW_CFA_GNU_args_size instruction takes an unsigned LEB128 operand representing an argument size.
	// Just read and do nothing.
	// TODO(kakkoyun): Implement this.
	_, _ = util.DecodeSLEB128(frameContext.buf)
}
