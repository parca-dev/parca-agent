## Design of dwarf based stack walking

The DWARF unwind unformation is read from the `.eh_frame` ELF section, parsed, and evaluated to generate unwind tables (see `table.go`). The unwind tables have, for every program counter(*) in an executable, instructions on how to find the stack pointer value before calling the function of the current frame, as well as information on where to find the return address for the current function, as well as how to calculate the value of various registers in the previous frame.

Once we have these tables in memory, we sort them by program counter, and load them in a BPF map.

Once the BPF program has this table, in order to unwind the stack, it will:

1. Fetches the initial registers
   1. The instruction pointer `$rip`. Needed to find the row in the unwind table.
   2. The stack pointer `$rsp`, and the frame pointer `$rbp`, needed to calculate the stack pointer value for the previous frame (CFA). We can find the return address and other registers pushed on the stack at an offset from CFA.
2. While `unwound_frame_count <= MAX_STACK_DEPTH`:
   1. Finds the unwind table row for the PC for which `$found_row_PC <= $target_PC < $PC_after_found_row`.
      1. If there'a not entry for it **and** `$rbp` is zero, we have reached the bottom of the stack
   2. Add instruction pointer to stack
   3. Calculates the previous frame's stack pointer. This can be based off the current frame's `$rsp` or `$rbp`
   4. Updates the registers with the calculated values for the previous frame.
   5. Find next frame. Go to 2.

### Unwind table format

The unwind table is built from an array of rows of type `stack_unwind_row_t`. Each row takes 16 bytes (2x 8 bytes). 4 bytes are used for the program counter, and the rest are split as follows:

```
typedef struct {
  u64 pc;
  u16 __reserved_do_not_use;
  u8 cfa_type;
  u8 rbp_type;
  s16 cfa_offset;
  s16 rbp_offset;
} stack_unwind_row_t;
```

- 2 reserved bytes, which are unused at the moment. They help explicitly align the structure and in the future they will most likely be used to add support for other architectures.
- 1 byte for the CFA "type", whether we should evaluate an expression, if it's stored in a register, or if it's an an offset from `$rsp` or `$rbp`.
- 1 byte for the frame pointer "type", which works as the CFA type field.
- 1 byte for the CFA offset, that stored the offset we should apply to either base register to compute the CFA. If this CFA's rule is an expression, it will contain the expression identifier (`DWARF_EXPRESSION_*`).
- 1 byte for the rbp offset, which can be zero, to indicate that it doesn't change. Otherwise it will be the offset at which the previous frame pointer was pushed in the stack at `$current_rbp + offset`.

### Features / limitations

- **Architecture**: only x86_64 is supported
- **DWARF**:
  - Based on version 5 of the spec
  - DWARF expressions in Procedure Linkage Tables (PLTs) are supported for CFA's calculation (`DW_CFA_def_cfa_expression`)
  - No dwarf register support (`DW_CFA_register` and others)
  - Support for `.eh_frame` DWARF unwind information
- **Size limitations**: Due to the unwind table's design, there's some limits on the values we can accept:
  - Stacks can have up to 127 frames
  - Offsets' ranges must be between [-32768, 32767]
  - Right now, unwind tables up to 750k items are supported. Applications such as Firefox, Nginx, MySQL, Redpanda, Postgres, Systemd, CPython fit within this limit
- **Runtimes**:
  - We've done most of the testing on GCC and Clang compiled binaries so far.
  - We have mixed .eh_frame + JIT support for JITs that emit code with frame pointers.

_Note_: under active development. We are planning to tackle several of these, such as DWARF expression support. We are also working in providing good error messages as well as metrics on the native stack walker. Let us know if you have any feature request!
