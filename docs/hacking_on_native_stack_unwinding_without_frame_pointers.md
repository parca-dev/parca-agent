## Hacking on `.eh_frame`-based stack unwinding

Tracking this feature in https://github.com/parca-dev/parca-agent/issues/768.

### Design

The DWARF unwind unformation is read from the `.eh_frame` section (tracking other sections in https://github.com/parca-dev/parca-agent/issues/617), parsed, and evaluated to generate unwind tables (see `table.go`, among others). The unwind tables have, for every program counter in an executable, instructions on how to find the stack pointer value before calling the function of the current frame, as well as information on where to find the return address for the current function, as well as how to calculate the value of various registers in the previous frame.

Once we have these tables in memory, we sort them by program counter, and load them in a BPF map.

Once the BPF program has this table, in order to unwind the stack, it will:

1. Fetches the initial registers
   1. The instruction pointer `$rip`. Needed to find the row in the unwind table.
   2. The stack pointer `$rsp`, and the frame pointer `$rbp`, needed to calculate the stack pointer value for the previous frame (CFA). We can find the return address and other registers pushed on the stack at an offset from CFA.
2. While `unwound_frame_count <= MAX_STACK_DEPTH`
   1. Add instruction pointer to stack 
   2. If current instruction pointer is from `main`, we are done. Stop.
   3. Finds the unwind table row for the PC for which `$found_row_PC <= $target_PC < $PC_after_found_row`.
   4. Calculates the previous frame's stack pointer. This can be based off the current frame's `$rsp` or `$rbp`
   5. Updates the registers with the calculated values for the previous frame.
   6. Find next frame. Go to 2.

### BPF data checks

The data stored in BPF maps is just a bytes buffer. We interpret it as C data structures for convenience but this means that we need to ensure that the padding and aligment that the C compiler would insert is also inserted when we write to it in the Go side. To make development easier, we have decided to use word-aligned datatypes, in this case, all entries in the table are 8 bytes [1].

To facilitate quick data correctness checking, and to help debugging issues querying the table, there's two helpers to print row entries. One in the BPF side `show_row(stack_unwind_table_t *unwind_table, int index)` and `printRow` in Row.

When `Parca Agent` and the BPF program run, they print some entries' values to help spot check the data is correct. 

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
[...]
 - unwind table has 60969 items
[...]
  parca-demo-cpp-318748  [006] d.h2. 17414.354239: bpf_trace_printk: ~ 0 entry. Loc: 401020, CFA reg: 7 Offset: 16, $rbp 0
  parca-demo-cpp-318748  [006] d.h2. 17414.354239: bpf_trace_printk: ~ 1 entry. Loc: 401026, CFA reg: 7 Offset: 24, $rbp 0
  parca-demo-cpp-318748  [006] d.h2. 17414.354240: bpf_trace_printk: ~ 2 entry. Loc: 401030, CFA reg: 7 Offset: 24, $rbp 0
  parca-demo-cpp-318748  [006] d.h2. 17414.354240: bpf_trace_printk: ~ 60968 entry. Loc: 7f462ffd0ca0, CFA reg: 7 Offset: 8, $rbp 0
[...]
``` 

On the Agent:

```
  - Total entries 60969

        row[0]. Loc: 401020, CFA Reg: 7 Offset:16, $rbp: 0
        row[1]. Loc: 401026, CFA Reg: 7 Offset:24, $rbp: 0
        row[2]. Loc: 401030, CFA Reg: 7 Offset:24, $rbp: 0
        row[60968]. Loc: 7f462ffd0ca0, CFA Reg: 7 Offset:8, $rbp: 0
```

## Making sure that the stack is correct

GDB is very useful to verify that stack unwinding worked fine. We are mostly interested in checking:
- the frame's registers
- where are the return addresses stored and their values

Let's take `./internal/dwarf/frame/testdata/parca-demo-cpp-no-fp`'s output and make sure that the stack is correct:

<details>

```
parca-demo-cpp--1226527 [007] d.h2. 83153.230672: bpf_trace_printk: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
parca-demo-cpp--1226527 [007] d.h2. 83153.230673: bpf_trace_printk: traversing stack using .eh_frame information!!
parca-demo-cpp--1226527 [007] d.h2. 83153.230674: bpf_trace_printk: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
parca-demo-cpp--1226527 [007] d.h2. 83153.230675: bpf_trace_printk: - unwind table has 60957 items
parca-demo-cpp--1226527 [007] d.h2. 83153.230675: bpf_trace_printk: - main pc range 401260...4012d8
parca-demo-cpp--1226527 [007] d.h2. 83153.230676: bpf_trace_printk: ## frame: 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230676: bpf_trace_printk:    current pc: 4011e0
parca-demo-cpp--1226527 [007] d.h2. 83153.230677: bpf_trace_printk:    current sp: 7ffcaee95f08
parca-demo-cpp--1226527 [007] d.h2. 83153.230677: bpf_trace_printk:    current bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230678: bpf_trace_printk:    .done
parca-demo-cpp--1226527 [007] d.h2. 83153.230678: bpf_trace_printk:    => table_index: 12
parca-demo-cpp--1226527 [007] d.h2. 83153.230679: bpf_trace_printk:    cfa reg: $rsp, offset: 8 (pc: 4011d0)
parca-demo-cpp--1226527 [007] d.h2. 83153.230680: bpf_trace_printk:    previous ip: 401206 (@ 7ffcaee95f08)
parca-demo-cpp--1226527 [007] d.h2. 83153.230681: bpf_trace_printk:    previous sp: 7ffcaee95f10
parca-demo-cpp--1226527 [007] d.h2. 83153.230681: bpf_trace_printk:    bp offset 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230681: bpf_trace_printk:    previous bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230682: bpf_trace_printk: ## frame: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230682: bpf_trace_printk:    current pc: 401206
parca-demo-cpp--1226527 [007] d.h2. 83153.230682: bpf_trace_printk:    current sp: 7ffcaee95f10
parca-demo-cpp--1226527 [007] d.h2. 83153.230683: bpf_trace_printk:    current bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230684: bpf_trace_printk:    .done
parca-demo-cpp--1226527 [007] d.h2. 83153.230684: bpf_trace_printk:    => table_index: 14
parca-demo-cpp--1226527 [007] d.h2. 83153.230685: bpf_trace_printk:    cfa reg: $rsp, offset: 16 (pc: 401201)
parca-demo-cpp--1226527 [007] d.h2. 83153.230685: bpf_trace_printk:    previous ip: 401216 (@ 7ffcaee95f18)
parca-demo-cpp--1226527 [007] d.h2. 83153.230686: bpf_trace_printk:    previous sp: 7ffcaee95f20
parca-demo-cpp--1226527 [007] d.h2. 83153.230686: bpf_trace_printk:    bp offset 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230686: bpf_trace_printk:    previous bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230687: bpf_trace_printk: ## frame: 2
parca-demo-cpp--1226527 [007] d.h2. 83153.230687: bpf_trace_printk:    current pc: 401216
parca-demo-cpp--1226527 [007] d.h2. 83153.230687: bpf_trace_printk:    current sp: 7ffcaee95f20
parca-demo-cpp--1226527 [007] d.h2. 83153.230688: bpf_trace_printk:    current bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230688: bpf_trace_printk:    .done
parca-demo-cpp--1226527 [007] d.h2. 83153.230689: bpf_trace_printk:    => table_index: 17
parca-demo-cpp--1226527 [007] d.h2. 83153.230689: bpf_trace_printk:    cfa reg: $rsp, offset: 16 (pc: 401211)
parca-demo-cpp--1226527 [007] d.h2. 83153.230690: bpf_trace_printk:    previous ip: 401226 (@ 7ffcaee95f28)
parca-demo-cpp--1226527 [007] d.h2. 83153.230690: bpf_trace_printk:    previous sp: 7ffcaee95f30
parca-demo-cpp--1226527 [007] d.h2. 83153.230691: bpf_trace_printk:    bp offset 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230691: bpf_trace_printk:    previous bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230691: bpf_trace_printk: ## frame: 3
parca-demo-cpp--1226527 [007] d.h2. 83153.230692: bpf_trace_printk:    current pc: 401226
parca-demo-cpp--1226527 [007] d.h2. 83153.230692: bpf_trace_printk:    current sp: 7ffcaee95f30
parca-demo-cpp--1226527 [007] d.h2. 83153.230692: bpf_trace_printk:    current bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230693: bpf_trace_printk:    .done
parca-demo-cpp--1226527 [007] d.h2. 83153.230693: bpf_trace_printk:    => table_index: 20
parca-demo-cpp--1226527 [007] d.h2. 83153.230694: bpf_trace_printk:    cfa reg: $rsp, offset: 16 (pc: 401221)
parca-demo-cpp--1226527 [007] d.h2. 83153.230694: bpf_trace_printk:    previous ip: 401299 (@ 7ffcaee95f38)
parca-demo-cpp--1226527 [007] d.h2. 83153.230695: bpf_trace_printk:    previous sp: 7ffcaee95f40
parca-demo-cpp--1226527 [007] d.h2. 83153.230695: bpf_trace_printk:    bp offset 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230695: bpf_trace_printk:    previous bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230696: bpf_trace_printk: ## frame: 4
parca-demo-cpp--1226527 [007] d.h2. 83153.230696: bpf_trace_printk:    current pc: 401299
parca-demo-cpp--1226527 [007] d.h2. 83153.230696: bpf_trace_printk:    current sp: 7ffcaee95f40
parca-demo-cpp--1226527 [007] d.h2. 83153.230697: bpf_trace_printk:    current bp: 1
parca-demo-cpp--1226527 [007] d.h2. 83153.230697: bpf_trace_printk: ======= reached main! =======
parca-demo-cpp--1226527 [007] d.h2. 83153.230698: bpf_trace_printk: ~ 0 entry. Loc: 401020, CFA reg: 7 Offset: 16, $rbp 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230699: bpf_trace_printk: ~ 1 entry. Loc: 401026, CFA reg: 7 Offset: 24, $rbp 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230700: bpf_trace_printk: ~ 2 entry. Loc: 401030, CFA reg: 7 Offset: 24, $rbp 0
parca-demo-cpp--1226527 [007] d.h2. 83153.230701: bpf_trace_printk: ~ 60956 entry. Loc: 7f0fa57f4ca0, CFA reg: 7 Offset: 8, $rbp 0
```

</details>

For the first frame (minus the columns we don't care about right now), we have that:

```
## frame: 0
   current pc: 4011e0
   current sp: 7ffcaee95f08
   current bp: 1
   .done
   => table_index: 12
   cfa reg: $rsp, offset: 8 (pc: 4011d0)
   previous ip: 401206 (@ 7ffcaee95f08)
   previous sp: 7ffcaee95f10
   bp offset 0
   previous bp: 1
```

So let's set a breapoint in this program counter and check the different data:

```
$ sudo gdb -p $(pidof parca-demo-cpp-no-fp)
# Setting a breakpoint at the PC
(gdb) b *0x4011e0
Breakpoint 1 at 0x4011e0
# Let's continue until we hit it
(gdb) c
Continuing.
Breakpoint 1, 0x00000000004011e0 in top() ()
# We are in top(), let's now take a look at the registers
(gdb) p/x $rip
$1 = 0x4011e0
(gdb) p/x $rsp
$2 = 0x7ffcaee95f08
(gdb) p/x $rbp
$3 = 0x1
# Cool! Seems that all the registers match so far. Let's take a look at the frame information
(gdb) info frame 0
Stack frame at 0x7ffcaee95f10:
 rip = 0x4011e0 in top(); saved rip = 0x401206
 called by frame at 0x7ffcaee95f20
 Arglist at 0x7ffcaee95f00, args: 
 Locals at 0x7ffcaee95f00, Previous frame's sp is 0x7ffcaee95f10
 Saved registers:
  rip at 0x7ffcaee95f08
# We mostly want to see that the addresse where the return address (rip) is is correct. As we can see in the last
# line, it matches what we expect (0x7ffcaee95f08).
# The first line shows rip's value (0x401206), that also matches what we expect. This address is the program counter
# that the processor should execute once the current function exits. It's pushed into the stack with a `call` instruciton.
```

Let's go check the frame above
```
## frame: 1
   current pc: 401206
   current sp: 7ffcaee95f10
   current bp: 1
   .done
   => table_index: 14
   cfa reg: $rsp, offset: 16 (pc: 401201)
   previous ip: 401216 (@ 7ffcaee95f18)
   previous sp: 7ffcaee95f20
   bp offset 0
   previous bp: 1
```

```
# Let's go one frame up in the stack
(gdb) up 
#1  0x0000000000401206 in c1() ()
(gdb) p/x $rip
$2 = 0x401206
(gdb) p/x $rsp
$3 = 0x7ffcaee95f10
(gdb) p/x $rbp
$4 = 0x1
# All good here :)
(gdb) info frame
Stack level 1, frame at 0x7ffcaee95f20:
 rip = 0x401206 in c1(); saved rip = 0x401216
 called by frame at 0x7ffcaee95f30, caller of frame at 0x7ffcaee95f10
 Arglist at 0x7ffcaee95f08, args: 
 Locals at 0x7ffcaee95f08, Previous frame's sp is 0x7ffcaee95f20
 Saved registers:
  rip at 0x7ffcaee95f18
# As we did before, let's check the return address (0x401216), as 
# well as where it's located (0x7ffcaee95f18). Great success so far!
```

This process should be repeated for each frame until we reach the last frame of the stack.

## Debugging the unwind tables

When there's a suspicion of the table data not being correct, the two small helpers to print a row of the table can be very useful. To inspect the row table output manually: 

```
$ dist/eh-frame --executable <executable>
$ readelf -wF <executable>
```

It can be useful to see a function's disassembly in GDB to check if the row values make sense

```
(gdb) disassemble 0x401216
Dump of assembler code for function _Z2b1v:
   0x0000000000401210 <+0>:     push   %rax
   0x0000000000401211 <+1>:     call   0x401200 <_Z2c1v>
   0x0000000000401216 <+6>:     pop    %rcx                       <===== the instruction for this program counter
   0x0000000000401217 <+7>:     ret    
End of assembler dump.
```


## Debugging notes

Remember than when running GDB on a process, the debugee will go into traced `t` state when a breakpoint is hit, and it will not run, so it will be de-scheduled from the CPU and the profiler will show no samples.

Another thing to bear in mind when setting breakpoints is that there could be more than one path that leads to a particular program counter. This is important when checking for specific register and return address values, as this particular code path might not match what we saw in another trace. 


## Notes

- [1]: This is of course not very efficient. Once the implementation is more mature, we will use the smallest data types we can, but we need to be careful and ensure that the C ABI is correct while loading data in the BPF maps.