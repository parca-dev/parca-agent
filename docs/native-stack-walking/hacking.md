## Hacking on dwarf based stack walking

Tracking this feature in https://github.com/parca-dev/parca-agent/issues/768.

### Checking that the unwinder is working

The best way to check that the unwinder is working well, besides visually inspecting the profiles it generates, is by reading its statistics. This can be done with

```
$ sudo bpftool prog tracelog | grep stats -A7
            ruby-3224822 [009] d.h2. 105855.824637: bpf_trace_printk: [[ stats for cpu 9 ]]
            ruby-3224822 [009] d.h2. 105855.824638: bpf_trace_printk: success=5393
            ruby-3224822 [009] d.h2. 105855.824638: bpf_trace_printk: unsup_expression=156
            ruby-3224822 [009] d.h2. 105855.824638: bpf_trace_printk: truncated_counter=0
            ruby-3224822 [009] d.h2. 105855.824639: bpf_trace_printk: catchall_count=0
            ruby-3224822 [009] d.h2. 105855.824639: bpf_trace_printk: never=0
            ruby-3224822 [009] d.h2. 105855.824639: bpf_trace_printk: total_counter=5550
            ruby-3224822 [009] d.h2. 105855.824639: bpf_trace_printk: (not_covered_count=67)
```

To find what caused an error, it's useful to run this command:

```
$ sudo bpftool prog tracelog | grep error
```

This is sufficient to troubleshoot the unwinder right now, but soon we will add more fine grained statistics, probably per process, and perhaps we can expose them as Prometheus metrics.

### BPF data checks

The data stored in BPF maps is just a bytes buffer. We interpret it as C data structures for convenience but this means that we need to ensure that the padding and aligment that the C compiler would insert is also inserted when we write to it in the Go side. To make development easier, we have decided to use word-aligned datatypes, in this case, all entries in the table are 8 bytes [1].

To facilitate quick data correctness checking, and to help debugging issues querying the table, there's two helpers to print row entries. One in the BPF side `show_row(stack_unwind_table_t *unwind_table, int index)` and `printRow` in Row.

When `Parca Agent` and the BPF program run, they print some entries' values to help spot check the data is correct.

```
$ sudo bpftool prog tracelog
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
- where are the saved return addresses stored and their values

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
# We mostly want to see that the addresse where the saved return address (previous frame's rip) is is correct. As we can see in the last
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


(*): This is not always the case, such as in DWARF expressions, for example, but an overlwhelming majority of the times it is
