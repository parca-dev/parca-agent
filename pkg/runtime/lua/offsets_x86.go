//go:build amd64

package lua

import (
	"errors"
	"slices"

	"golang.org/x/arch/x86/x86asm"
)

var endbr64 = [4]byte{0xf3, 0x0f, 0x1e, 0xfa}

/*
*
Dump of assembler code for function lua_close:

Get the offset global_State pointer in lua_State (glref) and the offset
of the lua_State pointer in global_State (cur_L) from the disassembly of lua_close
which is a dynamic public symbol that should be all binaries of LuaJIT including stripped.

	0x0000000000016d80 <+0>:     push   %r13
	0x0000000000016d82 <+2>:     push   %r12
	0x0000000000016d84 <+4>:     lea    -0x33b(%rip),%r12        # 0x16a50
	0x0000000000016d8b <+11>:    push   %rbp
	0x0000000000016d8c <+12>:    push   %rbx
	0x0000000000016d8d <+13>:    mov    $0xa,%r13d
	0x0000000000016d93 <+19>:    sub    $0x8,%rsp
	0x0000000000016d97 <+23>:    mov    0x10(%rdi),%rbp
	0x0000000000016d9b <+27>:    mov    0xc0(%rbp),%rbx
	0x0000000000016da2 <+34>:    mov    %rbx,%rdi
	0x0000000000016da5 <+37>:    call   0x1f6f0 <luaJIT_profile_stop>
	0x0000000000016daa <+42>:    mov    0x38(%rbx),%rsi
	0x0000000000016dae <+46>:    mov    %rbx,%rdi
	0x0000000000016db1 <+49>:    movq   $0x0,0x170(%rbp)
	0x0000000000016dbc <+60>:    call   0x13210
	0x0000000000016dc1 <+65>:    mov    $0x1,%esi
	0x0000000000016dc6 <+70>:    mov    %rbp,%rdi
	0x0000000000016dc9 <+73>:    call   0xea10
	0x0000000000016dce <+78>:    andl   $0xfffffffe,0x388(%rbp)
	0x0000000000016dd5 <+85>:    movl   $0x0,0x3cc(%rbp)
	0x0000000000016ddf <+95>:    mov    %rbp,%rdi
	0x0000000000016de2 <+98>:    call   0x17220
	0x0000000000016de7 <+103>:   nopw   0x0(%rax,%rax,1)
	0x0000000000016df0 <+112>:   orb    $0x10,0x91(%rbp)
	0x0000000000016df7 <+119>:   xor    %edx,%edx
	0x0000000000016df9 <+121>:   xor    %esi,%esi
	0x0000000000016dfb <+123>:   mov    0x38(%rbx),%rax
	0x0000000000016dff <+127>:   movb   $0x0,0xb(%rbx)
	0x0000000000016e03 <+131>:   mov    %r12,%rcx
	0x0000000000016e06 <+134>:   movq   $0x0,0x50(%rbx)
	0x0000000000016e0e <+142>:   mov    %rbx,%rdi
	0x0000000000016e11 <+145>:   add    $0x10,%rax
	0x0000000000016e15 <+149>:   mov    %rax,0x28(%rbx)
	0x0000000000016e19 <+153>:   mov    %rax,0x20(%rbx)
	0x0000000000016e1d <+157>:   call   0xba8f
	0x0000000000016e22 <+162>:   test   %eax,%eax
	0x0000000000016e24 <+164>:   jne    0x16df0 <lua_close+112>
	0x0000000000016e26 <+166>:   sub    $0x1,%r13d
	0x0000000000016e2a <+170>:   je     0x16e40 <lua_close+192>
	0x0000000000016e2c <+172>:   mov    $0x1,%esi
	0x0000000000016e31 <+177>:   mov    %rbp,%rdi
	0x0000000000016e34 <+180>:   call   0xea10
	0x0000000000016e39 <+185>:   cmpq   $0x0,0x50(%rbp)
	0x0000000000016e3e <+190>:   jne    0x16df0 <lua_close+112>
	0x0000000000016e40 <+192>:   add    $0x8,%rsp
	0x0000000000016e44 <+196>:   mov    %rbx,%rdi
	0x0000000000016e47 <+199>:   pop    %rbx
	0x0000000000016e48 <+200>:   pop    %rbp
	0x0000000000016e49 <+201>:   pop    %r12
	0x0000000000016e4b <+203>:   pop    %r13
	0x0000000000016e4d <+205>:   jmp    0x16950
*/
//nolint:nonamedreturns
func findOffsets(b []byte) (glrefOffset, curLOffset int, err error) {
	// On statically linked binaries the function starts like this:
	// (gdb) disass/r lua_close
	// Dump of assembler code for function lua_close:
	//    0x0000000000012860 <+0>:     f3 0f 1e fa     endbr64
	//    0x0000000000012864 <+4>:     41 55   push   %r13
	if slices.Equal(b[0:4], endbr64[:]) {
		b = b[4:]
	}
	var Greg x86asm.Reg
	for len(b) > 0 {
		var i x86asm.Inst
		i, err = x86asm.Decode(b, 64)
		if err != nil {
			return 0, 0, err
		}
		if i.Op == x86asm.MOV {
			if Greg == 0 {
				a0, ok1 := i.Args[0].(x86asm.Reg)
				a1, ok2 := i.Args[1].(x86asm.Mem)
				if ok1 && ok2 && a1.Base == x86asm.RDI {
					Greg = a0
					glrefOffset = int(a1.Disp)
				}
			} else {
				a0, ok1 := i.Args[0].(x86asm.Mem)
				a1, ok2 := i.Args[1].(x86asm.Imm)
				if ok1 && ok2 && sameReg(a0.Base, Greg) && a1 == 0 {
					curLOffset = int(a0.Disp)
					break
				}
				// If Greg is dest error
				if r0, ok := i.Args[0].(x86asm.Reg); ok && sameReg(r0, Greg) {
					err = errors.New("parse error, register holding G was clobbered")
					return 0, 0, err
				}
			}
		}
		b = b[i.Len:]
	}
	return glrefOffset, curLOffset, nil
}

// If we're dealing with 32bit values compilers will use R or E prefix
// interchangeably (E refs are just zero padded).  Needed this for howl.
//
//nolint:exhaustive
func sameReg(r1, r2 x86asm.Reg) bool {
	if r1 == r2 {
		return true
	}
	f := func(r1, r2 x86asm.Reg) bool {
		switch r1 {
		case x86asm.EAX:
			return r2 == x86asm.RAX
		case x86asm.ECX:
			return r2 == x86asm.RCX
		case x86asm.EDX:
			return r2 == x86asm.RDX
		case x86asm.EBX:
			return r2 == x86asm.RBX
		default:
			return false
		}
	}
	return f(r1, r2) || f(r2, r1)
}
