/*
 * LuaJIT common internal definitions for eBPF profiler.
 * Copyright (C) 2005-2022 Mike Pall. See Copyright Notice in LuaJIT_COPYRIGHT.txt.
 *
 * Basically bits were copied from LuaJIT as is as much as possible with
 * pointer dereferencing macros changed to use BPF_PROBE_READ_USER.  32 bit
 * pointer mode is untested and not supported.  Runtime offsets are used for
 * global_State (cur_L and jit_base).  Everything else is remarkably stable
 * across LuaJIT releases and is baked in.
 */

// Suppress clang-format to keep LUAJIT style.
// clang-format off

#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#define LJ_TARGET_GC64 1

#define LJ_AINLINE __always_inline

#if __TARGET_ARCH_arm64
#define LJ_TARGET_ARM64 1
#endif

#if __TARGET_ARCH_x86
#define LJ_TARGET_X64 1
#endif

/* 64 bit GC references. */
#if LJ_TARGET_GC64
#define LJ_GC64 1
#endif

#define LJ_ASSERT_NAME2(name, line) name##line
#define LJ_ASSERT_NAME(line) LJ_ASSERT_NAME2(lj_assert_, line)
#define check_exp(c, e) (e)

#define LJ_FR2 1
#define LJ_64 1

#define LUA_NUMBER double

#define LJ_ALIGN(n) __attribute__((aligned(n)))

typedef LUA_NUMBER lua_Number;
typedef int64_t intptr_t;

/* -- GC object references ------------------------------------------------ */

/* GCobj reference */
typedef struct GCRef {
#if LJ_GC64
  uint64_t gcptr64;	/* True 64 bit pointer. */
#else
  uint32_t gcptr32;	/* Pseudo 32 bit pointer. */
#endif
} GCRef;

/* Common GC header for all collectable objects. */
#define GCHeader	GCRef nextgc; uint8_t marked; uint8_t gct
/* This occupies 6 bytes, so use the next 2 bytes for non-32 bit fields. */

#if LJ_GC64
#define gcref(r)	((GCobj *)(r).gcptr64)
#define gcrefp(r, t)	((t *)(void *)(r).gcptr64)
#define gcrefu(r)	((r).gcptr64)
#else
#define gcref(r)	((GCobj *)(uintptr_t)(r).gcptr32)
#define gcrefp(r, t)	((t *)(void *)(uintptr_t)(r).gcptr32)
#define gcrefu(r)	((r).gcptr32)
#endif

/* -- Memory references --------------------------------------------------- */

/* Memory and GC object sizes. */
typedef uint32_t MSize;
#if LJ_GC64
typedef uint64_t GCSize;
#else
typedef uint32_t GCSize;
#endif

/* Memory reference */
typedef struct MRef {
#if LJ_GC64
    uint64_t ptr64; /* True 64 bit pointer. */
#else
    uint32_t ptr32; /* Pseudo 32 bit pointer. */
#endif
} MRef;

#if LJ_GC64
#define mref(r, t) ((t *)(void *)(r).ptr64)
#define mrefu(r) ((r).ptr64)
#else
#define mref(r, t) ((t *)(void *)(uintptr_t)(r).ptr32)
#define mrefu(r) ((r).ptr32)
#endif

#if LJ_ARCH_ENDIAN == LUAJIT_BE
#define LJ_LE 0
#define LJ_BE 1
#define LJ_ENDIAN_SELECT(le, be) be
#define LJ_ENDIAN_LOHI(lo, hi) hi lo
#else
#define LJ_LE 1
#define LJ_BE 0
#define LJ_ENDIAN_SELECT(le, be) le
#define LJ_ENDIAN_LOHI(lo, hi) lo hi
#endif

/* Tagged value. */
typedef LJ_ALIGN(8) union TValue {
    uint64_t u64; /* 64 bit pattern overlaps number. */
    lua_Number n; /* Number object overlaps split tag/value object. */
#if LJ_GC64
    GCRef gcr; /* GCobj reference with tag. */
    int64_t it64;
    struct {
        LJ_ENDIAN_LOHI(int32_t i;     /* Integer value. */
                       , uint32_t it; /* Internal object tag. Must overlap MSW of number. */
        )
    };
#else
    struct {
        LJ_ENDIAN_LOHI(
            union {
                GCRef gcr; /* GCobj reference (if any). */
                int32_t i; /* Integer value. */
            };
            , uint32_t it; /* Internal object tag. Must overlap MSW of number. */
        )
    };
#endif
#if LJ_FR2
    int64_t ftsz; /* Frame type and size of previous frame, or PC. */
#else
    struct {
        LJ_ENDIAN_LOHI(GCRef func;     /* Function for next frame (or dummy L). */
                       , FrameLink tp; /* Link to previous frame. */
        )
    } fr;
#endif
    struct {
        LJ_ENDIAN_LOHI(uint32_t lo;   /* Lower 32 bits of number. */
                       , uint32_t hi; /* Upper 32 bits of number. */
        )
    } u32;
} TValue;


/* Per-thread state object. */
struct lua_State {
    GCHeader;
    uint8_t dummy_ffid; /* Fake FF_C for curr_funcisL() on dummy frames. */
    uint8_t status;     /* Thread status. */
    MRef glref;         /* Link to global state. */
    GCRef gclist;       /* GC chain. */
    TValue *base;       /* Base of currently executing function. */
    TValue *top;        /* First free slot in the stack. */
    MRef maxstack;      /* Last free slot in the stack. */
    MRef stack;         /* Stack base. */
    GCRef openupval;    /* List of open upvalues in the stack. */
    GCRef env;          /* Thread environment (table of globals). */
    void *cframe;       /* End of C stack frame chain. */
    MSize stacksize;    /* True stack size (incl. LJ_STACK_EXTRA). */
    void *exdata;       /* user extra data pointer. added by OpenResty */
    void *exdata2;      /* the 2nd user extra data pointer. added by OpenResty */
#if LJ_TARGET_ARM
    uint32_t unused1;
    uint32_t unused2;
#endif
};

typedef struct lua_State lua_State;
typedef int (*lua_CFunction)(lua_State *L);
typedef const TValue cTValue;

#define LJ_TTHREAD (~6u)
#define LJ_TFUNC (~8u)
#define LJ_HASFFI 1

#if LJ_GC64
#define LJ_GCVMASK		(((uint64_t)1 << 47) - 1)
#endif

typedef uint32_t BCIns; /* Bytecode instruction. */
typedef uint32_t BCPos; /* Bytecode position. */
typedef uint32_t BCReg; /* Bytecode register. */
typedef int32_t BCLine; /* Bytecode line number. */

#define tvref(r) (mref(r, TValue))

#define strref(r) (&gcref((r))->str)
#define strdata(s) ((const char *)((s) + 1))

typedef struct GCproto {
    GCHeader;
    uint8_t numparams; /* Number of parameters. */
    uint8_t framesize; /* Fixed frame size. */
    MSize sizebc;      /* Number of bytecode instructions. */
#if LJ_GC64
    uint32_t unused_gc64;
#endif
    GCRef gclist;
    MRef k;         /* Split constant array (points to the middle). */
    MRef uv;        /* Upvalue list. local slot|0x8000 or parent uv idx. */
    MSize sizekgc;  /* Number of collectable constants. */
    MSize sizekn;   /* Number of lua_Number constants. */
    MSize sizept;   /* Total size including colocated arrays. */
    uint8_t sizeuv; /* Number of upvalues. */
    uint8_t flags;  /* Miscellaneous flags (see below). */
    uint16_t trace; /* Anchor for chain of root traces. */
    /* ------ The following fields are for debugging/tracebacks only ------ */
    GCRef chunkname;  /* Name of the chunk this function was defined in. */
    BCLine firstline; /* First line of the function definition. */
    BCLine numline;   /* Number of lines for the function definition. */
    MRef lineinfo;    /* Compressed map from bytecode ins. to source line. */
    MRef uvinfo;      /* Upvalue names. */
    MRef varinfo;     /* Names and compressed extents of local variables. */
} GCproto;

#define proto_knumtv(pt, idx) check_exp((uintptr_t)(idx) < (pt)->sizekn, &mref((pt)->k, TValue)[(idx)])
#define proto_bc(pt) ((BCIns *)((char *)(pt) + sizeof(GCproto)))
#define proto_bcpos(pt, pc) ((BCPos)((pc) - proto_bc(pt)))
#define proto_chunkname(pt) (strref(BPF_PROBE_READ_USER(pt, chunkname)))
#define proto_chunknamestr(pt) (strdata(proto_chunkname((pt))))
#define proto_lineinfo(pt) (mref(BPF_PROBE_READ_USER(pt, lineinfo), const void))
#define proto_uvinfo(pt) (mref(BPF_PROBE_READ_USER(pt, uvinfo), const uint8_t))

/* -- Function object (closures) ------------------------------------------ */

/* Common header for functions. env should be at same offset in GCudata. */
#define GCfuncHeader \
  GCHeader; uint8_t ffid; uint8_t nupvalues; \
  GCRef env; GCRef gclist; MRef pc

typedef struct GCfuncC {
  GCfuncHeader;
  lua_CFunction f;	/* C function to be called. */
  TValue upvalue[1];	/* Array of upvalues (TValue). */
} GCfuncC;

typedef struct GCfuncL {
  GCfuncHeader;
  GCRef uvptr[1];	/* Array of _pointers_ to upvalue objects (GCupval). */
} GCfuncL;

typedef union GCfunc {
  GCfuncC c;
  GCfuncL l;
} GCfunc;

#define FF_LUA 0
#define FF_C 1
#define isluafunc(fn) (BPF_PROBE_READ_USER(fn, c.ffid) == FF_LUA)
#define iscfunc(fn) (BPF_PROBE_READ_USER(fn, c.ffid) == FF_C)
#define isffunc(fn) (BPF_PROBE_READ_USER(fn, c.ffid) > FF_C)
#define funcproto(fn) check_exp(isluafunc(fn), (GCproto *)(mref(BPF_PROBE_READ_USER((fn), l.pc), char) - sizeof(GCproto)))
#define sizeCfunc(n) (sizeof(GCfuncC) - sizeof(TValue) + sizeof(TValue) * (n))

/* GC header for generic access to common fields of GC objects. */
typedef struct GChead {
    GCHeader;
    uint8_t unused1;
    uint8_t unused2;
    GCRef env;
    GCRef gclist;
    GCRef metatable;
} GChead;

/* -- String object ------------------------------------------------------- */

typedef uint32_t StrHash; /* String hash value. */
typedef uint32_t StrID;   /* String ID. */

/* String object header. String payload follows. */
typedef struct GCstr {
    GCHeader;
    uint8_t reserved; /* Used by lexer for fast lookup of reserved words. */
    uint8_t hashalg;  /* Hash algorithm. */
    StrID sid;        /* Interned string ID. */
    StrHash hash;     /* Hash of string. */
    MSize len;        /* Size of string. */
} GCstr;

typedef union GCobj {
    GChead gch;
    GCstr str;
    lua_State th;
    GCfunc fn;
} GCobj;

#define gco2pt(o) check_exp((o)->gch.gct == ~LJ_TPROTO, &(o)->pt)
#define obj2gco(v) ((GCobj *)(v))
#define gcval(o) ((GCobj *)(gcrefu(BPF_PROBE_READ_USER(o, gcr)) & LJ_GCVMASK))

/* -- Lua stack frame ----------------------------------------------------- */

/* Frame type markers in LSB of PC (4-byte aligned) or delta (8-byte aligned:
**
**    PC  00  Lua frame
** delta 001  C frame
** delta 010  Continuation frame
** delta 011  Lua vararg frame
** delta 101  cpcall() frame
** delta 110  ff pcall() frame
** delta 111  ff pcall() frame with active hook
*/
enum {
  FRAME_LUA, FRAME_C, FRAME_CONT, FRAME_VARG,
  FRAME_LUAP, FRAME_CP, FRAME_PCALL, FRAME_PCALLH
};
#define FRAME_TYPE		3
#define FRAME_P			4
#define FRAME_TYPEP		(FRAME_TYPE|FRAME_P)

/* Macros to access and modify Lua frames. */
#if LJ_FR2
/* Two-slot frame info, required for 64 bit PC/GCRef:
**
**                   base-2  base-1      |  base  base+1 ...
**                  [func   PC/delta/ft] | [slots ...]
**                  ^-- frame            | ^-- base   ^-- top
**
** Continuation frames:
**
**   base-4  base-3  base-2  base-1      |  base  base+1 ...
**  [cont      PC ] [func   PC/delta/ft] | [slots ...]
**                  ^-- frame            | ^-- base   ^-- top
*/
#define frame_gc(f)		(gcval((f)-1))
#define frame_ftsz(f) ((int64_t)BPF_PROBE_READ_USER(f, ftsz))
#define frame_pc(f)		((const BCIns *)frame_ftsz(f))
#else
/* One-slot frame info, sufficient for 32 bit PC/GCRef:
**
**              base-1              |  base  base+1 ...
**              lo     hi           |
**             [func | PC/delta/ft] | [slots ...]
**             ^-- frame            | ^-- base   ^-- top
**
** Continuation frames:
**
**  base-2      base-1              |  base  base+1 ...
**  lo     hi   lo     hi           |
** [cont | PC] [func | PC/delta/ft] | [slots ...]
**             ^-- frame            | ^-- base   ^-- top
*/
#define frame_gc(f)		(gcref((f)->fr.func))
#define frame_ftsz(f)		((ptrdiff_t)(f)->fr.tp.ftsz)
#define frame_pc(f)		(mref((f)->fr.tp.pcr, const BCIns))
#endif

#define frame_type(f)		(frame_ftsz(f) & FRAME_TYPE)
#define frame_typep(f)		(frame_ftsz(f) & FRAME_TYPEP)
#define frame_islua(f)		(frame_type(f) == FRAME_LUA)
#define frame_isc(f)		(frame_type(f) == FRAME_C)
#define frame_iscont(f)		(frame_typep(f) == FRAME_CONT)
#define frame_isvarg(f)		(frame_typep(f) == FRAME_VARG)
#define frame_ispcall(f)	((frame_ftsz(f) & 6) == FRAME_PCALL)

#define frame_func(f)		(&frame_gc(f)->fn)
#define frame_delta(f)		(frame_ftsz(f) >> 3)
#define frame_sized(f)		(frame_ftsz(f) & ~FRAME_TYPEP)

enum { LJ_CONT_TAILCALL, LJ_CONT_FFI_CALLBACK };  /* Special continuations. */

#if LJ_FR2
#define frame_contpc(f)		(frame_pc((f)-2))
#define frame_contv(f)      (BPF_PROBE_READ_USER(((f)-3), u64))
#else
#define frame_contpc(f)		(frame_pc((f)-1))
#define frame_contv(f)		(((f)-1)->u32.lo)
#endif
#if LJ_FR2
#define frame_contf(f)		((ASMFunction)(uintptr_t)((f)-3)->u64)
#elif LJ_64
#define frame_contf(f) \
  ((ASMFunction)(void *)((intptr_t)lj_vm_asm_begin + \
			 (intptr_t)(int32_t)((f)-1)->u32.lo))
#else
#define frame_contf(f)		((ASMFunction)gcrefp(((f)-1)->gcr, void))
#endif
#define frame_iscont_fficb(f) \
  (LJ_HASFFI && frame_contv(f) == LJ_CONT_FFI_CALLBACK)

static __always_inline BCIns frame_pc_prev(const BCIns *bcins) {
    const BCIns bcins_prev;
    bpf_probe_read_user((void *)&bcins_prev, sizeof(bcins_prev), bcins - 1);
    return bcins_prev;
}

#define frame_prevl(f) ((f) - (1 + LJ_FR2 + bc_a(frame_pc_prev(frame_pc(f)))))
#define frame_prevd(f) ((TValue *)((char *)(f)-frame_sized(f)))
#define frame_prev(f) (frame_islua(f) ? frame_prevl(f) : frame_prevd(f))
/* Note: this macro does not skip over FRAME_VARG. */

#define LJ_STATIC_ASSERT(cond) extern void LJ_ASSERT_NAME(__LINE__)(int STATIC_ASSERTION_FAILED[(cond) ? 1 : -1])
#define LJ_NOAPI extern
#define LJ_DATA LJ_NOAPI
#define LJ_DATADEF

#define MMDEF(_)                                                                 \
    _(index)                                                                     \
    _(newindex)                                                                  \
    _(gc)                                                                        \
    _(mode)                                                                      \
    _(eq)                                                                        \
    _(len) /* Only the above (fast) metamethods are negative cached (max. 8). */ \
    _(lt)                                                                        \
    _(le)                                                                        \
    _(concat)                                                                    \
    _(call) /* The following must be in ORDER ARITH. */                          \
    _(add)                                                                       \
    _(sub)                                                                       \
    _(mul)                                                                       \
    _(div)                                                                       \
    _(mod)                                                                       \
    _(pow)                                                                       \
    _(unm) /* The following are used in the standard libraries. */

typedef enum {
#define MMENUM(name) MM_##name,
    MMDEF(MMENUM) MM__MAX,
    MM____ = MM__MAX,
} MMS;
#include "lj_bc.h"
#include "lj_bcdef.h"

/* -- C stack frame ------------------------------------------------------- */

/* Macros to access and modify the C stack frame chain. */

/* These definitions must match with the arch-specific *.dasc files. */
#if LJ_TARGET_X64
#define CFRAME_OFS_PREV		(4*8)
#if LJ_GC64
#define CFRAME_OFS_PC		(3*8)
#define CFRAME_OFS_L		(2*8)
#define CFRAME_OFS_ERRF		(3*4)
#define CFRAME_OFS_NRES		(2*4)
#define CFRAME_OFS_MULTRES	(0*4)
#else
#define CFRAME_OFS_PC		(7*4)
#define CFRAME_OFS_L		(6*4)
#define CFRAME_OFS_ERRF		(5*4)
#define CFRAME_OFS_NRES		(4*4)
#define CFRAME_OFS_MULTRES	(1*4)
#endif
#if LJ_NO_UNWIND
#define CFRAME_SIZE		(12*8)
#else
#define CFRAME_SIZE		(10*8)
#endif
#define CFRAME_SIZE_JIT		(CFRAME_SIZE + 16)
#define CFRAME_SHIFT_MULTRES	0
#elif LJ_TARGET_ARM64
#define CFRAME_OFS_ERRF		36
#define CFRAME_OFS_NRES		40
#define CFRAME_OFS_PREV		0
#define CFRAME_OFS_L		16
#define CFRAME_OFS_PC		8
#define CFRAME_OFS_MULTRES	32
#define CFRAME_SIZE		208
#define CFRAME_SHIFT_MULTRES	3
#else
#error "Missing CFRAME_* definitions for this architecture"
#endif

#ifndef CFRAME_SIZE_JIT
#define CFRAME_SIZE_JIT		CFRAME_SIZE
#endif

#define CFRAME_RESUME		1
#define CFRAME_UNWIND_FF	2  /* Only used in unwinder. */
#define CFRAME_RAWMASK		(~(intptr_t)(CFRAME_RESUME|CFRAME_UNWIND_FF))

#define cframe_nres(cf)                                                                        \
    ({                                                                                         \
        int32_t __x;                                                                           \
        bpf_probe_read_user(&__x, sizeof(__x), (int32_t *)(((char *)(cf)) + CFRAME_OFS_NRES)); \
    })
#define cframe_prev_addr(cf) (void **)(((char *)(cf)) + CFRAME_OFS_PREV)
#define cframe_L_addr(cf) (GCRef *)(((char *)(cf)) + CFRAME_OFS_L)
#define cframe_L(addr) &gcref(addr)->th
// #define cframe_pc(cf) (mref(*(MRef *)(((char *)(cf)) + CFRAME_OFS_PC), const BCIns))
#define cframe_pc_addr(cf) (MRef *)(((char *)(cf)) + CFRAME_OFS_PC)
#define cframe_raw(cf) ((void *)((intptr_t)(cf) & CFRAME_RAWMASK))

typedef union IRIns {
} IRIns;

/* Snapshot and exit numbers. */

typedef struct SnapShot {
} SnapShot;
typedef uint8_t MCode;
typedef uint32_t IRRef; /* Used to pass around references. */
typedef uint32_t SnapEntry;

/* Trace object. */
typedef struct GCtrace {
    GCHeader;
    uint16_t nsnap; /* Number of snapshots. */
    IRRef nins;     /* Next IR instruction. Biased with REF_BIAS. */
#if LJ_GC64
    uint32_t unused_gc64;
#endif
    GCRef gclist;
    IRIns *ir;          /* IR instructions/constants. Biased with REF_BIAS. */
    IRRef nk;           /* Lowest IR constant. Biased with REF_BIAS. */
    uint32_t nsnapmap;  /* Number of snapshot map elements. */
    SnapShot *snap;     /* Snapshot array. */
    SnapEntry *snapmap; /* Snapshot map. */
    GCRef startpt;      /* Starting prototype. */
    MRef startpc;       /* Bytecode PC of starting instruction. */
    BCIns startins;     /* Original bytecode of starting instruction. */
    // remaining fields are not used
} GCtrace;

#define restorestack(L, n) ((TValue *)(mref(BPF_PROBE_READ_USER(L, stack), char) + (n)))

// The only field we access is cur_L, offset is derived from agent.
typedef struct global_State {
} global_State;

#define G(L) (mref(BPF_PROBE_READ_USER(L, glref), global_State))

#endif
