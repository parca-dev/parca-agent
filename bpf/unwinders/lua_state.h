/*
** LuaJIT common internal definitions for profiler to get BTF format.
** Copyright (C) 2005-2022 Mike Pall. See Copyright Notice in luajit.h
**
** 17-Jul-2022 Yusheng Zheng modified this from lua.h, lua_state.h and
** lj_def.h.
**
** 6/2024 Tommy Reilly modified this file from apisix/profiler/lua_state.h
** Basically things were added to flush out access to more LuaJIT functionality,
** not all of it is strictly needed but parts were lifted as is instead of
** trying to whittle everything down to the absolute minimum. Enough has
** added here that we should just require the luajit src as a subproject and
** maybe even upstream changes to make the projects header BPF friendly.
*/

#ifndef __LUA_STATE_H
#define __LUA_STATE_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LJ_TARGET_GC64 1
#define LJ_ARCH_BITS 64

/* 64 bit GC references. */
#if LJ_TARGET_GC64
#define LJ_GC64 1
#else
#define LJ_GC64 0
#endif

/* Disable or enable the JIT compiler. */
#if defined(LUAJIT_DISABLE_JIT) || defined(LJ_ARCH_NOJIT) || defined(LJ_OS_NOJIT)
#define LJ_HASJIT 0
#else
#define LJ_HASJIT 1
#endif

#define LJ_HASPROFILE 1

/* Static assertions. */
#define LJ_ASSERT_NAME2(name, line) name##line
#define LJ_ASSERT_NAME(line) LJ_ASSERT_NAME2(lj_assert_, line)
#ifdef __COUNTER__
#define LJ_STATIC_ASSERT(cond) extern void LJ_ASSERT_NAME(__COUNTER__)(int STATIC_ASSERTION_FAILED[(cond) ? 1 : -1])
#else
#define LJ_STATIC_ASSERT(cond) extern void LJ_ASSERT_NAME(__LINE__)(int STATIC_ASSERTION_FAILED[(cond) ? 1 : -1])
#endif

/* GCobj reference */
typedef struct GCRef {
#if LJ_GC64
    uint64_t gcptr64; /* True 64 bit pointer. */
#else
    uint32_t gcptr32; /* Pseudo 32 bit pointer. */
#endif
} GCRef;

/* 2-slot frame info. */
#if LJ_GC64
#define LJ_FR2 1
#else
#define LJ_FR2 0
#endif

#if LJ_ARCH_BITS == 32
#define LJ_32 1
#define LJ_64 0
#else
#define LJ_32 0
#define LJ_64 1
#endif

/* Optional defines. */
#ifndef LJ_FASTCALL
#define LJ_FASTCALL
#endif
#ifndef LJ_NORET
#define LJ_NORET
#endif
#ifndef LJ_NOAPI
#define LJ_NOAPI extern
#endif
#ifndef LJ_LIKELY
#define LJ_LIKELY(x) (x)
#define LJ_UNLIKELY(x) (x)
#endif

/* Attributes for internal functions. */
#define LJ_DATA LJ_NOAPI
#define LJ_DATADEF
#define LJ_ASMF LJ_NOAPI
#define LJ_FUNCA LJ_NOAPI
#if defined(ljamalg_c)
#define LJ_FUNC static
#else
#define LJ_FUNC LJ_NOAPI
#endif
#define LJ_FUNC_NORET LJ_FUNC LJ_NORET
#define LJ_FUNCA_NORET LJ_FUNCA LJ_NORET
#define LJ_ASMF_NORET LJ_ASMF LJ_NORET

/* Internal assertions. */
#if defined(LUA_USE_ASSERT) || defined(LUA_USE_APICHECK)
#define lj_assert_check(g, c, ...) ((c) ? (void)0 : (lj_assert_fail((g), __FILE__, __LINE__, __func__, __VA_ARGS__), 0))
#define lj_checkapi(c, ...) lj_assert_check(G(L), (c), __VA_ARGS__)
#else
#define lj_checkapi(c, ...) ((void)L)
#endif

#ifdef LUA_USE_ASSERT
#define lj_assertG_(g, c, ...) lj_assert_check((g), (c), __VA_ARGS__)
#define lj_assertG(c, ...) lj_assert_check(g, (c), __VA_ARGS__)
#define lj_assertL(c, ...) lj_assert_check(G(L), (c), __VA_ARGS__)
#define lj_assertX(c, ...) lj_assert_check(NULL, (c), __VA_ARGS__)
#define check_exp(c, e) (lj_assertX((c), #c), (e))
#else
#define lj_assertG_(g, c, ...) ((void)0)
#define lj_assertG(c, ...) ((void)g)
#define lj_assertL(c, ...) ((void)L)
#define lj_assertX(c, ...) ((void)0)
#define check_exp(c, e) (e)
#endif

/* PRNG state. Need this here, details in lj_prng.h. */
typedef struct PRNGState {
    uint64_t u[4];
} PRNGState;

/* Common GC header for all collectable objects. */
#define GCHeader    \
    GCRef nextgc;   \
    uint8_t marked; \
    uint8_t gct
/* This occupies 6 bytes, so use the next 2 bytes for non-32 bit fields. */

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

#define setmref(r, p) ((r).ptr64 = (uint64_t)(void *)(p))
#define setmrefu(r, u) ((r).ptr64 = (uint64_t)(u))
#define setmrefr(r, v) ((r).ptr64 = (v).ptr64)
#else
#define mref(r, t) ((t *)(void *)(uintptr_t)(r).ptr32)
#define mrefu(r) ((r).ptr32)

#define setmref(r, p) ((r).ptr32 = (uint32_t)(uintptr_t)(void *)(p))
#define setmrefu(r, u) ((r).ptr32 = (uint32_t)(u))
#define setmrefr(r, v) ((r).ptr32 = (v).ptr32)
#endif

#define LJ_ALIGN(n) __attribute__((aligned(n)))

#define LUA_NUMBER double

/* type of numbers in Lua */
typedef LUA_NUMBER lua_Number;

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

/* Frame link. */
typedef union {
    int32_t ftsz; /* Frame type and size of previous frame. */
    MRef pcr;     /* Or PC for Lua frames. */
} FrameLink;

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

/* Memory and GC object sizes. */
typedef uint32_t MSize;
#if LJ_GC64
typedef uint64_t GCSize;
#else
typedef uint32_t GCSize;
#endif

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
/* Internal object tags.
**
** Format for 32 bit GC references (!LJ_GC64):
**
** Internal tags overlap the MSW of a number object (must be a double).
** Interpreted as a double these are special NaNs. The FPU only generates
** one type of NaN (0xfff8_0000_0000_0000). So MSWs > 0xfff80000 are available
** for use as internal tags. Small negative numbers are used to shorten the
** encoding of type comparisons (reg/mem against sign-ext. 8 bit immediate).
**
**                  ---MSW---.---LSW---
** primitive types |  itype  |         |
** lightuserdata   |  itype  |  void * |  (32 bit platforms)
** lightuserdata   |ffff|seg|    ofs   |  (64 bit platforms)
** GC objects      |  itype  |  GCRef  |
** int (LJ_DUALNUM)|  itype  |   int   |
** number           -------double------
**
** Format for 64 bit GC references (LJ_GC64):
**
** The upper 13 bits must be 1 (0xfff8...) for a special NaN. The next
** 4 bits hold the internal tag. The lowest 47 bits either hold a pointer,
** a zero-extended 32 bit integer or all bits set to 1 for primitive types.
**
**                     ------MSW------.------LSW------
** primitive types    |1..1|itype|1..................1|
** GC objects         |1..1|itype|-------GCRef--------|
** lightuserdata      |1..1|itype|seg|------ofs-------|
** int (LJ_DUALNUM)   |1..1|itype|0..0|-----int-------|
** number              ------------double-------------
**
** ORDER LJ_T
** Primitive types nil/false/true must be first, lightuserdata next.
** GC objects are at the end, table/userdata must be lowest.
** Also check lj_ir.h for similar ordering constraints.
*/
#define LJ_TNIL (~0u)
#define LJ_TFALSE (~1u)
#define LJ_TTRUE (~2u)
#define LJ_TLIGHTUD (~3u)
#define LJ_TSTR (~4u)
#define LJ_TUPVAL (~5u)
#define LJ_TTHREAD (~6u)
#define LJ_TPROTO (~7u)
#define LJ_TFUNC (~8u)
#define LJ_TTRACE (~9u)
#define LJ_TCDATA (~10u)
#define LJ_TTAB (~11u)
#define LJ_TUDATA (~12u)
/* This is just the canonical number type used in some places. */
#define LJ_TNUMX (~13u)

/* Integers have itype == LJ_TISNUM doubles have itype < LJ_TISNUM */
#if LJ_64 && !LJ_GC64
#define LJ_TISNUM 0xfffeffffu
#else
#define LJ_TISNUM LJ_TNUMX
#endif
#define LJ_TISTRUECOND LJ_TFALSE
#define LJ_TISPRI LJ_TTRUE
#define LJ_TISGCV (LJ_TSTR + 1)
#define LJ_TISTABUD LJ_TTAB

#define LJ_HASFFI 1

/* Type marker for slot holding a traversal index. Must be lightuserdata. */
#define LJ_KEYINDEX 0xfffe7fffu

#if LJ_GC64
#define LJ_GCVMASK (((uint64_t)1 << 47) - 1)
#endif

#if LJ_64
/* To stay within 47 bits, lightuserdata is segmented. */
#define LJ_LIGHTUD_BITS_SEG 8
#define LJ_LIGHTUD_BITS_LO (47 - LJ_LIGHTUD_BITS_SEG)
#endif

/* -- Common type definitions --------------------------------------------- */

/* Types for handling bytecodes. Need this here, details in lj_bc.h. */
typedef uint32_t BCIns; /* Bytecode instruction. */
typedef uint32_t BCPos; /* Bytecode position. */
typedef uint32_t BCReg; /* Bytecode register. */
typedef int32_t BCLine; /* Bytecode line number. */

/* Internal assembler functions. Never call these directly from C. */
typedef void (*ASMFunction)(void);

/* Resizable string buffer. Need this here, details in lj_buf.h. */
#define SBufHeader   \
    char *w, *e, *b; \
    MRef L
typedef struct SBuf {
    SBufHeader;
} SBuf;

#if LJ_GC64
#define gcref(r) ((GCobj *)(r).gcptr64)
#define gcrefp(r, t) ((t *)(void *)(r).gcptr64)
#define gcrefu(r) ((r).gcptr64)
#define gcrefeq(r1, r2) ((r1).gcptr64 == (r2).gcptr64)

#define setgcref(r, gc) ((r).gcptr64 = (uint64_t) & (gc)->gch)
#define setgcreft(r, gc, it) (r).gcptr64 = (uint64_t) & (gc)->gch | (((uint64_t)(it)) << 47)
#define setgcrefp(r, p) ((r).gcptr64 = (uint64_t)(p))
#define setgcrefnull(r) ((r).gcptr64 = 0)
#define setgcrefr(r, v) ((r).gcptr64 = (v).gcptr64)
#else
#define gcref(r) ((GCobj *)(uintptr_t)(r).gcptr32)
#define gcrefp(r, t) ((t *)(void *)(uintptr_t)(r).gcptr32)
#define gcrefu(r) ((r).gcptr32)
#define gcrefeq(r1, r2) ((r1).gcptr32 == (r2).gcptr32)

#define setgcref(r, gc) ((r).gcptr32 = (uint32_t)(uintptr_t) & (gc)->gch)
#define setgcrefp(r, p) ((r).gcptr32 = (uint32_t)(uintptr_t)(p))
#define setgcrefnull(r) ((r).gcptr32 = 0)
#define setgcrefr(r, v) ((r).gcptr32 = (v).gcptr32)
#endif

#define tvref(r) (mref(r, TValue))

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

#define strref(r) (&gcref((r))->str)
#define strdata(s) ((const char *)((s) + 1))
#define strdatawr(s) ((char *)((s) + 1))
/* -- Userdata object ----------------------------------------------------- */

/* Userdata object. Payload follows. */
typedef struct GCudata {
    GCHeader;
    uint8_t udtype; /* Userdata type. */
    uint8_t unused2;
    GCRef env;       /* Should be at same offset in GCfunc. */
    MSize len;       /* Size of payload. */
    GCRef metatable; /* Must be at same offset in GCtab. */
    uint32_t align1; /* To force 8 byte alignment of the payload. */
} GCudata;

/* Userdata types. */
enum {
    UDTYPE_USERDATA, /* Regular userdata. */
    UDTYPE_IO_FILE,  /* I/O library FILE. */
    UDTYPE_FFI_CLIB, /* FFI C library namespace. */
    UDTYPE_BUFFER,   /* String buffer. */
    UDTYPE__MAX
};

#define uddata(u) ((void *)((u) + 1))
#define sizeudata(u) (sizeof(struct GCudata) + (u)->len)

/* -- C data object ------------------------------------------------------- */

/* C data object. Payload follows. */
typedef struct GCcdata {
    GCHeader;
    uint16_t ctypeid; /* C type ID. */
} GCcdata;

/* Prepended to variable-sized or realigned C data objects. */
typedef struct GCcdataVar {
    uint16_t offset; /* Offset to allocated memory (relative to GCcdata). */
    uint16_t extra;  /* Extra space allocated (incl. GCcdata + GCcdatav). */
    MSize len;       /* Size of payload. */
} GCcdataVar;

#define cdataptr(cd) ((void *)((cd) + 1))
#define cdataisv(cd) ((cd)->marked & 0x80)
#define cdatav(cd) ((GCcdataVar *)((char *)(cd) - sizeof(GCcdataVar)))
#define cdatavlen(cd) check_exp(cdataisv(cd), cdatav(cd)->len)
#define sizecdatav(cd) (cdatavlen(cd) + cdatav(cd)->extra)
#define memcdatav(cd) ((void *)((char *)(cd) - cdatav(cd)->offset))

/* -- Prototype object ---------------------------------------------------- */

#define SCALE_NUM_GCO ((int32_t)sizeof(lua_Number) / sizeof(GCRef))
#define round_nkgc(n) (((n) + SCALE_NUM_GCO - 1) & ~(SCALE_NUM_GCO - 1))

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
    void *lineinfo;   /* Compressed map from bytecode ins. to source line. */
    uint8_t *uvinfo;  /* Upvalue names. */
    MRef varinfo;     /* Names and compressed extents of local variables. */
} GCproto;

/* Flags for prototype. */
#define PROTO_CHILD 0x01  /* Has child prototypes. */
#define PROTO_VARARG 0x02 /* Vararg function. */
#define PROTO_FFI 0x04    /* Uses BC_KCDATA for FFI datatypes. */
#define PROTO_NOJIT 0x08  /* JIT disabled for this function. */
#define PROTO_ILOOP 0x10  /* Patched bytecode with ILOOP etc. */
/* Only used during parsing. */
#define PROTO_HAS_RETURN 0x20   /* Already emitted a return. */
#define PROTO_FIXUP_RETURN 0x40 /* Need to fixup emitted returns. */
/* Top bits used for counting created closures. */
#define PROTO_CLCOUNT 0x20 /* Base of saturating 3 bit counter. */
#define PROTO_CLC_BITS 3
#define PROTO_CLC_POLY (3 * PROTO_CLCOUNT) /* Polymorphic threshold. */

#define PROTO_UV_LOCAL 0x8000     /* Upvalue for local slot. */
#define PROTO_UV_IMMUTABLE 0x4000 /* Immutable upvalue. */

#define proto_kgc(pt, idx) check_exp((uintptr_t)(intptr_t)(idx) >= (uintptr_t) - (intptr_t)(pt)->sizekgc, gcref(mref((pt)->k, GCRef)[(idx)]))
#define proto_knumtv(pt, idx) check_exp((uintptr_t)(idx) < (pt)->sizekn, &mref((pt)->k, TValue)[(idx)])
#define proto_bc(pt) ((BCIns *)((char *)(pt) + sizeof(GCproto)))
#define proto_bcpos(pt, pc) ((BCPos)((pc) - proto_bc(pt)))
#define proto_uv(pt) (mref((pt)->uv, uint16_t))

#define proto_chunkname(pt) (strref(BPF_PROBE_READ_USER(pt, chunkname)))

#define proto_chunknamestr(pt) (strdata(proto_chunkname((pt))))
#define proto_lineinfo(pt) (mref((pt)->lineinfo, const void))
#define proto_uvinfo(pt) (mref((pt)->uvinfo, const uint8_t))
#define proto_varinfo(pt) (mref(BPF_PROBE_READ_USER(pt, varinfo), const uint8_t))

/* -- Upvalue object ------------------------------------------------------ */

typedef struct GCupval {
    GCHeader;
    uint8_t closed;    /* Set if closed (i.e. uv->v == &uv->u.value). */
    uint8_t immutable; /* Immutable value. */
    union {
        TValue tv; /* If closed: the value itself. */
        struct {   /* If open: double linked list, anchored at thread. */
            GCRef prev;
            GCRef next;
        };
    };
    MRef v;         /* Points to stack slot (open) or above (closed). */
    uint32_t dhash; /* Disambiguation hash: dh1 != dh2 => cannot alias. */
} GCupval;

#define uvprev(uv_) (&gcref((uv_)->prev)->uv)
#define uvnext(uv_) (&gcref((uv_)->next)->uv)
#define uvval(uv_) (mref((uv_)->v, TValue))

/* GC header for generic access to common fields of GC objects. */
typedef struct GChead {
    GCHeader;
    uint8_t unused1;
    uint8_t unused2;
    GCRef env;
    GCRef gclist;
    GCRef metatable;
} GChead;

/* -- Function object (closures) ------------------------------------------ */

/* Common header for functions. env should be at same offset in GCudata. */
#define GCfuncHeader   \
    GCHeader;          \
    uint8_t ffid;      \
    uint8_t nupvalues; \
    GCRef env;         \
    GCRef gclist;      \
    MRef pc

typedef struct GCfuncC {
    GCfuncHeader;
    lua_CFunction f;   /* C function to be called. */
    TValue upvalue[1]; /* Array of upvalues (TValue). */
} GCfuncC;

typedef struct GCfuncL {
    GCfuncHeader;
    GCRef uvptr[1]; /* Array of _pointers_ to upvalue objects (GCupval). */
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
#define sizeLfunc(n) (sizeof(GCfuncL) - sizeof(GCRef) + sizeof(GCRef) * (n))

typedef struct GCtab {
    GCHeader;
    uint8_t nomm; /* Negative cache for fast metamethods. */
    char colo;    /* Array colocation. */
    MRef array;   /* Array part. */
    GCRef gclist;
    GCRef metatable; /* Must be at same offset in GCudata. */
    MRef node;       /* Hash part. */
    uint32_t asize;  /* Size of array part (keys [0, asize-1]). */
    uint32_t hmask;  /* Hash part mask (size of hash part - 1). */
#if LJ_GC64
    MRef freetop; /* Top of free elements. */
#endif
} GCtab;

#define sizetabcolo(n) ((n) * sizeof(TValue) + sizeof(GCtab))
#define tabref(r) (&gcref((r))->tab)
#define noderef(r) (mref((r), Node))
#define nextnode(n) (mref((n)->next, Node))
#if LJ_GC64
#define getfreetop(t, n) (noderef((t)->freetop))
#define setfreetop(t, n, v) (setmref((t)->freetop, (v)))
#else
#define getfreetop(t, n) (noderef((n)->freetop))
#define setfreetop(t, n, v) (setmref((n)->freetop, (v)))
#endif

typedef union GCobj {
    GChead gch;
    GCstr str;
    GCupval uv;
    lua_State th;
    GCproto pt;
    GCfunc fn;
    GCcdata cd;
    GCtab tab;
    GCudata ud;
} GCobj;

/* Macros to convert a GCobj pointer into a specific value. */
#define gco2str(o) check_exp((o)->gch.gct == ~LJ_TSTR, &(o)->str)
#define gco2uv(o) check_exp((o)->gch.gct == ~LJ_TUPVAL, &(o)->uv)
#define gco2th(o) check_exp((o)->gch.gct == ~LJ_TTHREAD, &(o)->th)
#define gco2pt(o) check_exp((o)->gch.gct == ~LJ_TPROTO, &(o)->pt)
#define gco2func(o) check_exp((o)->gch.gct == ~LJ_TFUNC, &(o)->fn)
#define gco2cd(o) check_exp((o)->gch.gct == ~LJ_TCDATA, &(o)->cd)
#define gco2tab(o) check_exp((o)->gch.gct == ~LJ_TTAB, &(o)->tab)
#define gco2ud(o) check_exp((o)->gch.gct == ~LJ_TUDATA, &(o)->ud)

/* Macro to convert any collectable object into a GCobj pointer. */
#define obj2gco(v) ((GCobj *)(v))

#if LJ_GC64
#define gcval(o) ((GCobj *)(gcrefu(BPF_PROBE_READ_USER(o, gcr)) & LJ_GCVMASK))

#else
#define gcval(o) (gcref((o)->gcr))
#endif

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
enum { FRAME_LUA, FRAME_C, FRAME_CONT, FRAME_VARG, FRAME_LUAP, FRAME_CP, FRAME_PCALL, FRAME_PCALLH };
#define FRAME_TYPE 3
#define FRAME_P 4
#define FRAME_TYPEP (FRAME_TYPE | FRAME_P)

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
#define frame_gc(f) (gcval((f) - 1))
#define frame_ftsz(f) ((int64_t)BPF_PROBE_READ_USER(f, ftsz))

#define frame_pc(f) ((const BCIns *)frame_ftsz(f))
#define setframe_ftsz(f, sz) ((f)->ftsz = (sz))
#define setframe_pc(f, pc) ((f)->ftsz = (int64_t)(intptr_t)(pc))
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
#define frame_gc(f) (gcref((f)->fr.func))
#define frame_ftsz(f) ((ptrdiff_t)BPF_PROBE_READ_USER(f, fr.tp.ftsz))

#define frame_pc(f) (mref((f)->fr.tp.pcr, const BCIns))
#define setframe_gc(f, p, tp) (setgcref((f)->fr.func, (p)), UNUSED(tp))
#define setframe_ftsz(f, sz) ((f)->fr.tp.ftsz = (int32_t)(sz))
#define setframe_pc(f, pc) (setmref((f)->fr.tp.pcr, (pc)))
#endif

#define frame_type(f) (frame_ftsz(f) & FRAME_TYPE)
#define frame_typep(f) (frame_ftsz(f) & FRAME_TYPEP)
#define frame_islua(f) (frame_type(f) == FRAME_LUA)
#define frame_isc(f) (frame_type(f) == FRAME_C)
#define frame_iscont(f) (frame_typep(f) == FRAME_CONT)
#define frame_isvarg(f) (frame_typep(f) == FRAME_VARG)
#define frame_ispcall(f) ((frame_ftsz(f) & 6) == FRAME_PCALL)
#define frame_func(f) (&frame_gc(f)->fn)

#define frame_delta(f) (frame_ftsz(f) >> 3)
#define frame_sized(f) (frame_ftsz(f) & ~FRAME_TYPEP)

enum { LJ_CONT_TAILCALL, LJ_CONT_FFI_CALLBACK }; /* Special continuations. */

#if LJ_FR2
#define frame_contpc(f) (frame_pc((f) - 2))
#define frame_contv(f) (BPF_PROBE_READ_USER(((f) - 3), u64))
#else
#define frame_contpc(f) (frame_pc((f) - 1))
#define frame_contv(f) (((f) - 1)->u32.lo)
#endif

#define frame_iscont_fficb(f) (LJ_HASFFI && frame_contv(f) == LJ_CONT_FFI_CALLBACK)

static __always_inline BCIns frame_pc_prev(const BCIns *bcins) {
    const BCIns bcins_prev;
    bpf_probe_read_user((void *)&bcins_prev, sizeof(bcins_prev), bcins - 1);
    return bcins_prev;
}

#define frame_prevl(f) ((f) - (1 + LJ_FR2 + bc_a(frame_pc_prev(frame_pc(f)))))
#define frame_prevd(f) ((TValue *)((char *)(f) - frame_sized(f)))
#define frame_prev(f) (frame_islua(f) ? frame_prevl(f) : frame_prevd(f))

/* -- State objects ------------------------------------------------------- */

/* VM states. */
enum {
    LJ_VMST_INTERP, /* Interpreter. */
    LJ_VMST_C,      /* C function. */
    LJ_VMST_GC,     /* Garbage collector. */
    LJ_VMST_EXIT,   /* Trace exit handler. */
    LJ_VMST_RECORD, /* Trace recorder. */
    LJ_VMST_OPT,    /* Optimizer. */
    LJ_VMST_ASM,    /* Assembler. */
    LJ_VMST__MAX
};

#define setvmstate(g, st) ((g)->vmstate = ~LJ_VMST_##st)

/* Metamethods. ORDER MM */
#ifdef LJ_HASFFI
#define MMDEF_FFI(_) _(new)
#else
#define MMDEF_FFI(_)
#endif

#if LJ_52 || LJ_HASFFI
#define MMDEF_PAIRS(_) _(pairs) _(ipairs)
#else
#define MMDEF_PAIRS(_)
#define MM_pairs 255
#define MM_ipairs 255
#endif

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
    _(unm) /* The following are used in the standard libraries. */               \
    _(metatable) _(tostring) MMDEF_FFI(_) MMDEF_PAIRS(_)

typedef enum {
#define MMENUM(name) MM_##name,
    MMDEF(MMENUM)
#undef MMENUM
        MM__MAX,
    MM____ = MM__MAX,
    MM_FAST = MM_len
} MMS;

#include "lj_bc.h"
#include "lj_bcdef.h"

/* GC root IDs. */
typedef enum {
    GCROOT_MMNAME, /* Metamethod names. */
    GCROOT_MMNAME_LAST = GCROOT_MMNAME + MM__MAX - 1,
    GCROOT_BASEMT, /* Metatables for base types. */
    GCROOT_BASEMT_NUM = GCROOT_BASEMT + ~LJ_TNUMX,
    GCROOT_IO_INPUT,  /* Userdata for default I/O input file. */
    GCROOT_IO_OUTPUT, /* Userdata for default I/O output file. */
    GCROOT_MAX
} GCRootID;

/* Garbage collector state. */
typedef struct GCState {
    GCSize total;         /* Memory currently allocated. */
    GCSize threshold;     /* Memory threshold. */
    uint8_t currentwhite; /* Current white color. */
    uint8_t state;        /* GC state. */
    uint8_t nocdatafin;   /* No cdata finalizer called. */
#if LJ_64
    uint8_t lightudnum; /* Number of lightuserdata segments - 1. */
#else
    uint8_t unused1;
#endif
    MSize sweepstr;  /* Sweep position in string table. */
    GCRef root;      /* List of all collectable objects. */
    MRef sweep;      /* Sweep position in root list. */
    GCRef gray;      /* List of gray objects. */
    GCRef grayagain; /* List of objects for atomic traversal. */
    GCRef weak;      /* List of weak tables (to be cleared). */
    GCRef mmudata;   /* List of userdata (to be finalized). */
    GCSize debt;     /* Debt (how much GC is behind schedule). */
    GCSize estimate; /* Estimate of memory actually in use. */
    MSize stepmul;   /* Incremental GC step granularity. */
    MSize pause;     /* Pause between successive GC cycles. */
#if LJ_64
    MRef lightudseg; /* Upper bits of lightuserdata segments. */
#endif
} GCState;

/* thread status */
#define LUA_OK 0
#define LUA_YIELD 1
#define LUA_ERRRUN 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5

/* Invalid bytecode position. */
#define NO_BCPOS (~(BCPos)0)

/* Stored IRType. */
typedef struct IRType1 {
    uint8_t irt;
} IRType1;

/* Stored combined IR opcode and type. */
typedef uint16_t IROpT;

/* IR references. */
typedef uint16_t IRRef1; /* One stored reference. */
typedef uint32_t IRRef2; /* Two stored references. */
typedef uint32_t IRRef;  /* Used to pass around references. */

/* Stored opcode. */
typedef uint8_t IROp1;

typedef int64_t intptr_t;

#ifdef LJ_TARGET_X64
#define CFRAME_OFS_PC (3 * 8)
#define CFRAME_OFS_L (2 * 8)
#define CFRAME_OFS_ERRF (3 * 4)
#define CFRAME_OFS_NRES (2 * 4)
#define CFRAME_OFS_MULTRES (0 * 4)
#define CFRAME_OFS_PREV (4 * 8)
#elif LJ_TARGET_ARM64
#define CFRAME_OFS_ERRF 36
#define CFRAME_OFS_NRES 40
#define CFRAME_OFS_PREV 0
#define CFRAME_OFS_L 16
#define CFRAME_OFS_PC 8
#define CFRAME_OFS_MULTRES 32
#define CFRAME_SIZE 208
#define CFRAME_SHIFT_MULTRES 3
#endif

#define CFRAME_RESUME 1
#define CFRAME_UNWIND_FF 2 /* Only used in unwinder. */
#define CFRAME_RAWMASK (~(intptr_t)(CFRAME_RESUME | CFRAME_UNWIND_FF))

#define cframe_errfunc(cf) (*(int32_t *)(((char *)(cf)) + CFRAME_OFS_ERRF))
#define cframe_nres(cf)                                                                        \
    ({                                                                                         \
        int32_t __x;                                                                           \
        bpf_probe_read_user(&__x, sizeof(__x), (int32_t *)(((char *)(cf)) + CFRAME_OFS_NRES)); \
        __x;                                                                                   \
    })
#define cframe_nres_addr(cf) (int32_t *)(((char *)(cf)) + CFRAME_OFS_NRES)
#define cframe_prev_addr(cf) (void **)(((char *)(cf)) + CFRAME_OFS_PREV)
#define cframe_multres(cf) (*(uint32_t *)(((char *)(cf)) + CFRAME_OFS_MULTRES))
#define cframe_multres_n(cf) (cframe_multres((cf)) >> CFRAME_SHIFT_MULTRES)
// #define cframe_L(cf) (&gcref(*(GCRef *)(((char *)(cf)) + CFRAME_OFS_L))->th)
#define cframe_L_addr(cf) (GCRef *)(((char *)(cf)) + CFRAME_OFS_L)
#define cframe_L(addr) &gcref(addr)->th
// #define cframe_pc(cf) (mref(*(MRef *)(((char *)(cf)) + CFRAME_OFS_PC), const BCIns))

#define cframe_pc_addr(cf) (MRef *)(((char *)(cf)) + CFRAME_OFS_PC)

#define setcframe_L(cf, L) (setmref(*(MRef *)(((char *)(cf)) + CFRAME_OFS_L), (L)))
#define setcframe_pc(cf, pc) (setmref(*(MRef *)(((char *)(cf)) + CFRAME_OFS_PC), (pc)))
#define cframe_canyield(cf) ((intptr_t)(cf) & CFRAME_RESUME)
#define cframe_unwind_ff(cf) ((intptr_t)(cf) & CFRAME_UNWIND_FF)
#define cframe_raw(cf) ((void *)((intptr_t)(cf) & CFRAME_RAWMASK))
#define cframe_Lpc(L) cframe_pc(cframe_raw(L->cframe))

/* IR instruction format (64 bit).
**
**    16      16     8   8   8   8
** +-------+-------+---+---+---+---+
** |  op1  |  op2  | t | o | r | s |
** +-------+-------+---+---+---+---+
** |  op12/i/gco32 |   ot  | prev  | (alternative fields in union)
** +-------+-------+---+---+---+---+
** |  TValue/gco64                 | (2nd IR slot for 64 bit constants)
** +---------------+-------+-------+
**        32           16      16
**
** prev is only valid prior to register allocation and then reused for r + s.
*/

typedef union IRIns {
    struct {
        LJ_ENDIAN_LOHI(IRRef1 op1;   /* IR operand 1. */
                       , IRRef1 op2; /* IR operand 2. */
        )
        IROpT ot;    /* IR opcode and type (overlaps t and o). */
        IRRef1 prev; /* Previous ins in same chain (overlaps r and s). */
    };
    struct {
        IRRef2 op12;              /* IR operand 1 and 2 (overlaps op1 and op2). */
        LJ_ENDIAN_LOHI(IRType1 t; /* IR type. */
                       , IROp1 o; /* IR opcode. */
        )
        LJ_ENDIAN_LOHI(uint8_t r;   /* Register allocation (overlaps prev). */
                       , uint8_t s; /* Spill slot allocation (overlaps prev). */
        )
    };
    int32_t i; /* 32 bit signed integer literal (overlaps op12). */
    GCRef gcr; /* GCobj constant (overlaps op12 or entire slot). */
    MRef ptr;  /* Pointer constant (overlaps op12 or entire slot). */
    TValue tv; /* TValue constant (overlaps entire slot). */
} IRIns;

/* Snapshot and exit numbers. */
typedef uint32_t SnapNo;
typedef uint32_t ExitNo;

/* Trace number. */
typedef uint32_t TraceNo;  /* Used to pass around trace numbers. */
typedef uint16_t TraceNo1; /* Stored trace number. */

/* Stack snapshot header. */
typedef struct SnapShot {
    uint32_t mapofs; /* Offset into snapshot map. */
    IRRef1 ref;      /* First IR ref for this snapshot. */
    uint16_t mcofs;  /* Offset into machine code in MCode units. */
    uint8_t nslots;  /* Number of valid slots. */
    uint8_t topslot; /* Maximum frame extent. */
    uint8_t nent;    /* Number of compressed entries. */
    uint8_t count;   /* Count of taken exits for this snapshot. */
} SnapShot;

/* Compressed snapshot entry. */
typedef uint32_t SnapEntry;

/* Machine code type. */
// #if LJ_TARGET_X86ORX64
typedef uint8_t MCode;
// #else
// typedef uint32_t MCode;
// #endif

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
    MSize szmcode;      /* Size of machine code. */
    MCode *mcode;       /* Start of machine code. */
#if LJ_ABI_PAUTH
    ASMFunction mcauth; /* Start of machine code, with ptr auth applied. */
#endif
    MSize mcloop;      /* Offset of loop start in machine code. */
    uint16_t nchild;   /* Number of child traces (root trace only). */
    uint16_t spadjust; /* Stack pointer adjustment (offset in bytes). */
    TraceNo1 traceno;  /* Trace number. */
    TraceNo1 link;     /* Linked trace (or self for loops). */
    TraceNo1 root;     /* Root trace of side trace (or 0 for root traces). */
    TraceNo1 nextroot; /* Next root trace for same prototype. */
    TraceNo1 nextside; /* Next side trace of same root trace. */
    uint8_t sinktags;  /* Trace has SINK tags. */
    uint8_t topslot;   /* Top stack slot already checked to be allocated. */
    uint8_t linktype;  /* Type of link. */
    uint8_t unused1;
#ifdef LUAJIT_USE_GDBJIT
    void *gdbjit_entry; /* GDB JIT entry. */
#endif
} GCtrace;

#define restorestack(L, n) ((TValue *)(mref(BPF_PROBE_READ_USER(L, stack), char) + (n)))

/* Note: changing the following defines breaks the Lua 5.1 ABI. */
#define LUA_INTEGER ptrdiff_t
#define LUA_IDSIZE 60 /* Size of lua_Debug.short_src. */

/*
** prototype for memory-allocation functions
*/
typedef void *(*lua_Alloc)(void *ud, void *ptr, size_t osize, size_t nsize);

struct lua_Debug {
    int event;
    const char *name;           /* (n) */
    const char *namewhat;       /* (n) `global', `local', `field', `method' */
    const char *what;           /* (S) `Lua', `C', `main', `tail' */
    const char *source;         /* (S) */
    int currentline;            /* (l) */
    int nups;                   /* (u) number of upvalues */
    int linedefined;            /* (S) */
    int lastlinedefined;        /* (S) */
    char short_src[LUA_IDSIZE]; /* (S) */
    /* private part */
    int i_ci; /* active function */
};

typedef struct lua_Debug lua_Debug; /* activation record */

/* Functions to be called by the debuger in specific events */
typedef void (*lua_Hook)(lua_State *L, lua_Debug *ar);

/* String interning state. */
typedef struct StrInternState {
    GCRef *tab;       /* String hash table anchors. */
    MSize mask;       /* String hash mask (size of hash table - 1). */
    MSize num;        /* Number of strings in hash table. */
    StrID id;         /* Next string ID. */
    uint8_t idreseed; /* String ID reseed counter. */
    uint8_t second;   /* String interning table uses secondary hashing. */
    uint8_t unused1;
    uint8_t unused2;
    LJ_ALIGN(8) uint64_t seed; /* Random string seed. */
} StrInternState;

/* Hash node. */
typedef struct Node {
    TValue val; /* Value object. Must be first field. */
    TValue key; /* Key object. */
    MRef next;  /* Hash chain. */
#if !LJ_GC64
    MRef freetop; /* Top of free elements (stored in t->node[0]). */
#endif
} Node;

/* Global state, shared by all threads of a Lua universe. */
typedef struct global_State {
    lua_Alloc allocf;         /* Memory allocator. */
    void *allocd;             /* Memory allocator data. */
    GCState gc;               /* Garbage collector. */
    GCstr strempty;           /* Empty string. */
    uint8_t stremptyz;        /* Zero terminator of empty string. */
    uint8_t hookmask;         /* Hook mask. */
    uint8_t dispatchmode;     /* Dispatch mode. */
    uint8_t vmevmask;         /* VM event mask. */
    StrInternState str;       /* String interning. */
    volatile int32_t vmstate; /* VM state or current JIT code trace number. */
    GCRef mainthref;          /* Link to main thread. */
    SBuf tmpbuf;              /* Temporary string buffer. */
    TValue tmptv, tmptv2;     /* Temporary TValues. */
    Node nilnode;             /* Fallback 1-element hash part (nil key and value). */
    TValue registrytv;        /* Anchor for registry. */
    GCupval uvhead;           /* Head of double-linked list of all open upvalues. */
    int32_t hookcount;        /* Instruction hook countdown. */
    int32_t hookcstart;       /* Start count for instruction hook counter. */
    lua_Hook hookf;           /* Hook function. */
    lua_CFunction wrapf;      /* Wrapper for C function calls. */
    lua_CFunction panic;      /* Called as a last resort for errors. */
    BCIns bc_cfunc_int;       /* Bytecode for internal C function calls. */
    BCIns bc_cfunc_ext;       /* Bytecode for external C function calls. */
    GCRef cur_L;              /* Currently executing lua_State. */
    MRef jit_base;            /* Current JIT code L->base or NULL. */
    MRef ctype_state;         /* Pointer to C type state. */
    PRNGState prng;           /* Global PRNG state. */
    GCRef gcroot[GCROOT_MAX]; /* GC roots. */
    MRef saved_jit_base;      /* saved jit_base for lj_err_throw */
} global_State;

#define G(L) (mref(BPF_PROBE_READ_USER(L, glref), global_State))

#define LJ_STACK_EXTRA (5 + 2 * LJ_FR2) /* Extra stack space (metamethods). */

/* Optimization parameters and their defaults. Length is a char in octal! */
#define JIT_PARAMDEF(_)                                                    \
    _(\010, maxtrace, 8000)   /* Max. # of traces in cache. */             \
    _(\011, maxrecord, 16000) /* Max. # of recorded IR instructions. */    \
    _(\012, maxirconst, 500)  /* Max. # of IR constants of a trace. */     \
    _(\007, maxside, 100)     /* Max. # of side traces of a root trace. */ \
    _(\007, maxsnap, 500)     /* Max. # of snapshots for a trace. */       \
    _(\011, minstitch, 3)     /* Min. # of IR ins for a stitched trace. */ \
                                                                           \
    _(\007, hotloop, 56) /* # of iter. to detect a hot loop/call. */       \
    _(\007, hotexit, 10) /* # of taken exits to start a side trace. */     \
    _(\007, tryside, 4)  /* # of attempts to compile a side trace. */      \
                                                                           \
    _(\012, instunroll, 4)  /* Max. unroll for instable loops. */          \
    _(\012, loopunroll, 15) /* Max. unroll for loop ops in side traces. */ \
    _(\012, callunroll, 3)  /* Max. unroll for recursive calls. */         \
    _(\011, recunroll, 2)   /* Min. unroll for true recursion. */          \
                                                                           \
    /* Size of each machine code area (in KBytes). */                      \
    _(\011, sizemcode, JIT_P_sizemcode_DEFAULT)                            \
    /* Max. total size of all machine code areas (in KBytes). */           \
    _(\010, maxmcode, 40960)                                               \
    /* End of list. */

enum {
#define JIT_PARAMENUM(len, name, value) JIT_P_##name,
    JIT_PARAMDEF(JIT_PARAMENUM)
#undef JIT_PARAMENUM
        JIT_P__MAX
};

/* Round-robin penalty cache for bytecodes leading to aborted traces. */
typedef struct HotPenalty {
    MRef pc;         /* Starting bytecode PC. */
    uint16_t val;    /* Penalty value, i.e. hotcount start. */
    uint16_t reason; /* Abort reason (really TraceErr). */
} HotPenalty;

#define PENALTY_SLOTS 64     /* Penalty cache slot. Must be a power of 2. */
#define PENALTY_MIN (36 * 2) /* Minimum penalty value. */
#define PENALTY_MAX 60000    /* Maximum penalty value. */
#define PENALTY_RNDBITS 4    /* # of random bits to add to penalty value. */

/* Round-robin backpropagation cache for narrowing conversions. */
typedef struct BPropEntry {
    IRRef1 key; /* Key: original reference. */
    IRRef1 val; /* Value: reference after conversion. */
    IRRef mode; /* Mode for this entry (currently IRCONV_*). */
} BPropEntry;

/* Number of slots for the backpropagation cache. Must be a power of 2. */
#define BPROP_SLOTS 16

/* Scalar evolution analysis cache. */
typedef struct ScEvEntry {
    MRef pc;      /* Bytecode PC of FORI. */
    IRRef1 idx;   /* Index reference. */
    IRRef1 start; /* Constant start reference. */
    IRRef1 stop;  /* Constant stop reference. */
    IRRef1 step;  /* Constant step reference. */
    IRType1 t;    /* Scalar type. */
    uint8_t dir;  /* Direction. 1: +, 0: -. */
} ScEvEntry;

/* -- IR instructions ----------------------------------------------------- */

/* IR instruction definition. Order matters, see below. ORDER IR */
#define IRDEF(_)                                                                \
    /* Guarded assertions. */                                                   \
    /* Must be properly aligned to flip opposites (^1) and (un)ordered (^4). */ \
    _(LT, N, ref, ref)                                                          \
    _(GE, N, ref, ref)                                                          \
    _(LE, N, ref, ref)                                                          \
    _(GT, N, ref, ref)                                                          \
                                                                                \
    _(ULT, N, ref, ref)                                                         \
    _(UGE, N, ref, ref)                                                         \
    _(ULE, N, ref, ref)                                                         \
    _(UGT, N, ref, ref)                                                         \
                                                                                \
    _(EQ, C, ref, ref)                                                          \
    _(NE, C, ref, ref)                                                          \
                                                                                \
    _(ABC, N, ref, ref)                                                         \
    _(RETF, S, ref, ref)                                                        \
                                                                                \
    /* Miscellaneous ops. */                                                    \
    _(NOP, N, ___, ___)                                                         \
    _(BASE, N, lit, lit)                                                        \
    _(PVAL, N, lit, ___)                                                        \
    _(GCSTEP, S, ___, ___)                                                      \
    _(HIOP, S, ref, ref)                                                        \
    _(LOOP, S, ___, ___)                                                        \
    _(USE, S, ref, ___)                                                         \
    _(PHI, S, ref, ref)                                                         \
    _(RENAME, S, ref, lit)                                                      \
    _(PROF, S, ___, ___)                                                        \
                                                                                \
    /* Constants. */                                                            \
    _(KPRI, N, ___, ___)                                                        \
    _(KINT, N, cst, ___)                                                        \
    _(KGC, N, cst, ___)                                                         \
    _(KPTR, N, cst, ___)                                                        \
    _(KKPTR, N, cst, ___)                                                       \
    _(KNULL, N, cst, ___)                                                       \
    _(KNUM, N, cst, ___)                                                        \
    _(KINT64, N, cst, ___)                                                      \
    _(KSLOT, N, ref, lit)                                                       \
                                                                                \
    /* Bit ops. */                                                              \
    _(BNOT, N, ref, ___)                                                        \
    _(BSWAP, N, ref, ___)                                                       \
    _(BAND, C, ref, ref)                                                        \
    _(BOR, C, ref, ref)                                                         \
    _(BXOR, C, ref, ref)                                                        \
    _(BSHL, N, ref, ref)                                                        \
    _(BSHR, N, ref, ref)                                                        \
    _(BSAR, N, ref, ref)                                                        \
    _(BROL, N, ref, ref)                                                        \
    _(BROR, N, ref, ref)                                                        \
                                                                                \
    /* Arithmetic ops. ORDER ARITH */                                           \
    _(ADD, C, ref, ref)                                                         \
    _(SUB, N, ref, ref)                                                         \
    _(MUL, C, ref, ref)                                                         \
    _(DIV, N, ref, ref)                                                         \
    _(MOD, N, ref, ref)                                                         \
    _(POW, N, ref, ref)                                                         \
    _(NEG, N, ref, ref)                                                         \
                                                                                \
    _(ABS, N, ref, ref)                                                         \
    _(LDEXP, N, ref, ref)                                                       \
    _(MIN, C, ref, ref)                                                         \
    _(MAX, C, ref, ref)                                                         \
    _(FPMATH, N, ref, lit)                                                      \
                                                                                \
    /* Overflow-checking arithmetic ops. */                                     \
    _(ADDOV, CW, ref, ref)                                                      \
    _(SUBOV, NW, ref, ref)                                                      \
    _(MULOV, CW, ref, ref)                                                      \
                                                                                \
    /* Memory ops. A = array, H = hash, U = upvalue, F = field, S = stack. */   \
                                                                                \
    /* Memory references. */                                                    \
    _(AREF, R, ref, ref)                                                        \
    _(HREFK, R, ref, ref)                                                       \
    _(HREF, L, ref, ref)                                                        \
    _(NEWREF, S, ref, ref)                                                      \
    _(UREFO, LW, ref, lit)                                                      \
    _(UREFC, LW, ref, lit)                                                      \
    _(FREF, R, ref, lit)                                                        \
    _(TMPREF, S, ref, lit)                                                      \
    _(STRREF, N, ref, ref)                                                      \
    _(LREF, L, ___, ___)                                                        \
                                                                                \
    /* Loads and Stores. These must be in the same order. */                    \
    _(ALOAD, L, ref, ___)                                                       \
    _(HLOAD, L, ref, ___)                                                       \
    _(ULOAD, L, ref, ___)                                                       \
    _(FLOAD, L, ref, lit)                                                       \
    _(XLOAD, L, ref, lit)                                                       \
    _(SLOAD, L, lit, lit)                                                       \
    _(VLOAD, L, ref, lit)                                                       \
    _(ALEN, L, ref, ref)                                                        \
                                                                                \
    _(ASTORE, S, ref, ref)                                                      \
    _(HSTORE, S, ref, ref)                                                      \
    _(USTORE, S, ref, ref)                                                      \
    _(FSTORE, S, ref, ref)                                                      \
    _(XSTORE, S, ref, ref)                                                      \
                                                                                \
    /* Allocations. */                                                          \
    _(SNEW, N, ref, ref) /* CSE is ok, not marked as A. */                      \
    _(XSNEW, A, ref, ref)                                                       \
    _(TNEW, AW, lit, lit)                                                       \
    _(TDUP, AW, ref, ___)                                                       \
    _(CNEW, AW, ref, ref)                                                       \
    _(CNEWI, NW, ref, ref) /* CSE is ok, not marked as A. */                    \
                                                                                \
    /* Buffer operations. */                                                    \
    _(BUFHDR, L, ref, lit)                                                      \
    _(BUFPUT, LW, ref, ref)                                                     \
    _(BUFSTR, AW, ref, ref)                                                     \
                                                                                \
    /* Barriers. */                                                             \
    _(TBAR, S, ref, ___)                                                        \
    _(OBAR, S, ref, ref)                                                        \
    _(XBAR, S, ___, ___)                                                        \
                                                                                \
    /* Type conversions. */                                                     \
    _(CONV, N, ref, lit)                                                        \
    _(TOBIT, N, ref, ref)                                                       \
    _(TOSTR, N, ref, lit)                                                       \
    _(STRTO, N, ref, ___)                                                       \
                                                                                \
    /* Calls. */                                                                \
    _(CALLN, NW, ref, lit)                                                      \
    _(CALLA, AW, ref, lit)                                                      \
    _(CALLL, LW, ref, lit)                                                      \
    _(CALLS, S, ref, lit)                                                       \
    _(CALLXS, S, ref, ref)                                                      \
    _(CARG, N, ref, ref)                                                        \
                                                                                \
    /* End of list. */

/* IR opcodes (max. 256). */
typedef enum {
#define IRENUM(name, m, m1, m2) IR_##name,
    IRDEF(IRENUM)
#undef IRENUM
        IR__MAX
} IROp;

/* Tagged IR references (32 bit).
**
** +-------+-------+---------------+
** |  irt  | flags |      ref      |
** +-------+-------+---------------+
**
** The tag holds a copy of the IRType and speeds up IR type checks.
*/
typedef uint32_t TRef;

/* Fold state is used to fold instructions on-the-fly. */
typedef struct FoldState {
    IRIns ins;      /* Currently emitted instruction. */
    IRIns left[2];  /* Instruction referenced by left operand. */
    IRIns right[2]; /* Instruction referenced by right operand. */
} FoldState;

/* Trace compiler state. */
typedef enum {
    LJ_TRACE_IDLE, /* Trace compiler idle. */
    LJ_TRACE_ACTIVE = 0x10,
    LJ_TRACE_RECORD,     /* Bytecode recording active. */
    LJ_TRACE_RECORD_1ST, /* Record 1st instruction, too. */
    LJ_TRACE_START,      /* New trace started. */
    LJ_TRACE_END,        /* End of trace. */
    LJ_TRACE_ASM,        /* Assemble trace. */
    LJ_TRACE_ERR         /* Trace aborted with error. */
} TraceState;

/* Post-processing action. */
typedef enum {
    LJ_POST_NONE,         /* No action. */
    LJ_POST_FIXCOMP,      /* Fixup comparison and emit pending guard. */
    LJ_POST_FIXGUARD,     /* Fixup and emit pending guard. */
    LJ_POST_FIXGUARDSNAP, /* Fixup and emit pending guard and snapshot. */
    LJ_POST_FIXBOOL,      /* Fixup boolean result. */
    LJ_POST_FIXCONST,     /* Fixup constant results. */
    LJ_POST_FFRETRY       /* Suppress recording of retried fast functions. */
} PostProc;

/* 128 bit SIMD constants. */
enum { LJ_KSIMD_ABS, LJ_KSIMD_NEG, LJ_KSIMD__MAX };

/* JIT compiler limits. */
#define LJ_MAX_JSLOTS 250    /* Max. # of stack slots for a trace. */
#define LJ_MAX_PHI 64        /* Max. # of PHIs for a loop. */
#define LJ_MAX_EXITSTUBGR 16 /* Max. # of exit stub groups. */

/* JIT compiler state. */
typedef struct jit_State {
    GCtrace cur;       /* Current trace. */
    GCtrace *curfinal; /* Final address of current trace (set during asm). */

    lua_State *L;    /* Current Lua state. */
    const BCIns *pc; /* Current PC. */
    GCfunc *fn;      /* Current function. */
    GCproto *pt;     /* Current prototype. */
    TRef *base;      /* Current frame base, points into J->slots. */

    uint32_t flags; /* JIT engine flags. */
    BCReg maxslot;  /* Relative to baseslot. */
    BCReg baseslot; /* Current frame base, offset into J->slots. */

    uint8_t mergesnap; /* Allowed to merge with next snapshot. */
    uint8_t needsnap;  /* Need snapshot before recording next bytecode. */
    IRType1 guardemit; /* Accumulated IRT_GUARD for emitted instructions. */
    uint8_t bcskip;    /* Number of bytecode instructions to skip. */

    FoldState fold; /* Fold state. */

    const BCIns *bc_min; /* Start of allowed bytecode range for root trace. */
    MSize bc_extent;     /* Extent of the range. */

    TraceState state; /* Trace compiler state. */

    int32_t instunroll; /* Unroll counter for instable loops. */
    int32_t loopunroll; /* Unroll counter for loop ops in side traces. */
    int32_t tailcalled; /* Number of successive tailcalls. */
    int32_t framedepth; /* Current frame depth. */
    int32_t retdepth;   /* Return frame depth (count of RETF). */

#if LJ_K32__USED
    uint32_t k32[LJ_K32__MAX]; /* Common 4 byte constants used by backends. */
#endif
    TValue ksimd[LJ_KSIMD__MAX * 2 + 1]; /* 16 byte aligned SIMD constants. */
#if LJ_K64__USED
    TValue k64[LJ_K64__MAX]; /* Common 8 byte constants. */
#endif

    IRIns *irbuf;   /* Temp. IR instruction buffer. Biased with REF_BIAS. */
    IRRef irtoplim; /* Upper limit of instuction buffer (biased). */
    IRRef irbotlim; /* Lower limit of instuction buffer (biased). */
    IRRef loopref;  /* Last loop reference or ref of final LOOP (or 0). */

    MSize sizesnap;        /* Size of temp. snapshot buffer. */
    SnapShot *snapbuf;     /* Temp. snapshot buffer. */
    SnapEntry *snapmapbuf; /* Temp. snapshot map buffer. */
    MSize sizesnapmap;     /* Size of temp. snapshot map buffer. */

    PostProc postproc; /* Required post-processing after execution. */
#if LJ_SOFTFP32 || (LJ_32 && LJ_HASFFI)
    uint8_t needsplit; /* Need SPLIT pass. */
#endif
    uint8_t retryrec; /* Retry recording. */

    GCRef *trace;      /* Array of traces. */
    TraceNo freetrace; /* Start of scan for next free trace. */
    MSize sizetrace;   /* Size of trace array. */
    IRRef1 ktrace;     /* Reference to KGC with GCtrace. */

    IRRef1 chain[IR__MAX];                     /* IR instruction skip-list chain anchors. */
    TRef slot[LJ_MAX_JSLOTS + LJ_STACK_EXTRA]; /* Stack slot map. */

    int32_t param[JIT_P__MAX]; /* JIT engine parameters. */

    MCode *exitstubgroup[LJ_MAX_EXITSTUBGR]; /* Exit stub group addresses. */

    HotPenalty penalty[PENALTY_SLOTS]; /* Penalty slots. */
    uint32_t penaltyslot;              /* Round-robin index into penalty slots. */

#ifdef LUAJIT_ENABLE_TABLE_BUMP
    RBCHashEntry rbchash[RBCHASH_SLOTS]; /* Reverse bytecode map. */
#endif

    BPropEntry bpropcache[BPROP_SLOTS]; /* Backpropagation cache slots. */
    uint32_t bpropslot;                 /* Round-robin index into bpropcache slots. */

    ScEvEntry scev; /* Scalar evolution analysis cache slots. */

    const BCIns *startpc; /* Bytecode PC of starting instruction. */
    TraceNo parent;       /* Parent of current side trace (0 for root traces). */
    ExitNo exitno;        /* Exit number in parent of current side trace. */
    int exitcode;         /* Exit code from unwound trace. */

    BCIns *patchpc; /* PC for pending re-patch. */
    BCIns patchins; /* Instruction for pending re-patch. */

    int mcprot;         /* Protection of current mcode area. */
    MCode *mcarea;      /* Base of current mcode area. */
    MCode *mctop;       /* Top of current mcode area. */
    MCode *mcbot;       /* Bottom of current mcode area. */
    size_t szmcarea;    /* Size of current mcode area. */
    size_t szallmcarea; /* Total size of all allocated mcode areas. */

    TValue errinfo; /* Additional info element for trace errors. */

#if LJ_HASPROFILE
    GCproto *prev_pt; /* Previous prototype. */
    BCLine prev_line; /* Previous line. */
    int prof_mode;    /* Profiling mode: 0, 'f', 'l'. */
#endif
    PRNGState prng; /* PRNG state for the JIT compiler, defaults to prng in
                       global_State. */
} jit_State;

/* Type of hot counter. Must match the code in the assembler VM. */
/* 16 bits are sufficient. Only 0.0015% overhead with maximum slot penalty. */
typedef uint16_t HotCount;

/* Number of hot counter hash table entries (must be a power of two). */
#define HOTCOUNT_SIZE 64
#define HOTCOUNT_PCMASK ((HOTCOUNT_SIZE - 1) * sizeof(HotCount))

/* Hotcount decrements. */
#define HOTCOUNT_LOOP 2
#define HOTCOUNT_CALL 1

/* This solves a circular dependency problem -- bump as needed. Sigh. */
#define GG_NUM_ASMFF 57

#define GG_LEN_DDISP (BC__MAX + GG_NUM_ASMFF)
#define GG_LEN_SDISP BC_FUNCF
#define GG_LEN_DISP (GG_LEN_DDISP + GG_LEN_SDISP)

/* Global state, main thread and extra fields are allocated together. */
typedef struct GG_State {
    lua_State L;    /* Main thread. */
    global_State g; /* Global state. */
#if LJ_TARGET_ARM && !LJ_TARGET_NX
    /* Make g reachable via K12 encoded DISPATCH-relative addressing. */
    uint8_t align1[(16 - sizeof(global_State)) & 15];
#endif
#if LJ_TARGET_MIPS
    ASMFunction got[LJ_GOT__MAX]; /* Global offset table. */
#endif
#if LJ_HASJIT
    jit_State J;                      /* JIT state. */
    HotCount hotcount[HOTCOUNT_SIZE]; /* Hot counters. */
#if LJ_TARGET_ARM && !LJ_TARGET_NX
    /* Ditto for J. */
    uint8_t align2[(16 - sizeof(jit_State) - sizeof(HotCount) * HOTCOUNT_SIZE) & 15];
#endif
#endif
    ASMFunction dispatch[GG_LEN_DISP]; /* Instruction dispatch tables. */
    BCIns bcff[GG_NUM_ASMFF];          /* Bytecode for ASM fast functions. */
} GG_State;

#define GG_OFS(field) ((int)offsetof(GG_State, field))
#define G2GG(gl) ((GG_State *)((char *)(gl) - GG_OFS(g)))
#define J2GG(j) ((GG_State *)((char *)(j) - GG_OFS(J)))
#define L2GG(L) (G2GG(G(L)))
#define J2G(J) (&J2GG(J)->g)
#define G2J(gl) (&G2GG(gl)->J)
#define L2J(L) (&L2GG(L)->J)
#define GG_G2J (GG_OFS(J) - GG_OFS(g))
#define GG_G2DISP (GG_OFS(dispatch) - GG_OFS(g))
#define GG_DISP2G (GG_OFS(g) - GG_OFS(dispatch))
#define GG_DISP2J (GG_OFS(J) - GG_OFS(dispatch))
#define GG_DISP2HOT (GG_OFS(hotcount) - GG_OFS(dispatch))
#define GG_DISP2STATIC (GG_LEN_DDISP * (int)sizeof(ASMFunction))

/*
getting weird errors with this:

libbpf: BTF loading error: -22
-- BEGIN BTF LOAD LOG ---
magic: 0xeb9f
version: 1
...
Invalid offset
-- END BTF LOAD LOG
*/
/* Fixed internal variable names. */
#define VARNAMEDEF(_)             \
    _(FOR_IDX, "(for index)")     \
    _(FOR_STOP, "(for limit)")    \
    _(FOR_STEP, "(for step)")     \
    _(FOR_GEN, "(for generator)") \
    _(FOR_STATE, "(for state)")   \
    _(FOR_CTL, "(for control)")

enum {
    VARNAME_END,
#define VARNAMEENUM(name, str) VARNAME_##name,
    VARNAMEDEF(VARNAMEENUM)
#undef VARNAMEENUM
        VARNAME__MAX
};

#define itype(o) ((uint32_t)(BPF_PROBE_READ_USER(o, it64) >> 47))
#define tvisthread(o) (itype(o) == LJ_TTHREAD)
#define threadV(o) (&(gcval(o)->th))

#endif
