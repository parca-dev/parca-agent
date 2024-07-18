// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
//
// Copyright 2023-2024 The Parca Authors

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hash.h"
#include "shared.h"

#define LJ_AINLINE __always_inline

#if __TARGET_ARCH_arm64
#define LJ_TARGET_ARM64 1
#endif

#if __TARGET_ARCH_x86
#define LJ_TARGET_X64 1
#endif

#include "lua_state.h"

#define LUA_STACK_WALKING_PROGRAM_IDX 0
#define MAX_TAIL_CALLS 8
#define FRAMES_PER_CALL 16
//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Constants and Configuration                                             ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
const volatile bool verbose = false;

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║  BPF Maps                                                               ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

typedef struct {
    u32 cur_L_offset;
    u32 jit_base_offset;
} VMInfo;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, pid_t);
    __type(value, VMInfo);
} pid_to_vm_info SEC(".maps");

typedef struct {
    VMInfo info;
    lua_State *L;
    lua_State *uprobeL;
    cTValue *frame;
    cTValue *nextframe;
    cTValue *jit_base;
    u32 numTailCalls;
    stack_trace_t stack;
    error_t err;
} lua_unwind_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, lua_unwind_state_t);
} sample SEC(".maps");

// For ERROR_SAMPLE.
static const int BPF_PROGRAM = LUA_UNWINDER_PROGRAM_ID;

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Generic Helpers and Macros                                              ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//

#define LOG(fmt, ...)                               \
    ({                                              \
        if (verbose) {                              \
            bpf_printk("lua: " fmt, ##__VA_ARGS__); \
        }                                           \
    })

// static BCPos debug_framepc(lua_State *L, GCfunc *fn, cTValue *nextframe)
static __always_inline int lua_debug_framepc(lua_State *L, GCfunc *fn, cTValue *nextframe, BCPos *pos) {
    const BCIns *ins;
    GCproto *pt;
    void *p;
    //   lj_assertL(fn->c.gct == ~LJ_TFUNC || fn->c.gct == ~LJ_TTHREAD, "function or frame expected");
    uint8_t gct = BPF_PROBE_READ_USER(fn, c).gct;
    if (gct != ~LJ_TFUNC && gct != ~LJ_TTHREAD) {
        LOG("lua_debug_framepc: function or frame expected");
        return -1;
    }

    if (!isluafunc(fn)) { /* Cannot derive a PC for non-Lua functions. */
        return -12;
    } else if (nextframe == NULL) { /* Lua function on top. */
        void *cf = cframe_raw(BPF_PROBE_READ_USER(L, cframe));
        p = cframe_pc_addr(cf);
        MRef cframe_pc;
        bpf_probe_read_user(&cframe_pc, sizeof(cframe_pc), p);

        p = cframe_L_addr(cf);
        GCRef gval;
        bpf_probe_read_user(&gval, sizeof(gval), p);

        if (cf == NULL)
            return -2;
        else if (mref(cframe_pc, char *) == (char *)cframe_L(gval)) {
            return -11;
        }
        // ins = cframe_pc(cf); /* Only happens during error/hook handling. */
        ins = mref(cframe_pc, const BCIns);
    } else {
        if (frame_islua(nextframe)) {
            ins = frame_pc(nextframe);
        } else if (frame_iscont(nextframe)) {
            ins = frame_contpc(nextframe);
        } else {
            /* Lua function below errfunc/gc/hook: find cframe to get the PC. */
            void *cf = cframe_raw(BPF_PROBE_READ_USER(L, cframe));
            TValue *f = BPF_PROBE_READ_USER(L, base) - 1;
            for (int bpfLoopLimiter = 0; bpfLoopLimiter < 5; bpfLoopLimiter++) {
                if (cf == NULL)
                    return -4;
                int32_t nres;
                for (int bpfLoopLimiter2 = 0; bpfLoopLimiter2 < 5 && (nres = cframe_nres(cf)) < 0; bpfLoopLimiter2++) {
                    if (f >= restorestack(L, -nres))
                        break;
                    bpf_probe_read_user(&p, sizeof(void *), cframe_prev_addr(cf));
                    cf = cframe_raw(p);
                    if (cf == NULL)
                        return -5;
                    if (bpfLoopLimiter == 4) {
                        return -10;
                    }
                }
                if (f < nextframe)
                    break;
                if (frame_islua(f)) {
                    f = frame_prevl(f);
                } else {
                    bool isc = frame_isc(f);
                    if (isc || (frame_iscont(f) && frame_iscont_fficb(f))) {
                        bpf_probe_read_user(&p, sizeof(void *), cframe_prev_addr(cf));
                        cf = cframe_raw(p);
                    }
                    f = frame_prevd(f);
                }
                if (bpfLoopLimiter == 4) {
                    return -9;
                }
            }
            p = cframe_pc_addr(cf);
            MRef m;
            bpf_probe_read_user(&m, sizeof(m), p);
            ins = mref(m, const BCIns);
            if (!ins)
                return -6;
        }
    }
    pt = funcproto(fn);
    *pos = proto_bcpos(pt, ins) - 1;
    BCPos sizebc = BPF_PROBE_READ_USER(pt, sizebc);
    if (*pos > sizebc) { /* Undo the effects of lj_trace_exit for JLOOP. */
        BCIns insp;
        if (bpf_probe_read_user(&insp, sizeof(BCIns), ins - 1) != 0) {
            return -7;
        }
        if (bc_isret(bc_op(insp))) {
            GCtrace *T = (GCtrace *)((char *)(ins - 1) - offsetof(GCtrace, startins));
            *pos = proto_bcpos(pt, mref(BPF_PROBE_READ_USER(T, startpc), const BCIns));
        } else {
            return -8;
        }
    }
    return 0;
}

static __always_inline int lua_get_line(GCproto *pt, BCPos pc) {
    const void *lineinfo = BPF_PROBE_READ_USER(pt, lineinfo);
    MSize sizebc = BPF_PROBE_READ_USER(pt, sizebc);
    if (pc <= sizebc && lineinfo) {
        BCLine first = BPF_PROBE_READ_USER(pt, firstline);
        BCLine numline = BPF_PROBE_READ_USER(pt, numline);
        if (pc == sizebc)
            return first + numline;
        if (pc-- == 0)
            return first;
        if (numline < 256) {
            uint8_t offset;
            bpf_probe_read_user(&offset, 1, ((const uint8_t *)lineinfo) + pc);
            return first + offset;
        } else if (numline < 65536) {
            uint16_t offset;
            bpf_probe_read_user(&offset, 1, ((const uint16_t *)lineinfo) + pc);
            return first + offset;
        } else {
            uint32_t offset;
            bpf_probe_read_user(&offset, 1, ((const uint32_t *)lineinfo) + pc);
            return first + offset;
        }
    }
    return 0;
}

#define BUF_SIZE 16

/* Get name of upvalue. */
static __always_inline const char *lj_debug_uvname(GCproto *pt, uint32_t idx) {
    // uvinfo is all the names together as null terminated strings.
    const uint8_t *p = BPF_PROBE_READ_USER(pt, uvinfo);
    if (!p)
        return NULL;
    if (idx) {
        for (int i = 0; idx > 0 && i < 5; i++) {
            char c[BUF_SIZE];
            long len = bpf_probe_read_user_str(&c, BUF_SIZE, p);
            // If we have a short read (long variable name) read again.
            if (len == BUF_SIZE) {
                p += BUF_SIZE;
                continue;
            }
            if (len < 0) {
                return NULL;
            }
            p += len;
            idx--;
        }
    }
    return (const char *)p;
}

static int __always_inline lua_read_constant(BCReg reg, GCproto *pt, char *name, size_t siz) {
    ptrdiff_t idx = ~((ptrdiff_t)reg);
    GCRef *k = mref(BPF_PROBE_READ_USER(pt, k), GCRef);
    GCobj *o;
    int read;
    if ((read = bpf_probe_read_user(&o, sizeof(GCobj *), (void *)(k + idx))) == 0) {
        const char *strr = strdata(&o->str);
        if (bpf_probe_read_user_str(name, siz, strr) > 0) {
            return 0;
        }
    }
    // LOG("lua_read_constant failed reg=%u, idx=%d, k=%llx", reg, idx, k);
    return -1;
}

// lua_debug_slotname attempts to find the name used to look up the thing stored
// in slot by walking the lua instructions backwards from ip.
static int __always_inline lua_debug_slotname(GCproto *pt, const BCIns *ip, BCReg slot, symbol_t *sym) {
    // restart:
    int steps = 5;
    char *name = (char *)sym->method_name;
    size_t siz = sizeof(sym->method_name);
    for (int i = 0; i < steps; i++) {
        // NYI: not sure its needed...
        // if (lua_debug_varname(pt, proto_bcpos(pt, ip), slot, name, siz) == 0) {
        //     LOG("lua_debug_slotname: varname=%s", name);
        // }
        if (--ip == proto_bc(pt)) {
            return -11;
        }
        BCIns ins;
        if (bpf_probe_read_user(&ins, sizeof(BCIns), ip) != 0) {
            return -1;
        }
        BCOp op = bc_op(ins);
        BCReg ra = bc_a(ins);
        if (bcmode_a(op) == BCMbase) {
            if (slot >= ra && (op != BC_KNIL || slot <= bc_d(ins)))
                return -2;
        } else if (bcmode_a(op) == BCMdst && ra == slot) {
            if (op < BC__MAX) {
                LOG("lua_debug_slotname: op=%x:%x, slot=%d", op, ins, slot);
            }
            switch (bc_op(ins)) {
                case BC_MOV:
                    if (ra == slot) {
                        slot = bc_d(ins);
                    }
                    break;
                case BC_GGET: {
                    //*name = strdata(gco2str(proto_kgc(pt, ~(ptrdiff_t)bc_d(ins))));
                    if (lua_read_constant(bc_d(ins), pt, name, siz) == 0) {
                        return 0;
                    }
                    return -4;
                }
                case BC_TGETS: {
                    //*name = strdata(gco2str(proto_kgc(pt, ~(ptrdiff_t)bc_c(ins))));
                    if (lua_read_constant(bc_c(ins), pt, name, siz) == 0) {
                        // Go around again and pick up table lookup.
                        slot = bc_b(ins);
                        name = (char *)sym->class_name;
                        siz = sizeof(sym->class_name);
                    } else {
                        return -7;
                    }
                    break;
                }
                case BC_UGET: {
                    const char *src = lj_debug_uvname(pt, bc_d(ins));
                    if (src && bpf_probe_read_user_str(name, siz, src) > 0) {
                        return 0;
                    }
                    return -8;
                }
                default:
                    LOG("lua_debug_slotname saw unexpected instruction: %x", ins);
                    return -9;
            }
        }
    }
    return -10;
}

// If pc points to a CALL instruction get the slot it was stored in.
static __always_inline int lua_debug_slot(GCproto *pt, BCPos pc, BCReg *reg) {
    BCIns *ip = proto_bc(pt) + pc;
    BCIns ins;
    if (bpf_probe_read_user(&ins, sizeof(BCIns), ip) == 0) {
        MMS mm = bcmode_mm(bc_op(ins));
        if (mm == MM_call) {
            BCReg slot = bc_a(ins);
            if (bc_op(ins) == BC_ITERC)
                slot -= 3;
            *reg = slot;
            return 0;
        }
        return -1;
    }
    return -2;
}

// lua_debug_funcname attempts to get the current function name by looking at the calling frame
// and getting the name of the slot out of the call instruction
static __always_inline int lua_debug_funcname(lua_State *L, cTValue *frame, symbol_t *sym) {
    cTValue *pframe;
    GCfunc *fn;
    BCPos pc;
    if (frame_isvarg(frame))
        frame = frame_prevd(frame);
    pframe = frame_prev(frame);
    fn = frame_func(pframe);
    if (frame == NULL) {
        LOG("lua_debug_funcname couldn't get frame");
        return -1;
    }
    int res = lua_debug_framepc(L, fn, frame, &pc);
    if (res < 0) {
        LOG("lua_debug_framepc failed to get pc: %d", res);
        return -4;
    }
    BCReg slot;
    GCproto *pt = funcproto(fn);
    if ((res = lua_debug_slot(pt, pc, &slot)) != 0) {
        LOG("lua_debug_slot failed=%d, %d", res, slot);
        return -2;
    } else {
        if ((res = lua_debug_slotname(pt, proto_bc(pt) + pc, slot, sym)) != 0) {
            LOG("lua_debug_slotname failed=%d, %d", res, slot);
            return -3;
        }
    }
    return 0;
}

#define FUNCNAME_ERR "funcname_err: "

static __always_inline int lua_get_funcdata(struct bpf_perf_event_data *ctx, lua_State *L, cTValue *frame, cTValue *nextframe, stack_trace_t *st) {
    GCfunc *fn = frame_func(frame);
    if (!fn)
        return -2;
    if (isluafunc(fn)) {
        GCproto *pt = funcproto(fn);
        if (!pt)
            return -3;
        const char *src = proto_chunknamestr(pt); /* GCstr *name */
        if (!src)
            return -4;

        symbol_t sym = {};
        __builtin_memset((void *)&sym, 0, sizeof(symbol_t));

        int res;
        if ((res = bpf_probe_read_user_str(sym.path, sizeof(sym.path), src)) <= 0) {
            LOG("proto_chunknamestr failed=%d", res);
        }

        // Line comes from nextframe b/c the fn stored in each frame is the caller function.
        u64 lineno = 0;
        BCPos pc;
        res = lua_debug_framepc(L, fn, nextframe, &pc);
        if (res < 0) {
            LOG("lua_debug_framepc for lineno failed: %d fn=%llx,nextframe=%llx", res, fn, nextframe);
        } else {
            lineno = lua_get_line(pt, pc);
        }
        if ((res = lua_debug_funcname(L, frame, &sym) != 0)) {
            if (BPF_PROBE_READ_USER(pt, firstline) == 0) {
                __builtin_strncpy(sym.method_name, "main", 5);
            } else {
                __builtin_strncpy(sym.method_name, FUNCNAME_ERR, sizeof(FUNCNAME_ERR));
                char resp = -res;
                sym.method_name[sizeof(FUNCNAME_ERR) - 2] = resp + '0';
                LOG("lua_debug_funcname failed: %d", res);
            }
        }

        u64 id = get_symbol_id(&sym);
        u64 cur_len = st->len;
        if (st->len < MAX_STACK_DEPTH) {
            u64 key = (lineno << 32) | id;
            st->addresses[cur_len] = key;
            st->len++;
            LOG("lua_get_funcdata(%d): %s:%s", st->len, sym.class_name, sym.method_name);
            LOG("line:%u (%s):%x", lineno, sym.path, (u32)id);
        }
    } else if (iscfunc(fn)) {
        void *funcp = BPF_PROBE_READ_USER(fn, c.f);
        LOG("FUNC_TYPE_C: level= %d, funcp=0x%llx", st->len, funcp);
    } else if (isffunc(fn)) {
        uint8_t ffid = BPF_PROBE_READ_USER(fn, c.ffid);
        LOG("FUNC_TYPE_F: level= %d, ffid=0x%u", st->len, ffid);
    }
    return 0;
}

struct ngx_http_lua_co_ctx_s {
    void *data; /* user state for cosockets */
    lua_State *co;
};

/* fish_for_L attempts to find a lua_State pointer by searching a small number of pointers
   relative to some stack address, sp.  We look for a nginx context pointer which should
   have a lua_State at offset 0x8 and we also look for a direct lua_State pointer.
*/
static __always_inline lua_State *fish_for_L(u64 sp, int cur_L_offset) {
    struct ngx_http_lua_co_ctx_s *lua_co_ctx;
    lua_State *Lmaybe = NULL;

    for (int i = 1; i <= 4; i++) {
        bpf_probe_read_user(&lua_co_ctx, sizeof(lua_co_ctx), (void **)sp - i);
        if (lua_co_ctx == NULL) {
            continue;
        }
        Lmaybe = BPF_PROBE_READ_USER(lua_co_ctx, co);
        void *exdata2 = BPF_PROBE_READ_USER(Lmaybe, exdata2);
        if (exdata2 == lua_co_ctx) {
            LOG("unwind_lua_stack: picked up L from ngx_http_lua_co_ctx_s* on stack %llx", Lmaybe);
            break;
        } else {
            LOG("unwind_lua_stack: stack slot %i wasn't a ngx_http_lua_co_ctx_s, %llx, %llx", i, lua_co_ctx, exdata2);
        }

        // See if lua_State was on stack
        Lmaybe = (lua_State *)lua_co_ctx;
        global_State *globalp = mref(BPF_PROBE_READ_USER(Lmaybe, glref), global_State);
        void *cur_L;
        bpf_probe_read_user(&cur_L, sizeof(void *), (void *)((char *)globalp + cur_L_offset));

        if (cur_L == Lmaybe) {
            LOG("unwind_lua_stack: picked up L from stack %llx", Lmaybe);
            break;
        } else {
            // No luck.
            // TODO: should we require G->cur_L == Lmaybe or should we only require L->G->cur_L == G->cur_L,
            // that would be looser and maybe be more successful.
            Lmaybe = NULL;
        }
    }
    return Lmaybe;
}

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ BPF Programs                                                            ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
SEC("perf_event")
int unwind_lua_stack(struct bpf_perf_event_data *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid >> 32;
    pid_t tid = pid_tgid;

    u32 zero = 0;
    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        LOG("[error] unwind_state is NULL!");
        return 1;
    }

    lua_unwind_state_t *lua_unwind_state = bpf_map_lookup_elem(&sample, &zero);
    if (lua_unwind_state == NULL) {
        LOG("[error] lua_unwind_state is NULL!");
        return 1;
    }

    error_t *err_ctx = &lua_unwind_state->err;

    VMInfo *vm_info = bpf_map_lookup_elem(&pid_to_vm_info, &pid);
    if (!vm_info) {
        LOG("[error] vm_info is NULL, not a Lua process");
        ERROR_MSG(err_ctx, "vm_info was NULL");
        goto error;
    }

    lua_unwind_state->numTailCalls = 0;
    lua_unwind_state->jit_base = NULL;
    lua_unwind_state->L = NULL;
    lua_unwind_state->info = *vm_info;
    __builtin_memset(&lua_unwind_state->stack, 0, sizeof(stack_trace_t));

    global_State *G = NULL;
    lua_uprobe_state_t *uprobe_state = bpf_map_lookup_elem(&tid_to_lua_state, &tid);
    if (uprobe_state != NULL) {
        G = uprobe_state->G;
    }

    lua_State *L = NULL;
    if (G != NULL) {
        // Lua land could have done a coroutine switch and cur_L could be different now from what
        // the uprobe recorded.  Try to get L from G first then fall back to uprobeL.
        bpf_probe_read_user(&L, sizeof(void *), (char *)G + lua_unwind_state->info.cur_L_offset);
        if (G(L) != G) {
            LOG("G(%llx)->cur_L (offset %d) doesn't point to L(%llx)", G, lua_unwind_state->info.cur_L_offset, L);
            G = NULL;
        }
        if (lua_unwind_state->uprobeL) {
            L = lua_unwind_state->uprobeL;
            G = G(L);
            if (G != NULL) {
                if (G(L) != G) {
                    LOG("G(%llx)->cur_L (offset %d) doesn't point to lua_unwind_state->uprobeL(%llx)", G, lua_unwind_state->info.cur_L_offset, L);
                } else {
                    // Success!
                    LOG("Got L from lua_unwind_state->uprobeL, L(%llx), G(%llx)", L, G);
                }
            }
        }
    }

    if (L == NULL) {
        // TODO try to map IP to a lua bc position so get better line numbers
        // for stack top. Not sure how to do this, perhaps the code that
        // generates the luajit perf.map files could help but it looks like the
        // whole GCtrace gets mapped to a single line...

        // Attempt to get L if user probes are turned off.  This should probably
        // be enabled via a bit just for openresty ... for now always do it so
        // we can inspect logs to see if its working.
        // This is only used when uprobes are disabled or aren't firing.
        u64 sp = PT_REGS_SP(&ctx->regs);

        lua_State *Lmaybe = fish_for_L(sp, lua_unwind_state->info.cur_L_offset);

        // Try other spots on the stack.
        if (Lmaybe == NULL) {
            for (int i = 0; i < NUM_INTERESTING_STACK_ADDRESSES; i++) {
                Lmaybe = fish_for_L(unwind_state->interesting_stack_addresses[i], lua_unwind_state->info.cur_L_offset);
                if (Lmaybe != NULL) {
                    break;
                }
            }
        }

        if (Lmaybe != NULL) {
            L = Lmaybe;
            G = mref(BPF_PROBE_READ_USER(L, glref), global_State);
        }
    }

    if (L == NULL) {
        LOG("[debug] Lua unwind_lua_stack no context");
        ERROR_MSG(err_ctx, "context not found");
        goto error;
    } else if (G != NULL) {
        cTValue *base;
        bpf_probe_read_user(&base, sizeof(base), (void *)(((char *)G) + lua_unwind_state->info.jit_base_offset));
        lua_unwind_state->jit_base = base;
    }

    lua_unwind_state->frame = NULL;
    lua_unwind_state->nextframe = NULL;
    lua_unwind_state->L = L;
    LOG("[debug] tail calling lua stack walker");
    bpf_tail_call(ctx, &programs, LUA_STACK_WALKING_PROGRAM_IDX);

    return 0;

error:
    ERROR_SAMPLE(unwind_state, err_ctx);
    return 1;
}

SEC("perf_event")
int walk_lua_stack(struct bpf_perf_event_data *ctx) {
    int err = 0;
    u32 zero = 0;
    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        return 1;
    }
    lua_unwind_state_t *lua_unwind_state = bpf_map_lookup_elem(&sample, &zero);
    if (lua_unwind_state == NULL) {
        return 1;
    }
    error_t *err_ctx = &lua_unwind_state->err;
    lua_State *L = lua_unwind_state->L;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    int per_thread_id = pid_tgid;

    // TODO: Not sure if this thread stuff is needed, something to do with lua coroutines.
    // if (top > base && tvisthread(base)) {
    //     LOG("thread involved");
    //     GCobj *o = gcval(base);
    //     L2 = (lua_State *)o;
    //     l2base = BPF_PROBE_READ_USER(L2, base);
    // }

    if (lua_unwind_state->frame == NULL) {
        if (lua_unwind_state->jit_base != NULL) {
            lua_unwind_state->frame = lua_unwind_state->jit_base - 1;
        } else {
            lua_unwind_state->frame = BPF_PROBE_READ_USER(L, base) - 1;
        }
        lua_unwind_state->nextframe = lua_unwind_state->frame;
    }

    LOG("Lua walk, L=0x%llx, frame=%llx, nextframe=%llx", L, lua_unwind_state->frame, lua_unwind_state->nextframe);

    cTValue *bot = tvref(BPF_PROBE_READ_USER(L, stack)) + LJ_FR2;
    bool skip = false;
    for (int i = 0; i < FRAMES_PER_CALL && lua_unwind_state->frame > bot; i++) {
        if (frame_gc(lua_unwind_state->frame) == obj2gco(L)) {
            skip = true; /* Skip dummy frames. See lj_err_optype_call(). */
        }
        if (!skip) {
            err = lua_get_funcdata(ctx, L, lua_unwind_state->frame, lua_unwind_state->nextframe, &lua_unwind_state->stack);
            LOG("walk_lua_stack: lua_get_funcdata=%d", err);
            // Fail only if the first frame fails, this avoids throwing away a perfectly good stack
            // if something goes sideways.  TODO: synthetic error frame?
            if (err < 0 && lua_unwind_state->stack.len == 0) {
                ERROR_MSG(err_ctx, "first frame failed");
                goto error;
            }
        } else {
            skip = false;
        }
        lua_unwind_state->nextframe = lua_unwind_state->frame;
        if (frame_islua(lua_unwind_state->frame)) {
            lua_unwind_state->frame = frame_prevl(lua_unwind_state->frame);
        } else {
            if (frame_isvarg(lua_unwind_state->frame)) {
                skip = true; /* Skip vararg pseudo-frame. */
            }
            lua_unwind_state->frame = frame_prevd(lua_unwind_state->frame);
        }
    }

    if (lua_unwind_state->frame > bot) {
        if (lua_unwind_state->numTailCalls++ < MAX_TAIL_CALLS) {
            bpf_tail_call(ctx, &programs, LUA_STACK_WALKING_PROGRAM_IDX);
        } else {
            // TODO: add truncated stack frame?
        }
    }

    if (lua_unwind_state->stack.len == 0) {
        return 1;
    }

    // Hash stack.
    u64 stack_hash = hash_stack(&lua_unwind_state->stack, 0);
    LOG("[debug] stack hash: %d:%d", stack_hash, lua_unwind_state->stack.len);

    unwind_state->stack_key.interpreter_stack_id = stack_hash;

    // Insert stack.
    err = bpf_map_update_elem(&stack_traces, &stack_hash, &lua_unwind_state->stack, BPF_ANY);
    if (err != 0) {
        LOG("[error] failed to insert stack_traces with %d", err);
    }

    // If we had success remember G.
    global_State *G = G(L);
    void *cur_L;
    err = bpf_probe_read_user(&cur_L, sizeof(void *), (char *)G + lua_unwind_state->info.cur_L_offset);
    if (err == 0) {
        LOG("walk_lua_stack: could read G(%llx),cur_L=%llx", G, cur_L);
        if (bpf_map_update_elem(&tid_to_lua_state, &per_thread_id, &G, BPF_ANY) != 0) {
            LOG("tid_to_lua_state map update failed lua_State failed");
        }
    }

    aggregate_stacks();

    return 0;
error:
    ERROR_SAMPLE(unwind_state, err_ctx);
    // If we fail to unwind clear context.
    // G = NULL;
    // lua_unwind_state->L = NULL;
    return 1;
}

SEC("uprobe/lua_entrypoint")
int BPF_UPROBE(lua_entrypoint) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    lua_State *L = (lua_State *)PT_REGS_PARM1(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    u32 zero = 0;
    lua_unwind_state_t *lua_unwind_state = bpf_map_lookup_elem(&sample, &zero);
    if (lua_unwind_state == NULL) {
        return 1;
    }

    // Save entrypoint task state for later stack walking.
    lua_uprobe_state_t uprobe_state;
    uprobe_state.G = G(L);
    uprobe_state.sp = PT_REGS_SP(ctx);
    uprobe_state.ip = PT_REGS_IP(ctx);
    uprobe_state.bp = PT_REGS_FP(ctx);
    if (bpf_map_update_elem(&tid_to_lua_state, &tid, &uprobe_state, BPF_ANY) != 0) {
        LOG("tid_to_lua_state map update failed lua_State failed");
    }

    // Save L and G, we'll try to use both in the lua stack walking.
    if (lua_unwind_state->uprobeL != L) {
        LOG("lua_entrypoint: L=%llx, G=%llx", L, uprobe_state.G);
        lua_unwind_state->uprobeL = L;
    }

    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        // This should never happen.
        return false;
    }

    return 0;
}

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Metadata                                                                ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
#define KBUILD_MODNAME "lua"
volatile const char bpf_metadata_name[] SEC(".rodata") = "lua";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "Dual MIT/GPL";
