/* Execution test for the copy-and-patch stencil pipeline (copy-patch-rvvm.md).
 *
 * Copies stencils into executable memory, patches constants and
 * continuations, elides fallthrough branches, executes the result, and
 * compares every guest-cache slot against a C reference over deterministic
 * random programs and adversarial operands. Also exercises both outcomes of
 * the guard stencil.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "cp-emit.h"

#ifndef CP_NSLOTS
#define CP_NSLOTS 7
#endif
#define NSLOTS CP_NSLOTS
#define NPARAMS (5 + NSLOTS) /* sa pc cd fetch tcc + the guest slots */
/* Guest-value arrays are padded to the sixteen slots the entry call
 * names so the literal initializers and the fixed call stay well-formed
 * at smaller slot counts; entries at NSLOTS and beyond are inert. */
#define NSLOTS_PAD (NSLOTS < 16 ? 16 : NSLOTS)
#if NSLOTS > 16
#error "harness names sixteen slot arguments; extend the roster here"
#endif
#define HEAP_SIZE (16u << 20)

/* Parameter order of the target-specific stencil contract. */
#if defined(__x86_64__)
#define SLOT_POS_K(k) ((k) == 0 ? 1 : (k) + 4)
#define POS_SA 0
#define POS_PC 2
#define POS_CD 3
#define POS_FETCH 4
#define POS_TCC (4 + NSLOTS)
#else
#define SLOT_POS_K(k) ((k) == 0 ? 1 : (k) == 1 ? 2 : (k) == 2 ? 6 : (k) + 5)
#define POS_SA 0
#define POS_PC 3
#define POS_CD 4
#define POS_FETCH 5
#define POS_TCC 7
#endif
static const int SLOT_POS[NSLOTS_PAD] = {SLOT_POS_K(0), SLOT_POS_K(1), SLOT_POS_K(2), SLOT_POS_K(3), SLOT_POS_K(4),
    SLOT_POS_K(5), SLOT_POS_K(6), SLOT_POS_K(7), SLOT_POS_K(8), SLOT_POS_K(9), SLOT_POS_K(10), SLOT_POS_K(11),
    SLOT_POS_K(12), SLOT_POS_K(13), SLOT_POS_K(14), SLOT_POS_K(15)};

typedef __attribute__((preserve_none)) void (*cp_entry_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t);

#if defined(__x86_64__)
typedef __attribute__((preserve_none)) void (*cp_short_entry_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint8_t *x86_short_entry_target;

__attribute__((preserve_none, noinline)) static void x86_short_entry(uint64_t sa, uint64_t r0, uint64_t pc, uint64_t cd,
    uint64_t fetch) {
    __attribute__((musttail)) return ((cp_short_entry_t) x86_short_entry_target)(sa, r0, pc, cd, fetch);
}
#endif

static cp_heap_t heap;

#if defined(__x86_64__)
static int test_x86_fma_stencil_selection(void) {
    if (cp_fp_fmadd_s_rne_table[0][0] != &cp_s_cp_fp_fmadd_s_rne_0_0) {
        fprintf(stderr, "x86 FMA table does not start on the soft-only stencil\n");
        return 1;
    }
    cp_enable_x86_fma_stencils();
    if (cp_fp_fmadd_s_rne_table[0][0] != &cp_s_cp_fp_fmadd_s_rne_0_0_x86_fma) {
        fprintf(stderr, "x86 FMA table entry was not substituted\n");
        return 1;
    }
    return 0;
}
#endif

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint64_t rng(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* Adversarial constants mixed into random choices. */
static uint64_t pick_imm(void) {
    static const uint64_t edge[] = {0, 1, 0xffffffffffffffffull, 0x8000000000000000ull, 0x7fffffffffffffffull,
        0xffffffffull, 0x100000000ull, 0xfffeull, 0x10000ull};
    if ((rng() & 3) == 0) {
        return edge[rng() % (sizeof(edge) / sizeof(edge[0]))];
    }
    return rng();
}

/* Register-register ops: the reference expressions mirror the RISC-V rules
 * the stencils implement (independent semantic validation is the machine
 * differential gate's job; this validates placement, patching, and chain
 * mechanics across every family). */
#define I64 (int64_t)
#define I32 (int32_t)
#define U32 (uint32_t)
#define SX32(v) ((uint64_t) (int64_t) (int32_t) (v))
#define CP_REG_OPS(X)                                                                                                  \
    X(add, a + b)                                                                                                      \
    X(sub, a - b)                                                                                                      \
    X(and, a &b)                                                                                                       \
    X(or, a | b)                                                                                                       \
    X(xor, a ^ b)                                                                                                      \
    X(sll, a << (b & 63))                                                                                              \
    X(srl, a >> (b & 63))                                                                                              \
    X(sra, (uint64_t) (I64 a >> (b & 63)))                                                                             \
    X(slt, (I64 a < I64 b) ? 1 : 0)                                                                                    \
    X(sltu, (a < b) ? 1 : 0)                                                                                           \
    X(addw, SX32(U32 a + U32 b))                                                                                       \
    X(subw, SX32(U32 a - U32 b))                                                                                       \
    X(sllw, SX32(U32 a << (b & 31)))                                                                                   \
    X(srlw, SX32(U32 a >> (b & 31)))                                                                                   \
    X(sraw, (uint64_t) (int64_t) (I32 a >> (b & 31)))                                                                  \
    X(mul, a *b)                                                                                                       \
    X(mulw, SX32(U32 a *U32 b))                                                                                        \
    X(mulh, (uint64_t) (int64_t) (((__int128) I64 a * (__int128) I64 b) >> 64))                                        \
    X(mulhu, (uint64_t) (((unsigned __int128) a * (unsigned __int128) b) >> 64))                                       \
    X(mulhsu, (uint64_t) (int64_t) (((__int128) I64 a * (unsigned __int128) b) >> 64))                                 \
    X(div,                                                                                                             \
        (b == 0) ? (uint64_t) -1 :                                                                                     \
                   ((a == 0x8000000000000000ull && b == (uint64_t) -1) ? a : (uint64_t) (I64 a / I64 b)))              \
    X(divu, (b == 0) ? (uint64_t) -1 : (a / b))                                                                        \
    X(rem, (b == 0) ? a : ((a == 0x8000000000000000ull && b == (uint64_t) -1) ? 0 : (uint64_t) (I64 a % I64 b)))       \
    X(remu, (b == 0) ? a : (a % b))                                                                                    \
    X(divw,                                                                                                            \
        (U32 b == 0) ? (uint64_t) -1 :                                                                                 \
                       ((U32 a == 0x80000000u && I32 b == -1) ? SX32(a) : (uint64_t) (int64_t) (I32 a / I32 b)))       \
    X(divuw, (U32 b == 0) ? (uint64_t) -1 : SX32(U32 a / U32 b))                                                       \
    X(remw,                                                                                                            \
        (U32 b == 0) ? SX32(a) : ((U32 a == 0x80000000u && I32 b == -1) ? 0 : (uint64_t) (int64_t) (I32 a % I32 b)))   \
    X(remuw, (U32 b == 0) ? SX32(a) : SX32(U32 a % U32 b))

#define CP_BR_OPS(X)                                                                                                   \
    X(beq, a == b)                                                                                                     \
    X(bne, a != b)                                                                                                     \
    X(blt, I64 a < I64 b)                                                                                              \
    X(bge, I64 a >= I64 b)                                                                                             \
    X(bltu, a < b)                                                                                                     \
    X(bgeu, a >= b)

#define DEF_REG_REF(n, e)                                                                                              \
    static uint64_t ref_##n(uint64_t a, uint64_t b) {                                                                  \
        return (uint64_t) (e);                                                                                         \
    }
CP_REG_OPS(DEF_REG_REF)
#define DEF_BR_REF(n, e)                                                                                               \
    static int bref_##n(uint64_t a, uint64_t b) {                                                                      \
        return (e) ? 1 : 0;                                                                                            \
    }
CP_BR_OPS(DEF_BR_REF)

static const struct {
    const cp_stencil_t *const (*tab)[NSLOTS][NSLOTS];
    uint64_t (*ref)(uint64_t, uint64_t);
} reg_ops[] = {
#define REG_ENT(n, e) {cp_##n##_table, ref_##n},
    CP_REG_OPS(REG_ENT)};
static const struct {
    const cp_stencil_t *const (*tab)[NSLOTS];
    int (*ref)(uint64_t, uint64_t);
} br_ops[] = {
#define BR_ENT(n, e) {cp_##n##_table, bref_##n},
    CP_BR_OPS(BR_ENT)};
#define NREG_OPS ((int) (sizeof(reg_ops) / sizeof(reg_ops[0])))
#define NBR_OPS ((int) (sizeof(br_ops) / sizeof(br_ops[0])))

struct op {
    int kind; /* 0 li, 1 reg op */
    int op;   /* index into reg_ops / imm_ops */
    int d, s1, s2;
    uint64_t imm;
};

static void reference(const struct op *ops, int n, uint64_t slot[NSLOTS_PAD]) {
    for (int i = 0; i < n; ++i) {
        const struct op *o = &ops[i];
        switch (o->kind) {
            case 0:
                slot[o->d] = o->imm;
                break;
            case 1:
                slot[o->d] = reg_ops[o->op].ref(slot[o->s1], slot[o->s2]);
                break;

            default:
                abort();
        }
    }
}

static uint64_t out[NPARAMS];

/* Fixed pinned-role values threaded through every run; programs must pass
 * them through untouched (the exit-stub test overrides pc and cd). */
#define SAV 0x4444000044440000ull
#define PCV 0x1111000011110000ull
#define CDV 0x0000000000123456ull
#define FETCHV 0x2222000022220000ull
#define TCCV 0x3333000033330000ull

__attribute__((noinline)) static void call_chain(cp_entry_t entry, const uint64_t g[NSLOTS_PAD]) {
#if defined(__x86_64__) && NSLOTS == 6
    entry(SAV, g[0], PCV, CDV, FETCHV, g[1], g[2], g[3], g[4], g[5], TCCV, g[6], g[7], g[8], g[9], g[10], g[11], g[12],
        g[13], g[14], g[15]);
#elif defined(__x86_64__) && NSLOTS == 7
    entry(SAV, g[0], PCV, CDV, FETCHV, g[1], g[2], g[3], g[4], g[5], g[6], TCCV, g[7], g[8], g[9], g[10], g[11], g[12],
        g[13], g[14], g[15]);
#elif defined(__x86_64__)
#error "extend call_chain for this x86-64 CP_NSLOTS"
#else
    entry(SAV, g[0], g[1], PCV, CDV, FETCHV, g[2], TCCV, g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12],
        g[13], g[14], g[15]);
#endif
}

static int check_passthrough(uint64_t pc_want, uint64_t cd_want) {
    if (out[POS_SA] != SAV || out[POS_PC] != pc_want || out[POS_CD] != cd_want || out[POS_FETCH] != FETCHV ||
        out[POS_TCC] != TCCV) {
        fprintf(stderr, "pinned roles: pc %016" PRIx64 " cd %016" PRIx64 " fetch %016" PRIx64 " tcc %016" PRIx64 "\n",
            out[POS_PC], out[POS_CD], out[POS_FETCH], out[POS_TCC]);
        return 1;
    }
    return 0;
}

#if defined(__x86_64__)
/* A full outer-chain call establishes the stack roster, then a real
 * five-argument interpreter-shaped function tail-branches into copied code.
 * Writing the last cache slot proves that the stack half survives the branch. */
static int test_x86_short_entry(void) {
    heap.curr = 0;
    cp_heap_unprotect(&heap);
    const uint64_t value = 0xfedcba9876543210ull;
    const uint64_t li_imm[2] = {value, 0};
    uint8_t *none[2] = {NULL, NULL};
    x86_short_entry_target = cp_emit(&heap, cp_li_table[NSLOTS - 1], li_imm, none);
    const uint64_t exit_imm[2] = {(uint64_t) out, 0};
    cp_emit(&heap, &cp_s_cp_store_exit, exit_imm, none);
    cp_heap_protect_flush(&heap);

    uint64_t init[NSLOTS_PAD] = {0};
    memset(out, 0xaa, sizeof(out));
    call_chain((cp_entry_t) x86_short_entry, init);
    if (out[SLOT_POS[NSLOTS - 1]] != value) {
        fprintf(stderr, "x86 short entry lost stack cache slot: got %016" PRIx64 " want %016" PRIx64 "\n",
            out[SLOT_POS[NSLOTS - 1]], value);
        return 1;
    }
    return check_passthrough(PCV, CDV);
}
#endif

static int run_program(const struct op *ops, int n, const uint64_t init[NSLOTS_PAD]) {
    heap.curr = 0;
    cp_heap_unprotect(&heap);
    uint8_t *entry = NULL;
    for (int i = 0; i < n; ++i) {
        const struct op *o = &ops[i];
        uint64_t imm[2] = {o->imm, 0};
        uint8_t *cont[2] = {NULL, NULL};
        const cp_stencil_t *st = NULL;
        switch (o->kind) {
            case 0:
                st = cp_li_table[o->d];
                break;
            case 1:
                st = reg_ops[o->op].tab[o->d][o->s1][o->s2];
                break;

            default:
                abort();
        }
        uint8_t *at = cp_emit(&heap, st, imm, cont);
        if (entry == NULL) {
            entry = at;
        }
    }
    uint64_t imm[2] = {(uint64_t) out, 0};
    uint8_t *cont[2] = {NULL, NULL};
    uint8_t *at = cp_emit(&heap, &cp_s_cp_store_exit, imm, cont);
    if (entry == NULL) {
        entry = at;
    }
    cp_heap_protect_flush(&heap);

    if (getenv("CP_DUMP") != NULL) {
        FILE *df = fopen(getenv("CP_DUMP"), "wb");
        if (df == NULL) {
            perror("fopen CP_DUMP");
            exit(1);
        }
        fwrite(heap.base, 1, heap.curr, df);
        fclose(df);
        fprintf(stderr, "dumped %zu bytes, entry at +%zu, exiting\n", heap.curr, (size_t) (entry - heap.base));
        exit(0);
    }

    memset(out, 0xaa, sizeof(out));
    call_chain((cp_entry_t) entry, init);

    uint64_t ref[NSLOTS_PAD];
    memcpy(ref, init, sizeof(ref));
    reference(ops, n, ref);
    for (int i = 0; i < NSLOTS; ++i) {
        if (out[SLOT_POS[i]] != ref[i]) {
            fprintf(stderr, "slot %d: got %016" PRIx64 " want %016" PRIx64 "\n", i, out[SLOT_POS[i]], ref[i]);
            return 1;
        }
    }
    return check_passthrough(PCV, CDV);
}

static int run_addi_stencil(int word, int d, int s, int64_t simm, const uint64_t init[NSLOTS_PAD]) {
    heap.curr = 0;
    cp_heap_unprotect(&heap);
    uint64_t imm[2] = {(uint64_t) simm, 0};
    uint8_t *cont[2] = {NULL, NULL};
    const cp_stencil_t *st = word ? cp_addiw_table[d][s] : cp_addi_table[d][s];
    uint8_t *entry = cp_emit(&heap, st, imm, cont);
    uint64_t exit_imm[2] = {(uint64_t) out, 0};
    cp_emit(&heap, &cp_s_cp_store_exit, exit_imm, cont);
    cp_heap_protect_flush(&heap);

    memset(out, 0xaa, sizeof(out));
    call_chain((cp_entry_t) entry, init);
    uint64_t want;
    if (word) {
        uint32_t result = (uint32_t) init[s] + (uint32_t) simm;
        want = (uint64_t) (int64_t) (int32_t) result;
    } else {
        want = init[s] + (uint64_t) simm;
    }
    if (out[SLOT_POS[d]] != want) {
        fprintf(stderr, "addi%s d=%d s=%d imm=%" PRId64 ": got %016" PRIx64 " want %016" PRIx64 "\n", word ? "w" : "",
            d, s, simm, out[SLOT_POS[d]], want);
        return 1;
    }
    return check_passthrough(PCV, CDV);
}

/* Guard test: emit beq with the taken side landing in one exit stub and the
 * fallthrough side in another, run both outcomes, check the side taken. */
static uint64_t out_b[NPARAMS];
static int run_guard_op(int b, int s1, int s2, const uint64_t init[NSLOTS_PAD]) {
    heap.curr = 0;
    cp_heap_unprotect(&heap);
    /* Exit stubs first so the guard can point at them. */
    uint64_t imm_a[2] = {(uint64_t) out, 0};
    uint64_t imm_b[2] = {(uint64_t) out_b, 0};
    uint8_t *none[2] = {NULL, NULL};
    uint8_t *stub_a = cp_emit(&heap, &cp_s_cp_store_exit, imm_a, none);
    uint8_t *stub_b = cp_emit(&heap, &cp_s_cp_store_exit, imm_b, none);
    uint64_t imm[2] = {0, 0};
    uint8_t *cont[2] = {stub_a, stub_b};
    uint8_t *guard = cp_emit(&heap, br_ops[b].tab[s1][s2], imm, cont);
    cp_heap_protect_flush(&heap);

    memset(out, 0xaa, sizeof(out));
    memset(out_b, 0x55, sizeof(out_b));
    call_chain((cp_entry_t) guard, init);

    int taken = br_ops[b].ref(init[s1], init[s2]);
    const uint64_t *hit = taken ? out : out_b;
    for (int i = 0; i < NSLOTS; ++i) {
        if (hit[SLOT_POS[i]] != init[i]) {
            fprintf(stderr, "guard s1=%d s2=%d taken=%d slot %d: got %016" PRIx64 " want %016" PRIx64 "\n", s1, s2,
                taken, i, hit[SLOT_POS[i]], init[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (cp_heap_init(&heap, HEAP_SIZE) != 0) {
        perror("cp_heap_init");
        return 1;
    }

    int failures = 0;

#if defined(__x86_64__)
    failures += test_x86_fma_stencil_selection();
    failures += test_x86_short_entry();
#endif

    /* Fixed program covering every op kind and the elision path. */
    {
        struct op prog[] = {
            {0, 0, 3, 0, 0, 42},
            {0, 0, NSLOTS - 1, 0, 0, 100},
            {1, 0, 2, 3, NSLOTS - 1, 0},
            {1, 0, 0, 2, 3, 0},
            {1, 0, 1, NSLOTS > 6 ? 5 : 4, 0, 0},
        };
        uint64_t init[NSLOTS_PAD] = {1, 2, 3, 4, 5, 6, 7};
        failures += run_program(prog, sizeof(prog) / sizeof(prog[0]), init);
        fprintf(stderr, "fixed program done, failures %d\n", failures);
    }

    {
        static const int64_t immediates[] = {-2048, -1, 0, 1, 2047};
        uint64_t init[NSLOTS_PAD];
        for (int i = 0; i < NSLOTS; ++i) {
            init[i] = 0x8000000000000000ull + (uint64_t) i * 0x111111111111111ull;
        }
        for (int word = 0; word < 2 && failures == 0; ++word) {
            for (int d = 0; d < NSLOTS && failures == 0; ++d) {
                for (int s = 0; s < NSLOTS && failures == 0; ++s) {
                    for (size_t i = 0; i < sizeof(immediates) / sizeof(immediates[0]); ++i) {
                        failures += run_addi_stencil(word, d, s, immediates[i], init);
                    }
                }
            }
        }
        fprintf(stderr, "direct add-immediate stencils done, failures %d\n", failures);
    }

    /* Random programs over random slots, immediates, and repeated operands. */
    for (int trial = 0; trial < 500 && failures == 0; ++trial) {
        if (trial % 100 == 0) {
            fprintf(stderr, "random trial %d\n", trial);
        }
        struct op prog[40];
        int n = 8 + (int) (rng() % 32);
        for (int i = 0; i < n; ++i) {
            struct op *o = &prog[i];
            o->d = (int) (rng() % NSLOTS);
            o->s1 = (int) (rng() % NSLOTS);
            o->s2 = (int) (rng() % NSLOTS);
            o->imm = pick_imm();
            switch (rng() % 4) {
                case 0:
                    o->kind = 0;
                    break;
                case 1:
                    o->kind = 1;
                    o->op = (int) (rng() % NREG_OPS);
                    break;
                default:
                    /* Immediates route through li + reg-reg at formation;
                     * mirror that: li a scratch slot, then a reg op on it. */
                    o->kind = 0;
                    if (i + 1 < n) {
                        struct op *u = &prog[i + 1];
                        u->kind = 1;
                        u->op = (int) (rng() % NREG_OPS);
                        u->d = (int) (rng() % NSLOTS);
                        u->s1 = (int) (rng() % NSLOTS);
                        u->s2 = o->d;
                        ++i;
                    }
                    break;
            }
        }
        uint64_t init[NSLOTS_PAD];
        for (int i = 0; i < NSLOTS; ++i) {
            init[i] = pick_imm();
        }
        failures += run_program(prog, n, init);
    }

    /* Guard outcomes: equal, unequal, and same-slot (always taken). */
    {
        fprintf(stderr, "random trials done, failures %d\n", failures);
        uint64_t init[NSLOTS_PAD] = {5, 5, 6, 7, 8, 9, 10};
        for (int b = 0; b < NBR_OPS; ++b) {
            failures += run_guard_op(b, 0, 1, init); /* equal slots */
            failures += run_guard_op(b, 1, 2, init); /* unequal slots */
            failures += run_guard_op(b, 3, 3, init); /* same slot */
        }
        uint64_t signs[NSLOTS_PAD] = {0x8000000000000000ull, 1, (uint64_t) -1, 0, 5, 0x7fffffffffffffffull, 2};
        for (int b = 0; b < NBR_OPS; ++b) {
            for (int k = 0; k < NSLOTS; ++k) {
                failures += run_guard_op(b, k, (k + 1) % NSLOTS, signs);
            }
        }
    }

    if (failures != 0) {
        fprintf(stderr, "cp-stencils-test: FAILED\n");
        return 1;
    }
    printf("cp-stencils-test: PASSED\n");
    return 0;
}
