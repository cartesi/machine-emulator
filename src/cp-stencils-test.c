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

#define NSLOTS 8
#define NPARAMS 12 /* r0 r1 r2 pc cd fetch r3 tcc r4 r5 r6 r7 */
#define HEAP_SIZE (16u << 20)

/* Parameter order of the stencil contract; guest slot k sits at param
 * SLOT_POS[k], the pinned roles at positions 3, 4, 5, 7. */
static const int SLOT_POS[NSLOTS] = {0, 1, 2, 6, 8, 9, 10, 11};
#define POS_PC 3
#define POS_CD 4
#define POS_FETCH 5
#define POS_TCC 7

typedef __attribute__((preserve_none)) void (*cp_entry_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static cp_heap_t heap;

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* Adversarial constants mixed into random choices. */
static uint64_t pick_imm(void)
{
    static const uint64_t edge[] = {0, 1, 0xffffffffffffffffull, 0x8000000000000000ull, 0x7fffffffffffffffull,
        0xffffffffull, 0x100000000ull, 0xfffeull, 0x10000ull};
    if ((rng() & 3) == 0) {
        return edge[rng() % (sizeof(edge) / sizeof(edge[0]))];
    }
    return rng();
}

struct op {
    int kind; /* 0 li, 1 add, 2 addi, 3 ld */
    int d, s1, s2;
    uint64_t imm;
};

static uint64_t mem_pool[64];

static void reference(const struct op *ops, int n, uint64_t slot[NSLOTS])
{
    for (int i = 0; i < n; ++i) {
        const struct op *o = &ops[i];
        switch (o->kind) {
            case 0:
                slot[o->d] = o->imm;
                break;
            case 1:
                slot[o->d] = slot[o->s1] + slot[o->s2];
                break;
            case 2:
                slot[o->d] = slot[o->s1] + o->imm;
                break;
            case 3:
                slot[o->d] = *(const uint64_t *) (slot[o->s1] + o->imm);
                break;
            default:
                abort();
        }
    }
}

static uint64_t out[NPARAMS];

/* Fixed pinned-role values threaded through every run; programs must pass
 * them through untouched (the exit-stub test overrides pc and cd). */
#define PCV 0x1111000011110000ull
#define CDV 0x0000000000123456ull
#define FETCHV 0x2222000022220000ull
#define TCCV 0x3333000033330000ull

static void call_chain(cp_entry_t entry, const uint64_t g[NSLOTS])
{
    entry(g[0], g[1], g[2], PCV, CDV, FETCHV, g[3], TCCV, g[4], g[5], g[6], g[7]);
}

static int check_passthrough(uint64_t pc_want, uint64_t cd_want)
{
    if (out[POS_PC] != pc_want || out[POS_CD] != cd_want || out[POS_FETCH] != FETCHV || out[POS_TCC] != TCCV) {
        fprintf(stderr, "pinned roles: pc %016" PRIx64 " cd %016" PRIx64 " fetch %016" PRIx64 " tcc %016" PRIx64 "\n",
            out[POS_PC], out[POS_CD], out[POS_FETCH], out[POS_TCC]);
        return 1;
    }
    return 0;
}

static int run_program(const struct op *ops, int n, const uint64_t init[NSLOTS])
{
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
                st = cp_add_table[o->d][o->s1][o->s2];
                break;
            case 2:
                st = cp_addi_table[o->d][o->s1];
                break;
            case 3:
                st = cp_ld_table[o->d][o->s1];
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

    uint64_t ref[NSLOTS];
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

/* Guard test: emit beq with the taken side landing in one exit stub and the
 * fallthrough side in another, run both outcomes, check the side taken. */
static uint64_t out_b[NPARAMS];
static int run_guard(int s1, int s2, const uint64_t init[NSLOTS])
{
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
    uint8_t *guard = cp_emit(&heap, cp_beq_table[s1][s2], imm, cont);
    cp_heap_protect_flush(&heap);

    memset(out, 0xaa, sizeof(out));
    memset(out_b, 0x55, sizeof(out_b));
    call_chain((cp_entry_t) guard, init);

    int taken = init[s1] == init[s2];
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

int main(void)
{
    if (cp_heap_init(&heap, HEAP_SIZE) != 0) {
        perror("cp_heap_init");
        return 1;
    }

    int failures = 0;

    /* Fixed program covering every op kind and the elision path. */
    {
        struct op prog[] = {
            {0, 3, 0, 0, 42},
            {2, 2, 3, 0, 100},
            {1, 0, 2, 3, 0},
            {0, 4, 0, 0, (uint64_t) mem_pool},
            {3, 5, 4, 0, 8},
            {1, 7, 5, 0, 0},
        };
        for (unsigned i = 0; i < 64; ++i) {
            mem_pool[i] = 0x1111111111111111ull * (i + 1);
        }
        uint64_t init[NSLOTS] = {1, 2, 3, 4, 5, 6, 7, 8};
        failures += run_program(prog, sizeof(prog) / sizeof(prog[0]), init);
        fprintf(stderr, "fixed program done, failures %d\n", failures);
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
                    break;
                case 2:
                    o->kind = 2;
                    break;
                default:
                    o->kind = 3;
                    /* Load target must be a valid address: base slot gets the
                     * pool via a preceding li; keep it simple by rewriting
                     * this op into li base; ld d, base. */
                    if (i + 1 < n) {
                        o->kind = 0;
                        o->imm = (uint64_t) mem_pool;
                        struct op *l = &prog[i + 1];
                        l->kind = 3;
                        l->d = (int) (rng() % NSLOTS);
                        l->s1 = o->d;
                        l->imm = 8 * (rng() % 32);
                        ++i;
                    } else {
                        o->kind = 0;
                    }
                    break;
            }
        }
        uint64_t init[NSLOTS];
        for (int i = 0; i < NSLOTS; ++i) {
            init[i] = pick_imm();
        }
        failures += run_program(prog, n, init);
    }

    /* Guard outcomes: equal, unequal, and same-slot (always taken). */
    {
        fprintf(stderr, "random trials done, failures %d\n", failures);
        uint64_t init[NSLOTS] = {5, 5, 6, 7, 8, 9, 10, 11};
        failures += run_guard(0, 1, init); /* taken */
        failures += run_guard(1, 2, init); /* not taken */
        failures += run_guard(3, 3, init); /* same slot, degenerate always-taken */
    }

    if (failures != 0) {
        fprintf(stderr, "cp-stencils-test: FAILED\n");
        return 1;
    }
    printf("cp-stencils-test: PASSED\n");
    return 0;
}
