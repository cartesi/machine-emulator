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

#if defined(__linux__)
#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif

#include "cp-stencils-tables.h"

#define NSLOTS 8
#define HEAP_SIZE (16u << 20)

typedef __attribute__((preserve_none)) void (*cp_entry_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t);

static uint8_t *heap;
static size_t heap_curr;

/* Apple Silicon toggles the thread's MAP_JIT write protection. Elsewhere the
 * heap flips between RW and RX with mprotect: plain RWX with no barrier is
 * not enough under binary translation (Rosetta caches translations of
 * executed pages and needs the protection change to invalidate them). */
static void jit_unprotect(void)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(0);
#else
    if (mprotect(heap, HEAP_SIZE, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect rw");
        exit(1);
    }
#endif
}

static void jit_protect_flush(const void *p, size_t n)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate((void *) (uintptr_t) p, n);
#else
    (void) p;
    (void) n;
    if (mprotect(heap, HEAP_SIZE, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect rx");
        exit(1);
    }
    __builtin___clear_cache((char *) heap, (char *) heap + HEAP_SIZE);
#if defined(__linux__)
    /* The Linux JIT contract for cross-modifying code. Native x86 forgives
     * skipping it, binary translation (Rosetta) and AArch64 do not. */
    syscall(__NR_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
#endif
#endif
}

/* One emission: copy a stencil at heap_curr, apply patches, elide a trailing
 * fallthrough branch to `next` when possible. imm[2] fill the value holes,
 * cont[2] the continuations; cont[0]==NULL means "falls through to the next
 * emission" and is resolved after the copy. Returns the stencil address. */
static uint8_t *emit(const cp_stencil_t *st, const uint64_t imm[2], uint8_t *cont[2])
{
    uint8_t *dst = heap + heap_curr;
    uint32_t size = st->size;

    /* Fallthrough elision: a trailing branch to continuation 0 aimed at the
     * next address is dropped (4 bytes for AArch64 B, 5 for x86-64 e9+rel32
     * whose patch field sits at size-4 with the opcode byte before it). */
    int elide = 0;
    if (st->npatches > 0 && cont[0] == NULL) {
        const cp_patch_t *last = &st->patches[st->npatches - 1];
        if (last->kind == CP_P_JUMP26 && last->offset == size - 4 && last->ordinal == 0) {
            elide = 1;
            size -= 4;
        } else if (last->kind == CP_P_JMPREL32 && last->offset == size - 4 && last->ordinal == 0 &&
            st->code[size - 5] == 0xe9) {
            elide = 1;
            size -= 5;
        }
    }
    memcpy(dst, st->code, size);

    for (uint16_t i = 0; i < st->npatches - (uint16_t) elide; ++i) {
        const cp_patch_t *p = &st->patches[i];
        uint8_t *site = dst + p->offset;
        uint8_t *target = cont[p->ordinal];
        if (target == NULL) { /* non-trailing fallthrough: explicit branch */
            target = dst + size;
        }
        switch (p->kind) {
            case CP_P_JUMP26: {
                int64_t delta = (int64_t) (target - site);
                uint32_t insn = 0x14000000u | (((uint64_t) delta >> 2) & 0x03ffffffu);
                memcpy(site, &insn, 4);
                break;
            }
            case CP_P_JMPREL32: {
                int32_t rel = (int32_t) (target + p->addend - site);
                memcpy(site, &rel, 4);
                break;
            }
            case CP_P_ABS64: {
                uint64_t value = imm[p->ordinal] + (uint64_t) p->addend;
                memcpy(site, &value, 8);
                break;
            }
            default: { /* CP_P_G0..G3: 16-bit field at bits 5-20 */
                unsigned shift = 16u * (p->kind - CP_P_G0);
                uint32_t field = (uint32_t) ((imm[p->ordinal] >> shift) & 0xffffu);
                uint32_t insn;
                memcpy(&insn, site, 4);
                insn = (insn & ~(0xffffu << 5)) | (field << 5);
                memcpy(site, &insn, 4);
                break;
            }
        }
    }
    heap_curr += size;
    return dst;
}

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

static uint64_t out[NSLOTS];

static int run_program(const struct op *ops, int n, const uint64_t init[NSLOTS])
{
    heap_curr = 0;
    jit_unprotect();
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
        uint8_t *at = emit(st, imm, cont);
        if (entry == NULL) {
            entry = at;
        }
    }
    uint64_t imm[2] = {(uint64_t) out, 0};
    uint8_t *cont[2] = {NULL, NULL};
    uint8_t *at = emit(&cp_s_cp_store_exit, imm, cont);
    if (entry == NULL) {
        entry = at;
    }
    jit_protect_flush(heap, heap_curr);

    if (getenv("CP_DUMP") != NULL) {
        FILE *df = fopen(getenv("CP_DUMP"), "wb");
        if (df == NULL) {
            perror("fopen CP_DUMP");
            exit(1);
        }
        fwrite(heap, 1, heap_curr, df);
        fclose(df);
        fprintf(stderr, "dumped %zu bytes, entry at +%zu, exiting\n", heap_curr, (size_t) (entry - heap));
        exit(0);
    }

    memset(out, 0xaa, sizeof(out));
    ((cp_entry_t) entry)(init[0], init[1], init[2], init[3], init[4], init[5], init[6], init[7]);

    uint64_t ref[NSLOTS];
    memcpy(ref, init, sizeof(ref));
    reference(ops, n, ref);
    for (int i = 0; i < NSLOTS; ++i) {
        if (out[i] != ref[i]) {
            fprintf(stderr, "slot %d: got %016" PRIx64 " want %016" PRIx64 "\n", i, out[i], ref[i]);
            return 1;
        }
    }
    return 0;
}

/* Guard test: emit beq with the taken side landing in one exit stub and the
 * fallthrough side in another, run both outcomes, check the side taken. */
static uint64_t out_b[NSLOTS];
static int run_guard(int s1, int s2, const uint64_t init[NSLOTS])
{
    heap_curr = 0;
    jit_unprotect();
    /* Exit stubs first so the guard can point at them. */
    uint64_t imm_a[2] = {(uint64_t) out, 0};
    uint64_t imm_b[2] = {(uint64_t) out_b, 0};
    uint8_t *none[2] = {NULL, NULL};
    uint8_t *stub_a = emit(&cp_s_cp_store_exit, imm_a, none);
    uint8_t *stub_b = emit(&cp_s_cp_store_exit, imm_b, none);
    uint64_t imm[2] = {0, 0};
    uint8_t *cont[2] = {stub_a, stub_b};
    uint8_t *guard = emit(cp_beq_table[s1][s2], imm, cont);
    jit_protect_flush(heap, heap_curr);

    memset(out, 0xaa, sizeof(out));
    memset(out_b, 0x55, sizeof(out_b));
    ((cp_entry_t) guard)(init[0], init[1], init[2], init[3], init[4], init[5], init[6], init[7]);

    int taken = init[s1] == init[s2];
    const uint64_t *hit = taken ? out : out_b;
    for (int i = 0; i < NSLOTS; ++i) {
        if (hit[i] != init[i]) {
            fprintf(stderr, "guard s1=%d s2=%d taken=%d slot %d: got %016" PRIx64 " want %016" PRIx64 "\n", s1, s2,
                taken, i, hit[i], init[i]);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
#if defined(__APPLE__)
    heap = mmap(NULL, HEAP_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    heap = mmap(NULL, HEAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (heap == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
#if defined(__linux__)
    syscall(__NR_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
#endif

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
