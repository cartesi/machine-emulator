/* Copy-and-patch emitter core (see copy-patch-rvvm.md): a bump-allocated
 * executable heap and the stencil copy/patch/elide primitive, shared by the
 * stencil execution test and the backend translation unit.
 *
 * Callers hold the heap writable across a whole emission episode
 * (cp_heap_unprotect), emit stencils, then seal and publish once
 * (cp_heap_protect_flush). Continuation 0 is the fallthrough successor: a
 * NULL entry in the continuation array means "the next emitted byte", and a
 * trailing branch aimed there is elided.
 */

#ifndef CP_EMIT_H
#define CP_EMIT_H

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif
#if defined(__linux__)
#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "cp-stencils-tables.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *base;
    size_t size;
    size_t curr;
} cp_heap_t;

/* Returns 0 on success. The heap starts protected (RX). */
static inline int cp_heap_init(cp_heap_t *h, size_t size)
{
#if defined(__APPLE__)
    h->base = (uint8_t *) mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    h->base = (uint8_t *) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (h->base == MAP_FAILED) {
        return -1;
    }
    h->size = size;
    h->curr = 0;
#if defined(__linux__)
    /* Register for the cross-modifying-code barrier used at publish. */
    syscall(__NR_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
#endif
    return 0;
}

static inline void cp_heap_free(cp_heap_t *h)
{
    if (h->base != NULL) {
        munmap(h->base, h->size);
        h->base = NULL;
    }
}

static inline void cp_heap_unprotect(cp_heap_t *h)
{
#if defined(__APPLE__)
    (void) h;
    pthread_jit_write_protect_np(0);
#else
    mprotect(h->base, h->size, PROT_READ | PROT_WRITE);
#endif
}

static inline void cp_heap_protect_flush(cp_heap_t *h)
{
#if defined(__APPLE__)
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(h->base, h->curr);
#else
    mprotect(h->base, h->size, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *) h->base, (char *) h->base + h->size);
#if defined(__linux__)
    syscall(__NR_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
#endif
#endif
}

static inline size_t cp_heap_remaining(const cp_heap_t *h)
{
    return h->size - h->curr;
}

/* Copies one stencil at the heap cursor and applies its patches. imm[2] fill
 * the value holes, cont[2] the continuations (NULL continuation 0 means
 * fallthrough, elided when the branch is trailing). Returns the stencil
 * address, or NULL when the heap is full (caller flushes all and retries).
 */
static inline uint8_t *cp_emit(cp_heap_t *h, const cp_stencil_t *st, const uint64_t imm[2], uint8_t *const cont[2])
{
    uint8_t *dst = h->base + h->curr;
    uint32_t size = st->size;

    if (h->curr + size > h->size) {
        return NULL;
    }

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
                unsigned shift = 16u * (unsigned) (p->kind - CP_P_G0);
                uint32_t field = (uint32_t) ((imm[p->ordinal] >> shift) & 0xffffu);
                uint32_t insn;
                memcpy(&insn, site, 4);
                insn = (insn & ~(0xffffu << 5)) | (field << 5);
                memcpy(site, &insn, 4);
                break;
            }
        }
    }
    h->curr += size;
    return dst;
}

/* Rewrites a previously emitted trailing branch site to a new target: the
 * link patch applied when a pending successor compiles. The heap must be
 * writable. */
static inline void cp_patch_branch(uint8_t *site, uint8_t kind, int32_t addend, uint8_t *target)
{
    if (kind == CP_P_JUMP26) {
        int64_t delta = (int64_t) (target - site);
        uint32_t insn = 0x14000000u | (((uint64_t) delta >> 2) & 0x03ffffffu);
        memcpy(site, &insn, 4);
    } else {
        int32_t rel = (int32_t) (target + addend - site);
        memcpy(site, &rel, 4);
    }
}

#ifdef __cplusplus
}
#endif

#endif
