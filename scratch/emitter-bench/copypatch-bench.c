/* Emission-rate bound for a copy-and-patch emitter on Apple Silicon.
 *
 * Models one trace as 16 stencil copies (one per guest instruction, sized to
 * RVVM's measured 27 bytes/guest-insn body average) plus 12 scalar patches
 * and a per-trace icache flush, written into a MAP_JIT heap under
 * pthread_jit_write_protect_np toggles, with a hashmap-free bump allocator.
 * This is the ceiling the stencil emitter approaches, not a simulation of
 * stencil selection.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>

#define N_TRACES 20000
#define INSNS_PER_TRACE 16
#define STENCIL_BYTES 28   /* per guest instruction, rounded to 4 */
#define PATCHES_PER_TRACE 12

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int main(void)
{
    size_t heap_size = 64u << 20;
    uint8_t *heap = mmap(NULL, heap_size, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (heap == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* One fake stencil per "opcode", filled with distinct bytes. */
    static uint8_t stencils[32][STENCIL_BYTES];
    for (int i = 0; i < 32; ++i) {
        memset(stencils[i], 0x90 + i, STENCIL_BYTES);
    }

    uint64_t emitted_bytes = 0;
    size_t curr = 0;

    uint64_t t0 = now_ns();
    for (uint32_t i = 0; i < N_TRACES; ++i) {
        size_t trace_bytes = INSNS_PER_TRACE * STENCIL_BYTES;
        if (curr + trace_bytes > heap_size) {
            curr = 0; /* flush-all analog */
        }
        uint8_t *dst = heap + curr;
        pthread_jit_write_protect_np(0);
        for (int k = 0; k < INSNS_PER_TRACE; ++k) {
            memcpy(dst + k * STENCIL_BYTES, stencils[(i + k) & 31], STENCIL_BYTES);
        }
        for (int p = 0; p < PATCHES_PER_TRACE; ++p) {
            uint32_t *hole = (uint32_t *)(dst + p * (trace_bytes / PATCHES_PER_TRACE));
            *hole = (*hole & 0xff00000fu) | ((i + p) << 4); /* masked field patch */
        }
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(dst, trace_bytes);
        curr += trace_bytes;
        emitted_bytes += trace_bytes;
    }
    uint64_t elapsed = now_ns() - t0;

    printf("copypatch-bound: traces %u guest-insns %u emitted %llu bytes\n", N_TRACES,
        N_TRACES * INSNS_PER_TRACE, (unsigned long long)emitted_bytes);
    printf("copypatch-bound: total %.3f ms, %.0f ns/trace, %.2f ns/guest-insn, %.0f MB/s\n",
        elapsed / 1e6, (double)elapsed / N_TRACES,
        (double)elapsed / ((uint64_t)N_TRACES * INSNS_PER_TRACE), emitted_bytes * 1000.0 / elapsed);
    return 0;
}
