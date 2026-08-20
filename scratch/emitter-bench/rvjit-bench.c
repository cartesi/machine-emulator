/* Emission-rate microbenchmark for RVVM's rvjit emitter.
 *
 * Emits N independent traces of the same 16-guest-instruction integer mix
 * (ALU + guard branch + trace-ending branch), each finalized into the code
 * heap with the same linkage path the emulator uses (same-page pending links
 * patched as successors compile). Reports ns per trace, ns per guest
 * instruction, and emitted-code throughput.
 *
 * Build against the prebuilt release.darwin.arm64 objects; see build.sh.
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "rvjit.h"
#include "rvjit_emit.h"

#define N_TRACES 20000
#define INSNS_PER_TRACE 16

/* RISC-V register numbers */
#define ZERO 0
#define T0 5
#define T1 6
#define T2 7
#define S0 8
#define A2 12
#define A3 13
#define A4 14
#define A5 15
#define A6 16
#define A7 17

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int main(void)
{
    static rvjit_block_t ctx;
    if (!rvjit_ctx_init(&ctx, 64u << 20)) {
        fprintf(stderr, "rvjit_ctx_init failed\n");
        return 1;
    }
    rvjit_set_rv64(&ctx, true);

    uint64_t emitted_bytes = 0;
    uint64_t traces = 0;
    uint64_t flushes = 0;

    uint64_t t0 = now_ns();
    for (uint32_t i = 0; i < N_TRACES; ++i) {
        rvjit_block_init(&ctx);
        ctx.virt_pc = 0x80000000ull + (uint64_t)i * 64;
        ctx.phys_pc = 0x80000000ull + (uint64_t)i * 64;
        ctx.pc_off = 0;

        rvjit64_li(&ctx, A5, 0x12345);
        rvjit64_addi(&ctx, A5, A5, 1);
        rvjit64_add(&ctx, A4, A4, A3);
        rvjit64_xor(&ctx, A6, A4, A5);
        rvjit64_sltu(&ctx, A7, A4, A5);
        rvjit64_andi(&ctx, T0, A6, 0xff);
        rvjit64_srli(&ctx, T1, A4, 3);
        rvjit64_sub(&ctx, A3, A3, T0);
        rvjit64_slli(&ctx, T2, A5, 2);
        rvjit64_or(&ctx, A4, A4, T1);
        rvjit64_addiw(&ctx, A2, A2, -1);
        rvjit64_mul(&ctx, S0, A4, A5);
        rvjit64_beq(&ctx, A2, ZERO); /* guard exit */
        rvjit64_addi(&ctx, A5, A5, 8);
        rvjit64_and(&ctx, A6, A6, A4);
        rvjit64_bne(&ctx, A2, A5); /* trace-ending guard */

        ctx.pc_off = 64; /* successor is the next trace head, same page */
        ctx.linkage = LINKAGE_JMP;

        if (rvjit_block_finalize(&ctx) == NULL) {
            rvjit_flush_cache(&ctx);
            ++flushes;
            continue;
        }
        emitted_bytes += ctx.size;
        ++traces;
    }
    uint64_t elapsed = now_ns() - t0;

    printf("rvjit: traces %llu guest-insns %llu emitted %llu bytes flushes %llu\n",
        (unsigned long long)traces, (unsigned long long)(traces * INSNS_PER_TRACE),
        (unsigned long long)emitted_bytes, (unsigned long long)flushes);
    printf("rvjit: total %.3f ms, %.0f ns/trace, %.1f ns/guest-insn, %.1f MB/s\n",
        elapsed / 1e6, (double)elapsed / traces, (double)elapsed / (traces * INSNS_PER_TRACE),
        emitted_bytes * 1000.0 / elapsed);
    return 0;
}
