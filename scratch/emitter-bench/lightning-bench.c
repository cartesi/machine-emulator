/* Emission-rate microbenchmark for GNU lightning, mirroring the real
 * backend's per-trace pattern: one jit_state per trace, jit_prolog +
 * jit_tramp(0) (frameless continuation), an entry guard, guest registers
 * loaded from a register file at entry and stored back at exit, the same
 * 16-guest-instruction integer mix as rvjit-bench.c, and jit_emit into
 * executable memory. States are kept alive during timing (as the backend
 * keeps trace owners) and destroyed afterwards.
 *
 * Build against the bundled lightning; see build.sh.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <lightning.h>

#define N_TRACES 20000
#define INSNS_PER_TRACE 16

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static uint64_t regfile[32];

int main(void)
{
    init_jit(NULL);

    static jit_state_t *states[N_TRACES];
    uint64_t emitted_bytes = 0;
    uint64_t traces = 0;

    /* Guest registers in host registers, as the backend allocates them. */
    const jit_gpr_t a2 = JIT_R1;
    const jit_gpr_t a3 = JIT_R2;
    const jit_gpr_t a4 = JIT_R3;
    const jit_gpr_t a5 = JIT_R4;
    const jit_gpr_t a6 = JIT_R5;
    const jit_gpr_t a7 = JIT_V0;
    const jit_gpr_t t0 = JIT_V2;
    const jit_gpr_t t1 = JIT_V3;
    const jit_gpr_t t2 = JIT_R0;
    const jit_gpr_t s0 = JIT_V7;

    uint64_t t_start = now_ns();
    for (uint32_t i = 0; i < N_TRACES; ++i) {
        jit_state_t *_jit = jit_new_state();
        if (_jit == NULL) {
            fprintf(stderr, "jit_new_state failed\n");
            return 1;
        }

        jit_prolog();
        jit_tramp(0);

        /* Entry guard (countdown check in the real backend). */
        jit_node_t *entry_bail = jit_blei(JIT_V5, 10);

        /* Load the guest registers this trace maps. */
        jit_ldxi(a2, JIT_V1, 12 * 8);
        jit_ldxi(a3, JIT_V1, 13 * 8);
        jit_ldxi(a4, JIT_V1, 14 * 8);
        jit_ldxi(a5, JIT_V1, 15 * 8);
        jit_ldxi(a6, JIT_V1, 16 * 8);
        jit_ldxi(a7, JIT_V1, 17 * 8);

        /* The same 16-guest-instruction mix as rvjit-bench.c. */
        jit_movi(a5, 0x12345);              /* li */
        jit_addi(a5, a5, 1);                /* addi */
        jit_addr(a4, a4, a3);               /* add */
        jit_xorr(a6, a4, a5);               /* xor */
        jit_ltr_u(a7, a4, a5);              /* sltu */
        jit_andi(t0, a6, 0xff);             /* andi */
        jit_rshi_u(t1, a4, 3);              /* srli */
        jit_subr(a3, a3, t0);               /* sub */
        jit_lshi(t2, a5, 2);                /* slli */
        jit_orr(a4, a4, t1);                /* or */
        jit_addi(a2, a2, -1);               /* addiw, low half */
        jit_extr_i(a2, a2);                 /* addiw, sign extend */
        jit_mulr(s0, a4, a5);               /* mul */
        jit_node_t *guard = jit_beqi(a2, 0); /* beq guard exit */
        jit_addi(a5, a5, 8);                /* addi */
        jit_andr(a6, a6, a4);               /* and */
        jit_node_t *end = jit_beqr(a2, a5); /* trace-ending guard */

        /* Normal exit: store dirty guest registers, account cycles, leave. */
        jit_stxi(13 * 8, JIT_V1, a3);
        jit_stxi(14 * 8, JIT_V1, a4);
        jit_stxi(15 * 8, JIT_V1, a5);
        jit_stxi(16 * 8, JIT_V1, a6);
        jit_stxi(17 * 8, JIT_V1, a7);
        jit_stxi(8 * 8, JIT_V1, s0);
        jit_subi(JIT_V5, JIT_V5, INSNS_PER_TRACE);
        jit_patch_abs(jit_jmpi(), (jit_pointer_t)regfile); /* continuation address placeholder */

        /* Shared exit stub for the guards. */
        jit_patch(entry_bail);
        jit_patch(guard);
        jit_patch(end);
        jit_movi(JIT_R0, (jit_word_t)i);
        jit_patch_abs(jit_jmpi(), (jit_pointer_t)regfile);

        if (jit_emit() == NULL) {
            fprintf(stderr, "jit_emit failed\n");
            return 1;
        }
        jit_word_t code_size = 0;
        jit_get_code(&code_size);
        emitted_bytes += (uint64_t)code_size;
        states[i] = _jit;
        ++traces;
    }
    uint64_t elapsed = now_ns() - t_start;

    printf("lightning: traces %llu guest-insns %llu emitted %llu bytes\n",
        (unsigned long long)traces, (unsigned long long)(traces * INSNS_PER_TRACE),
        (unsigned long long)emitted_bytes);
    printf("lightning: total %.3f ms, %.0f ns/trace, %.1f ns/guest-insn, %.1f MB/s\n",
        elapsed / 1e6, (double)elapsed / traces, (double)elapsed / (traces * INSNS_PER_TRACE),
        emitted_bytes * 1000.0 / elapsed);

    for (uint32_t i = 0; i < N_TRACES; ++i) {
        jit_state_t *_jit = states[i];
        jit_destroy_state();
    }
    finish_jit();
    return 0;
}
