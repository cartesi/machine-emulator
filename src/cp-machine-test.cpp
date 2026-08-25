// Runtime test for stateful stencil families (copy-patch-rvvm.md): builds
// a real machine, warms its hot TLB through the interpreter's own
// read/write_virtual_memory paths, then executes copied and patched
// load/store and exact-FP stencil chains against the live machine state,
// checking results, architectural flags, and guard continuations.

#define TC_TRANSLATION_UNIT
#include "interpret.cpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>

#include "cp-emit.h"
#include "machine-config.hpp"

using namespace cartesi;

#ifndef CP_NSLOTS
#define CP_NSLOTS 7
#endif
#define NPARAMS (5 + CP_NSLOTS) /* sa pc cd fetch tcc + the guest slots */
/* Guest-value arrays are padded to the sixteen slots the entry call
 * names so the literal initializers and the fixed call stay well-formed
 * at smaller slot counts; entries at CP_NSLOTS and beyond are inert. */
#define CP_NSLOTS_PAD (CP_NSLOTS < 16 ? 16 : CP_NSLOTS)
#if CP_NSLOTS > 16
#error "harness names sixteen slot arguments; extend the roster here"
#endif
#if defined(__x86_64__)
#define SLOT_POS_K(k) ((k) == 0 ? 1 : (k) + 4)
#else
#define SLOT_POS_K(k) ((k) == 0 ? 1 : (k) == 1 ? 2 : (k) == 2 ? 6 : (k) + 5)
#endif
static const int SLOT_POS[CP_NSLOTS_PAD] = {SLOT_POS_K(0), SLOT_POS_K(1), SLOT_POS_K(2), SLOT_POS_K(3), SLOT_POS_K(4),
    SLOT_POS_K(5), SLOT_POS_K(6), SLOT_POS_K(7), SLOT_POS_K(8), SLOT_POS_K(9), SLOT_POS_K(10), SLOT_POS_K(11),
    SLOT_POS_K(12), SLOT_POS_K(13), SLOT_POS_K(14), SLOT_POS_K(15)};

using cp_entry_t = __attribute__((preserve_none)) void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t);

static cp_heap_t heap;
static uint64_t out_hit[NPARAMS];
static uint64_t out_bail[NPARAMS];

// Emits stencil -> store_exit(out_hit) with the bail continuation aimed at a
// separate store_exit(out_bail); returns the chain entry.
static uint8_t *emit_chain(const cp_stencil_t *st, uint64_t stencil_selector = 0) {
    heap.curr = 0;
    cp_heap_unprotect(&heap);
    uint64_t imm_bail[2] = {reinterpret_cast<uint64_t>(out_bail), 0};
    uint8_t *none[2] = {nullptr, nullptr};
    uint8_t *bail = cp_emit(&heap, &cp_s_cp_store_exit, imm_bail, none);
    uint64_t imm[2] = {stencil_selector, 0};
    uint8_t *cont[2] = {nullptr, bail};
    uint8_t *entry = cp_emit(&heap, st, imm, cont);
    uint64_t imm_hit[2] = {reinterpret_cast<uint64_t>(out_hit), 0};
    cp_emit(&heap, &cp_s_cp_store_exit, imm_hit, none);
    cp_heap_protect_flush(&heap);
    return entry;
}

static int failures = 0;

static void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

int main() {
    machine_config cfg;
    cfg.ram.length = 1 << 20;
    machine m(cfg);
    const state_access a(m);
    const auto sa_bits = std::bit_cast<uint64_t>(a);

    if (cp_heap_init(&heap, 1u << 20) != 0) {
        std::perror("cp_heap_init");
        return 1;
    }

    // Test data in RAM, one warmed page and one never-touched page.
    const uint64_t warm_vaddr = AR_RAM_START + 0x1000;
    const uint64_t cold_vaddr = AR_RAM_START + 0x10000;
    const uint64_t pattern = 0x1122334455667788ull;
    m.write_memory(warm_vaddr, reinterpret_cast<const unsigned char *>(&pattern), sizeof(pattern));
    const uint8_t negb = 0x80;
    m.write_memory(warm_vaddr + 8, &negb, 1);

    // Warm the read and write hot TLB slots through the interpreter's own
    // slow paths (bare translation: machine mode, satp off).
    {
        host_addr pc{};
        uint64_t val = 0;
        check(read_virtual_memory<uint64_t>(a, pc, 0, warm_vaddr, &val), "warm read");
        check(val == pattern, "warm read value");
        const auto st = write_virtual_memory<uint64_t>(a, pc, 0, warm_vaddr, pattern);
        check(st == execute_status::success, "warm write");
    }

    const uint64_t g_init[CP_NSLOTS_PAD] = {warm_vaddr, 0xaaaaaaaaaaaaaaaaull, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16};
    const uint64_t ctx = a.read_tlb_ctx_slot_base() / TLB_SET_SIZE;
    const auto run = [&](uint8_t *entry, const uint64_t g[CP_NSLOTS_PAD]) {
        std::memset(out_hit, 0xee, sizeof(out_hit));
        std::memset(out_bail, 0xdd, sizeof(out_bail));
#if defined(__x86_64__) && CP_NSLOTS == 6
        reinterpret_cast<cp_entry_t>(entry)(sa_bits, g[0], 0x111100ull, 0x2222ull, 0x3333ull, g[1], g[2], g[3], g[4],
            g[5], 0x4444ull, g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
#elif defined(__x86_64__) && CP_NSLOTS == 7
        reinterpret_cast<cp_entry_t>(entry)(sa_bits, g[0], 0x111100ull, 0x2222ull, 0x3333ull, g[1], g[2], g[3], g[4],
            g[5], g[6], 0x4444ull, g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
#elif defined(__x86_64__)
#error "extend the machine test entry for this x86-64 CP_NSLOTS"
#else
        reinterpret_cast<cp_entry_t>(entry)(sa_bits, g[0], g[1], 0x111100ull, 0x2222ull, 0x3333ull, g[2], 0x4444ull,
            g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
#endif
    };

    // 1. LD hit: slot1 = [slot0], hit continuation taken, value exact.
    {
        uint8_t *entry = emit_chain(cp_ld_table[1][0], ctx);
        run(entry, g_init);
        check(out_hit[SLOT_POS[1]] == pattern, "ld hit value");
        check(out_hit[SLOT_POS[0]] == warm_vaddr, "ld base preserved");
        check(out_bail[0] == 0xddddddddddddddddull, "ld bail not taken");
    }

    // 2. LB sign extension from the interpreter's own semantics.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = warm_vaddr + 8;
        uint8_t *entry = emit_chain(cp_lb_table[1][0], ctx);
        run(entry, g);
        check(out_hit[SLOT_POS[1]] == 0xffffffffffffff80ull, "lb sign extension");
    }

    // 3. Cold slot: uninitialized hot TLB entry must take the bail
    // continuation and leave every slot unchanged.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = cold_vaddr;
        uint8_t *entry = emit_chain(cp_ld_table[1][0], ctx);
        run(entry, g);
        check(out_bail[SLOT_POS[1]] == 0xaaaaaaaaaaaaaaaaull, "cold ld bails with slots intact");
        check(out_hit[0] == 0xeeeeeeeeeeeeeeeeull, "cold ld hit not taken");
    }

    // 4. SD hit: [slot0] = slot1, then verify through the machine.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[1] = 0xcafef00dcafef00dull;
        uint8_t *entry = emit_chain(cp_sd_table[0][1], ctx);
        run(entry, g);
        check(out_hit[0] != 0xeeeeeeeeeeeeeeeeull || out_hit[SLOT_POS[0]] == warm_vaddr, "sd hit taken");
        uint64_t readback = 0;
        m.read_memory(warm_vaddr, reinterpret_cast<unsigned char *>(&readback), sizeof(readback));
        check(readback == 0xcafef00dcafef00dull, "sd value visible through the machine");
    }

    // 5. SW then LWU: word store and zero-extending reload compose.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[1] = 0xffffffff80000001ull;
        uint8_t *entry = emit_chain(cp_sw_table[0][1], ctx);
        run(entry, g);
        uint8_t *entry2 = emit_chain(cp_lwu_table[2][0], ctx);
        run(entry2, g);
        check(out_hit[SLOT_POS[2]] == 0x80000001ull, "sw + lwu round trip");
    }

    // 6. Direct MV copies the source without an artificial x0 operand.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = 0x0123456789abcdefull;
        uint8_t *entry = emit_chain(cp_mv_table[1][0]);
        run(entry, g);
        check(out_hit[SLOT_POS[1]] == g[0], "mv exact value");
        check(out_hit[SLOT_POS[0]] == g[0], "mv source preserved");
    }

    // Exact FP stencils are guarded only by mstatus.FS. They use integer
    // and soft-float bit semantics and never take the arithmetic fallback.
    a.write_mstatus((a.read_mstatus() & ~MSTATUS_FS_MASK) | MSTATUS_FS_DIRTY);

    // 7. Sign injection preserves payload bits and replaces only the sign.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = float_box(UINT32_C(0x3f800001));
        g[1] = float_box(UINT32_C(0xc0000002));
        uint8_t *entry = emit_chain(cp_fp_fsgnj_s_table[0][1]);
        run(entry, g);
        check(out_hit[SLOT_POS[0]] == float_box(UINT32_C(0xbf800001)), "fsgnj.s exact bits");
        check(out_bail[0] == 0xddddddddddddddddull, "fsgnj.s has no fallback");
    }

    // 8. Min handles signaling NaN and accumulates NV exactly.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = float_box(UINT32_C(0x7f800001));
        g[1] = float_box(UINT32_C(0x3f800000));
        a.write_fcsr(0);
        uint8_t *entry = emit_chain(cp_fp_min_s_table[0][1]);
        run(entry, g);
        check(out_hit[SLOT_POS[0]] == float_box(UINT32_C(0x3f800000)), "fmin.s signaling NaN result");
        check((a.read_fcsr() & FFLAGS_NV_MASK) != 0, "fmin.s signaling NaN flag");
    }

    // 9. Comparisons write the integer roster destination and preserve the
    // same NaN exception behavior as the portable implementation.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = float_box(UINT64_C(0x3ff0000000000000));
        g[1] = float_box(UINT64_C(0x4000000000000000));
        a.write_fcsr(0);
        uint8_t *entry = emit_chain(cp_fp_lt_d_table[0][1]);
        run(entry, g);
        check(out_hit[SLOT_POS[0]] == 1, "flt.d exact result");
        check(a.read_fcsr() == 0, "flt.d exact flags");
    }

    // 10. Classification performs mandatory NaN unboxing: malformed single
    // precision input is classified as the canonical quiet NaN.
    {
        uint64_t g[CP_NSLOTS_PAD];
        std::memcpy(g, g_init, sizeof(g));
        g[0] = UINT64_C(0x000000003f800000);
        uint8_t *entry = emit_chain(cp_fp_class_s_table[0]);
        run(entry, g);
        check(out_hit[SLOT_POS[0]] == i_sfloat32::fclass(i_sfloat32::F_QNAN), "fclass.s malformed box");
    }

    // 11. FS-off fails before any exact operation and leaves every roster
    // value untouched for portable exception handling.
    {
        a.write_mstatus(a.read_mstatus() & ~MSTATUS_FS_MASK);
        uint8_t *entry = emit_chain(&cp_s_cp_fp_fs_guard);
        run(entry, g_init);
        check(out_bail[SLOT_POS[0]] == g_init[0], "FP FS-off guard preserves slots");
        check(out_hit[0] == 0xeeeeeeeeeeeeeeeeull, "FP FS-off guard takes bail");
    }

    cp_heap_free(&heap);
    if (failures != 0) {
        std::fprintf(stderr, "cp-machine-test: FAILED (%d)\n", failures);
        return 1;
    }
    std::printf("cp-machine-test: PASSED\n");
    return 0;
}
