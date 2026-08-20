// Spike: stencil from the interpreter's own execute body.
#define TC_TRANSLATION_UNIT
#include "interpret.cpp"

namespace cartesi {
struct cp_slot_access;
template <>
struct i_state_access_fast_addr<cp_slot_access> {
    using type = uint64_t;
};
struct cp_slot_access : i_state_access<cp_slot_access>, i_accept_scoped_notes<cp_slot_access> {
    uint64_t *v1;
    uint64_t *v2;
    uint64_t *vd;
    cp_slot_access(uint64_t *a1, uint64_t *a2, uint64_t *ad) : v1(a1), v2(a2), vd(ad) {}
    static const char *do_get_name() {
        return "cp_slot_access";
    }
    uint64_t do_read_x(int i) const {
        return i == 1 ? *v1 : *v2;
    }
    void do_write_x(int /*i*/, uint64_t val) const {
        *vd = val;
    }
};
} // namespace cartesi

typedef unsigned long long u64;
#define CONT __attribute__((preserve_none))
CONT extern "C" void cp_cont_0(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);

extern "C" CONT void cp_add_0_1_2(u64 r0, u64 r1, u64 r2, u64 pc_, u64 cd, u64 fetch, u64 r3, u64 tcc, u64 r4, u64 r5,
    u64 r6, u64 r7) {
    using namespace cartesi;
    uint64_t v1 = r1;
    uint64_t v2 = r2;
    uint64_t vd = 0;
    const cp_slot_access a(&v1, &v2, &vd);
    uint64_t dummy_pc = 0;
    // Synthetic word: ADD with rd=3, rs1=1, rs2=2, so the decode folds.
    constexpr uint32_t INSN = (2u << 20) | (1u << 15) | (3u << 7) | 0x33u;
    (void) execute_ADD<rd_kind::xN>(a, dummy_pc, INSN);
    r0 = vd;
    __attribute__((musttail)) return cp_cont_0(r0, r1, r2, pc_, cd, fetch, r3, tcc, r4, r5, r6, r7);
}
