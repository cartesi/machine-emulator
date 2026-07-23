// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

/// \file
/// \brief Differential tests for the hard-float fast path against the soft-float reference.
/// \details Every accelerated operation is compared against the soft-float implementation, in
/// result bits and resulting fflags, over structured edge-case operands and random operands,
/// across all rounding modes and with NX initially clear and set. The test also proves through
/// the dispatch counters that the fast path actually executes (a differential test could
/// otherwise pass while only ever exercising the fallback), and checks that the environment
/// guard disables dispatch under non-default host controls, preserves the caller's status
/// flags, and honors the CARTESI_NO_HARDFLOAT kill switch.

#include <array>
#include <cfenv>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

#include "hard-float.hpp"
#include "soft-float.hpp"

using namespace cartesi;

static uint64_t checked = 0;
static uint64_t failed = 0;

static void fail(const char *msg) {
    std::fprintf(stderr, "FAILED %s\n", msg);
    failed++;
}

static void report(const char *op, uint32_t rm, uint32_t fflags_in, uint64_t a, uint64_t b, uint64_t c, uint64_t rs,
    uint32_t fs, uint64_t rh, uint32_t fh) {
    std::fprintf(stderr,
        "FAILED %s rm=%" PRIu32 " fflags=%02" PRIx32 " a=%016" PRIx64 " b=%016" PRIx64 " c=%016" PRIx64
        " soft=%016" PRIx64 "/%02" PRIx32 " hard=%016" PRIx64 "/%02" PRIx32 "\n",
        op, rm, fflags_in, a, b, c, rs, fs, rh, fh);
    failed++;
    if (failed > 20) {
        std::fprintf(stderr, "too many failures, aborting\n");
        std::exit(1);
    }
}

/// \brief Differential checks of HFLOAT against SFLOAT for one precision.
template <typename SFLOAT, typename HFLOAT>
struct differ {
    using U = SFLOAT::F_UINT;
    using unary_fn = U (*)(U, FRM_modes, uint32_t *);
    using binary_fn = U (*)(U, U, FRM_modes, uint32_t *);
    using ternary_fn = U (*)(U, U, U, FRM_modes, uint32_t *);

    static constexpr std::array<uint32_t, 2> NX_PRESETS{0, FFLAGS_NX_MASK};

    static void check1(const char *op, unary_fn soft, unary_fn hard, U a, FRM_modes rm, uint32_t fflags_in) {
        uint32_t fs = fflags_in;
        uint32_t fh = fflags_in;
        const U rs = soft(a, rm, &fs);
        const U rh = hard(a, rm, &fh);
        checked++;
        if (rs != rh || fs != fh) {
            report(op, rm, fflags_in, a, 0, 0, rs, fs, rh, fh);
        }
    }

    static void check2(const char *op, binary_fn soft, binary_fn hard, U a, U b, FRM_modes rm, uint32_t fflags_in) {
        uint32_t fs = fflags_in;
        uint32_t fh = fflags_in;
        const U rs = soft(a, b, rm, &fs);
        const U rh = hard(a, b, rm, &fh);
        checked++;
        if (rs != rh || fs != fh) {
            report(op, rm, fflags_in, a, b, 0, rs, fs, rh, fh);
        }
    }

    static void check3(const char *op, ternary_fn soft, ternary_fn hard, U a, U b, U c, FRM_modes rm,
        uint32_t fflags_in) {
        uint32_t fs = fflags_in;
        uint32_t fh = fflags_in;
        const U rs = soft(a, b, c, rm, &fs);
        const U rh = hard(a, b, c, rm, &fh);
        checked++;
        if (rs != rh || fs != fh) {
            report(op, rm, fflags_in, a, b, c, rs, fs, rh, fh);
        }
    }

    /// \brief Structured operand set covering every float class and rounding boundary shapes.
    static std::vector<U> interesting_values() {
        constexpr auto EXPM = static_cast<uint32_t>(SFLOAT::EXP_MASK);
        constexpr U MM = SFLOAT::MANT_MASK;
        constexpr uint32_t BIAS = EXPM / 2;
        constexpr auto MANT = static_cast<uint32_t>(SFLOAT::MANT_SIZE);
        std::vector<U> v{
            SFLOAT::pack(0, 0, 0),                              // +0
            SFLOAT::pack(1, 0, 0),                              // -0
            SFLOAT::pack(0, 0, 1),                              // min subnormal
            SFLOAT::pack(1, 0, 1),                              // -min subnormal
            SFLOAT::pack(0, 0, MM),                             // max subnormal
            SFLOAT::pack(1, 0, MM),                             // -max subnormal
            SFLOAT::pack(0, 0, (MM >> 1) + 1),                  // mid subnormal
            SFLOAT::pack(0, 1, 0),                              // min normal
            SFLOAT::pack(1, 1, 0),                              // -min normal
            SFLOAT::pack(0, 1, 1),                              // min normal + ulp
            SFLOAT::pack(0, EXPM - 1, MM),                      // max normal
            SFLOAT::pack(1, EXPM - 1, MM),                      // -max normal
            SFLOAT::pack(0, EXPM - 1, 0),                       // large power of two
            SFLOAT::pack(0, EXPM - 2, MM),                      // half max normal, odd mantissa
            SFLOAT::pack(0, BIAS, 0),                           // 1.0
            SFLOAT::pack(1, BIAS, 0),                           // -1.0
            SFLOAT::pack(0, BIAS, 1),                           // 1.0 + ulp
            SFLOAT::pack(1, BIAS, 1),                           // -(1.0 + ulp)
            SFLOAT::pack(0, BIAS, MM),                          // just below 2.0
            SFLOAT::pack(0, BIAS, MM >> 1),                     // 1.499...
            SFLOAT::pack(0, BIAS, (MM >> 1) + 1),               // 1.5
            SFLOAT::pack(0, BIAS + 1, (MM >> 1)),               // 2.999...
            SFLOAT::pack(1, BIAS + 1, 1),                       // odd mantissa, negative
            SFLOAT::pack(0, BIAS - 1, 0),                       // 0.5
            SFLOAT::pack(0, BIAS + 1, 0),                       // 2.0
            SFLOAT::pack(0, BIAS + 2, MM),                      // near 8, odd mantissa
            SFLOAT::pack(0, BIAS - MANT, 0),                    // ulp of 1.0
            SFLOAT::pack(0, BIAS - MANT - 1, 0),                // half ulp of 1.0 (round-to-even boundary)
            SFLOAT::pack(0, BIAS - MANT - 2, 0),                // quarter ulp of 1.0
            SFLOAT::pack(1, BIAS - MANT - 1, 0),                // negative half ulp
            SFLOAT::pack(0, BIAS + MANT, 0),                    // large odd-integer scale
            SFLOAT::pack(0, BIAS + MANT + 1, 1),                // integer with sticky bits
            SFLOAT::pack(0, EXPM, 0),                           // +inf
            SFLOAT::pack(1, EXPM, 0),                           // -inf
            SFLOAT::F_QNAN,                                     // canonical qNaN
            static_cast<U>(SFLOAT::F_QNAN | SFLOAT::SIGN_MASK), // negative qNaN
            SFLOAT::pack(0, EXPM, SFLOAT::QNAN_MASK | 1),       // qNaN with payload
            SFLOAT::pack(0, EXPM, 1),                           // sNaN
            SFLOAT::pack(1, EXPM, MM >> 1),                     // negative sNaN with payload
        };
        std::mt19937_64 gen(42);
        for (int i = 0; i < 16; i++) {
            v.push_back(static_cast<U>(gen()));
        }
        return v;
    }

    /// \brief Operation names for reports, filled in by name_ops().
    struct op_names {
        char add[16];
        char mul[16];
        char div[16];
        char sqrt[16];
        char fma[16];
    };

    static op_names name_ops(const char *prec) {
        op_names n{};
        (void) std::snprintf(n.add, sizeof(n.add), "%s.add", prec);
        (void) std::snprintf(n.mul, sizeof(n.mul), "%s.mul", prec);
        (void) std::snprintf(n.div, sizeof(n.div), "%s.div", prec);
        (void) std::snprintf(n.sqrt, sizeof(n.sqrt), "%s.sqrt", prec);
        (void) std::snprintf(n.fma, sizeof(n.fma), "%s.fma", prec);
        return n;
    }

    static void sweep_structured(const char *prec) {
        const op_names n = name_ops(prec);
        const std::vector<U> vals = interesting_values();
        for (uint32_t rm = FRM_RNE; rm <= FRM_RMM; rm++) {
            for (const uint32_t nx : NX_PRESETS) {
                for (const U a : vals) {
                    check1(n.sqrt, SFLOAT::sqrt, HFLOAT::sqrt, a, static_cast<FRM_modes>(rm), nx);
                    for (const U b : vals) {
                        check2(n.add, SFLOAT::add, HFLOAT::add, a, b, static_cast<FRM_modes>(rm), nx);
                        check2(n.mul, SFLOAT::mul, HFLOAT::mul, a, b, static_cast<FRM_modes>(rm), nx);
                        check2(n.div, SFLOAT::div, HFLOAT::div, a, b, static_cast<FRM_modes>(rm), nx);
                        for (const U c : vals) {
                            check3(n.fma, SFLOAT::fma, HFLOAT::fma, a, b, c, static_cast<FRM_modes>(rm), nx);
                        }
                    }
                }
            }
        }
    }

    static void sweep_random(const char *prec, uint64_t count) {
        const op_names n = name_ops(prec);
        std::mt19937_64 gen(43);
        for (uint64_t i = 0; i < count; i++) {
            const auto a = static_cast<U>(gen());
            const auto b = static_cast<U>(gen());
            const auto c = static_cast<U>(gen());
            const auto rm = static_cast<FRM_modes>(gen() % 5);
            const uint32_t nx = NX_PRESETS[gen() % 2];
            check2(n.add, SFLOAT::add, HFLOAT::add, a, b, rm, nx);
            check2(n.mul, SFLOAT::mul, HFLOAT::mul, a, b, rm, nx);
            check2(n.div, SFLOAT::div, HFLOAT::div, a, b, rm, nx);
            check1(n.sqrt, SFLOAT::sqrt, HFLOAT::sqrt, a, rm, nx);
            check3(n.fma, SFLOAT::fma, HFLOAT::fma, a, b, c, rm, nx);
        }
    }
};

using differ32 = differ<i_sfloat32, i_float32>;
using differ64 = differ<i_sfloat64, i_float64>;

#ifdef HARD_FLOAT

// 1.5 and 2.5: normal operands whose add/mul/div/sqrt/fma results are nonzero normals,
// so with NX set and RNE every accelerated operation must take the fast path.
static constexpr uint64_t D_1_5 = UINT64_C(0x3ff8000000000000);
static constexpr uint64_t D_2_5 = UINT64_C(0x4004000000000000);
static constexpr uint32_t S_1_5 = UINT32_C(0x3fc00000);
static constexpr uint32_t S_2_5 = UINT32_C(0x40200000);

/// \brief Runs one call of every accelerated operation and format, each with the given initial fflags.
static void run_all_ops(uint32_t fflags_in) {
    uint32_t ff = fflags_in;
    (void) i_float64::add(D_1_5, D_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float64::mul(D_1_5, D_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float64::div(D_1_5, D_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float64::sqrt(D_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float64::fma(D_1_5, D_2_5, D_1_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float32::add(S_1_5, S_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float32::mul(S_1_5, S_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float32::div(S_1_5, S_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float32::sqrt(S_2_5, FRM_RNE, &ff);
    ff = fflags_in;
    (void) i_float32::fma(S_1_5, S_2_5, S_1_5, FRM_RNE, &ff);
}

/// \brief Proves through the dispatch counters that the fast path actually executes.
static void check_fast_path_coverage() {
    auto &ctx = hard_float_ctx();
    // with NX set, all 10 op/format combinations must be completed by the host FPU
    const uint64_t hits0 = ctx.hits;
    run_all_ops(FFLAGS_NX_MASK);
    if (ctx.hits != hits0 + 10) {
        fail("some operation did not take the fast path with NX set");
    }
    // with NX clear, all of them must fall back
    const uint64_t hits1 = ctx.hits;
    const uint64_t fallbacks1 = ctx.fallbacks;
    run_all_ops(0);
    if (ctx.hits != hits1 || ctx.fallbacks != fallbacks1 + 10) {
        fail("some operation did not fall back with NX clear");
    }
}

/// \brief Checks that the environment guard disables dispatch and preserves the caller's FP state.
static void check_env_guard() {
    // non-default rounding control must disable the fast path, and operations must
    // keep producing soft-float results (fail closed)
    (void) fesetround(FE_UPWARD);
    {
        const hard_float_scope scope;
        if (hard_float_ctx().enabled) {
            fail("fast path enabled under non-default host rounding control");
        }
        uint32_t ff = FFLAGS_NX_MASK;
        uint32_t fs = FFLAGS_NX_MASK;
        if (i_float64::add(D_1_5, D_2_5, FRM_RNE, &ff) != i_sfloat64::add(D_1_5, D_2_5, FRM_RNE, &fs) || ff != fs) {
            fail("operation diverged from soft-float under non-default host controls");
        }
    }
    (void) fesetround(FE_TONEAREST);

    // sticky status flags must not block dispatch, and the caller's exact status must
    // survive a scope in which fast-path operations raise host status flags
    (void) feclearexcept(FE_ALL_EXCEPT);
    (void) feraiseexcept(FE_DIVBYZERO);
    const int status_before = fetestexcept(FE_ALL_EXCEPT);
    if ((status_before & FE_DIVBYZERO) == 0 || (status_before & FE_INEXACT) != 0) {
        fail("could not stage the expected pending status flags");
    }
    {
        const hard_float_scope scope;
        if (!hard_float_ctx().enabled) {
            fail("pending status flags disabled the fast path");
        }
        uint32_t ff = FFLAGS_NX_MASK;
        (void) i_float64::div(D_1_5, D_2_5, FRM_RNE, &ff); // inexact, raises host NX status
    }
    if (fetestexcept(FE_ALL_EXCEPT) != status_before) {
        fail("scope did not restore the caller's exact status flags");
    }
    (void) feclearexcept(FE_ALL_EXCEPT);

    // the kill switch must disable dispatch
    (void) setenv("CARTESI_NO_HARDFLOAT", "1", 1);
    {
        const hard_float_scope scope;
        if (hard_float_ctx().enabled) {
            fail("fast path enabled despite CARTESI_NO_HARDFLOAT");
        }
    }
    (void) unsetenv("CARTESI_NO_HARDFLOAT");
}

#endif // HARD_FLOAT

int main() {
#ifdef HARD_FLOAT
    const hard_float_scope scope;
    if (!hard_float_ctx().enabled) {
        std::fprintf(stderr, "hard-float fast path disabled by host environment or CARTESI_NO_HARDFLOAT\n");
        return 1; // the differential sweeps would silently test nothing
    }
#else
    std::printf("hard float not compiled in, running trivial soft-vs-soft comparison\n");
#endif
    differ64::sweep_structured("f64");
    differ32::sweep_structured("f32");
    differ64::sweep_random("f64", 1000000);
    differ32::sweep_random("f32", 1000000);
#ifdef HARD_FLOAT
    check_fast_path_coverage();
    check_env_guard();
    std::printf("dispatch: %" PRIu64 " fast-path hits, %" PRIu64 " fallbacks\n", hard_float_ctx().hits,
        hard_float_ctx().fallbacks);
#endif
    std::printf("%" PRIu64 " cases checked, %" PRIu64 " failed\n", checked, failed);
    return failed == 0 ? 0 : 1;
}
