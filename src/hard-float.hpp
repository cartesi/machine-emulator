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

#ifndef HARD_FLOAT_HPP
#define HARD_FLOAT_HPP

/// \file
/// \brief Hardware floating-point operations with soft-float fallback.
/// \details The fast path executes guest floating-point operations directly on the host FPU when
/// uniform guards prove the result and exception flags bit-identical to the soft-float reference,
/// and falls back to soft-float otherwise. Guest-visible state transitions are therefore exactly
/// the same with the fast path enabled or disabled.

#include <cstdint>

#include "soft-float.hpp"

#if !defined(MICROARCHITECTURE) && !defined(ZKARCHITECTURE) && !defined(__FAST_MATH__) &&                              \
    (defined(__x86_64__) || defined(__aarch64__))
#define HARD_FLOAT
#endif

#ifdef HARD_FLOAT

#include <bit>
#include <cfloat>
#include <cstdlib>
#include <limits>
#include <optional>
#include <type_traits>

namespace cartesi {

// The fast path requires host floats to be IEC 60559 binary32/binary64, with each operation
// evaluated in its own type (no excess precision). Hosts that fail these requirements must
// not define HARD_FLOAT above, and then fall back to pure soft-float.
static_assert(std::numeric_limits<float>::is_iec559 && std::numeric_limits<double>::is_iec559,
    "hard float requires IEC 60559 host floating-point");
static_assert(FLT_EVAL_METHOD == 0, "hard float requires evaluation without excess precision");
static_assert(std::numeric_limits<float>::digits == 24 && std::numeric_limits<double>::digits == 53,
    "hard float requires binary32/binary64 host floating-point");

/// \brief Per-thread hard-float dispatch state.
struct hard_float_context {
    bool enabled{false}; // fast path may be used (set while a hard_float_scope is active)
#ifdef DUMP_STATS
    uint64_t hits{0};      // operations completed by the host FPU
    uint64_t fallbacks{0}; // operations that fell back to soft-float
#endif
};

/// \brief Returns the calling thread's hard-float dispatch state.
/// \details This is read on every accelerated operation, so the access must stay cheap. On ELF hosts
/// the initial-exec TLS model reduces it to one register-relative load, where the general-dynamic
/// model that shared objects get by default would call __tls_get_addr instead. The variable is small
/// enough to always fit the static TLS surplus reserved for dynamically loaded objects.
inline hard_float_context &hard_float_ctx() {
#ifdef __ELF__
    static thread_local hard_float_context ctx [[gnu::tls_model("initial-exec")]];
#else
    static thread_local hard_float_context ctx;
#endif
    return ctx;
}

/// \brief Counts an operation completed by the host FPU (statistics builds only).
inline void hard_float_count_hit() {
#ifdef DUMP_STATS
    hard_float_ctx().hits++;
#endif
}

/// \brief Counts an operation that fell back to soft-float (statistics builds only).
inline void hard_float_count_fallback() {
#ifdef DUMP_STATS
    hard_float_ctx().fallbacks++;
#endif
}

/// \class hard_float_scope
/// \brief Enables the hard-float fast path while in scope, when the host environment allows it.
/// \details The constructor saves the host floating-point environment and enables the fast path only
/// if its control fields are at their defaults (round-to-nearest-even, subnormals preserved, exception
/// traps masked) and CARTESI_NO_HARDFLOAT is not set in the process environment. Sticky exception-status
/// fields are ignored in the decision, because fast-path operations themselves set them. The destructor
/// restores the exact saved environment, so no floating-point status leaks to the caller. Nothing running
/// inside the scope may change the host floating-point control fields.
class hard_float_scope final {
public:
    hard_float_scope() {
#if defined(__x86_64__)
        m_mxcsr = __builtin_ia32_stmxcsr();
        // Default MXCSR control fields: FTZ/DAZ off, round-to-nearest, all exceptions masked.
        // The low 6 bits are the sticky exception-status flags.
        const bool env_ok = (m_mxcsr & ~UINT32_C(0x3f)) == UINT32_C(0x1f80);
#elif defined(__aarch64__)
        asm volatile("mrs %0, fpcr" : "=r"(m_fpcr)); // NOLINT(hicpp-no-assembler)
        asm volatile("mrs %0, fpsr" : "=r"(m_fpsr)); // NOLINT(hicpp-no-assembler)
        // FPCR fields that must be at their defaults: RMode (round-to-nearest), FZ/FZ16/FIZ/AH
        // (subnormals preserved, standard IEEE handling), and all exception trap enables.
        constexpr uint64_t FPCR_CHECK_MASK = (UINT64_C(3) << 22) | // RMode
            (UINT64_C(1) << 24) |                                  // FZ
            (UINT64_C(1) << 19) |                                  // FZ16
            (UINT64_C(0x1f) << 8) | (UINT64_C(1) << 15) |          // IOE/DZE/OFE/UFE/IXE/IDE trap enables
            (UINT64_C(1) << 1) | UINT64_C(1);                      // AH and FIZ
        const bool env_ok = (m_fpcr & FPCR_CHECK_MASK) == 0;
#endif
        hard_float_ctx().enabled = env_ok && std::getenv("CARTESI_NO_HARDFLOAT") == nullptr;
    }

    ~hard_float_scope() {
        hard_float_ctx().enabled = false;
#if defined(__x86_64__)
        __builtin_ia32_ldmxcsr(m_mxcsr);
#elif defined(__aarch64__)
        asm volatile("msr fpcr, %0" : : "r"(m_fpcr)); // NOLINT(hicpp-no-assembler)
        asm volatile("msr fpsr, %0" : : "r"(m_fpsr)); // NOLINT(hicpp-no-assembler)
#endif
    }

    hard_float_scope(const hard_float_scope &) = delete;
    hard_float_scope(hard_float_scope &&) = delete;
    hard_float_scope &operator=(const hard_float_scope &) = delete;
    hard_float_scope &operator=(hard_float_scope &&) = delete;

private:
#if defined(__x86_64__)
    uint32_t m_mxcsr{0};
#elif defined(__aarch64__)
    uint64_t m_fpcr{0};
    uint64_t m_fpsr{0};
#endif
};

/// \class i_hfloat
/// \brief Hardware floating-point operations with soft-float fallback.
/// \tparam SFLOAT Soft-float interface used as reference and fallback.
/// \tparam F_HOST Host floating-point type with the same binary representation.
/// \details Overrides only add, mul, fma, div, and sqrt; everything else is inherited from SFLOAT.
/// An overridden operation runs on the host FPU when uniform guards hold: the resolved rounding mode
/// is round-to-nearest-even (the host default), NX is already sticky in fflags, every operand is zero
/// or normal (no NaN, infinity, or subnormal), and the result is a normal with magnitude strictly
/// above the smallest normal. Under these guards the operation cannot raise any flag other than NX,
/// which is already set, and the correctly rounded host result is bit-identical to the soft-float
/// result. Every other case falls back to SFLOAT, which is safe because the operations are pure.
template <typename SFLOAT, typename F_HOST>
struct i_hfloat : SFLOAT {
    using F_UINT = SFLOAT::F_UINT;

    static_assert(sizeof(F_UINT) == sizeof(F_HOST), "host float type must match the guest representation");

    /// \brief Checks if a float is zero or normal (per-operand pre-guard).
    static bool is_zero_or_normal(F_UINT a) {
        const uint32_t a_exp = (a >> SFLOAT::MANT_SIZE) & SFLOAT::EXP_MASK;
        const F_UINT a_mant = a & SFLOAT::MANT_MASK;
        return (a_exp != 0 || a_mant == 0) && a_exp != SFLOAT::EXP_MASK;
    }

    /// \brief Checks if a float is a safe fast-path result (post-guard).
    /// \details Requires a normal with magnitude strictly above the smallest normal. A result of
    /// exactly the smallest normal magnitude can carry the underflow flag, when a tiny exact value
    /// rounds up to it, so it must fall back. Larger normals cannot carry underflow, and overflow
    /// under round-to-nearest always delivers infinity, which is also rejected here.
    static bool is_safe_result(F_UINT a) {
        const F_UINT a_mag = a & ~SFLOAT::SIGN_MASK;
        return a_mag > (static_cast<F_UINT>(1) << SFLOAT::MANT_SIZE) &&
            a_mag < (static_cast<F_UINT>(SFLOAT::EXP_MASK) << SFLOAT::MANT_SIZE);
    }

    /// \brief Checks the operand-independent pre-guard conditions.
    /// \details The plain integer tests come first, so operations that cannot take the fast path
    /// short-circuit past the thread-local access.
    static bool use_hard(FRM_modes rm, uint32_t fflags) {
        return rm == FRM_RNE && (fflags & FFLAGS_NX_MASK) != 0 && hard_float_ctx().enabled;
    }

    /// \brief Attempts a unary operation on the host FPU.
    /// \returns The result when the guards prove it bit-identical to soft-float, nullopt otherwise.
    template <typename HOP>
    static std::optional<F_UINT> try_unary(F_UINT a, FRM_modes rm, uint32_t fflags, const HOP &hop) {
        if (use_hard(rm, fflags) && is_zero_or_normal(a)) [[likely]] {
            const auto r = std::bit_cast<F_UINT>(hop(std::bit_cast<F_HOST>(a)));
            if (is_safe_result(r)) [[likely]] {
                hard_float_count_hit();
                return r;
            }
        }
        hard_float_count_fallback();
        return std::nullopt;
    }

    /// \brief Attempts a binary operation on the host FPU.
    /// \returns The result when the guards prove it bit-identical to soft-float, nullopt otherwise.
    template <typename HOP>
    static std::optional<F_UINT> try_binary(F_UINT a, F_UINT b, FRM_modes rm, uint32_t fflags, const HOP &hop) {
        if (use_hard(rm, fflags) && is_zero_or_normal(a) && is_zero_or_normal(b)) [[likely]] {
            const auto r = std::bit_cast<F_UINT>(hop(std::bit_cast<F_HOST>(a), std::bit_cast<F_HOST>(b)));
            if (is_safe_result(r)) [[likely]] {
                hard_float_count_hit();
                return r;
            }
        }
        hard_float_count_fallback();
        return std::nullopt;
    }

    /// \brief Attempts a ternary operation on the host FPU.
    /// \returns The result when the guards prove it bit-identical to soft-float, nullopt otherwise.
    template <typename HOP>
    static std::optional<F_UINT> try_ternary(F_UINT a, F_UINT b, F_UINT c, FRM_modes rm, uint32_t fflags,
        const HOP &hop) {
        if (use_hard(rm, fflags) && is_zero_or_normal(a) && is_zero_or_normal(b) && is_zero_or_normal(c)) [[likely]] {
            const auto r = std::bit_cast<F_UINT>(
                hop(std::bit_cast<F_HOST>(a), std::bit_cast<F_HOST>(b), std::bit_cast<F_HOST>(c)));
            if (is_safe_result(r)) [[likely]] {
                hard_float_count_hit();
                return r;
            }
        }
        hard_float_count_fallback();
        return std::nullopt;
    }

    /// \brief Addition operation.
    static F_UINT add(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        if (const auto r = try_binary(a, b, rm, *pfflags, [](F_HOST x, F_HOST y) { return x + y; })) [[likely]] {
            return *r;
        }
        return SFLOAT::add(a, b, rm, pfflags);
    }

    /// \brief Multiply operation.
    static F_UINT mul(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        if (const auto r = try_binary(a, b, rm, *pfflags, [](F_HOST x, F_HOST y) { return x * y; })) [[likely]] {
            return *r;
        }
        return SFLOAT::mul(a, b, rm, pfflags);
    }

    /// \brief Fused multiply and add operation.
    static F_UINT fma(F_UINT a, F_UINT b, F_UINT c, FRM_modes rm, uint32_t *pfflags) {
        if (const auto r = try_ternary(a, b, c, rm, *pfflags, [](F_HOST x, F_HOST y, F_HOST z) {
                if constexpr (std::is_same_v<F_HOST, float>) {
                    return __builtin_fmaf(x, y, z);
                } else {
                    return __builtin_fma(x, y, z);
                }
            })) [[likely]] {
            return *r;
        }
        return SFLOAT::fma(a, b, c, rm, pfflags);
    }

    /// \brief Division operation.
    static F_UINT div(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        if (const auto r = try_binary(a, b, rm, *pfflags, [](F_HOST x, F_HOST y) { return x / y; })) [[likely]] {
            return *r;
        }
        return SFLOAT::div(a, b, rm, pfflags);
    }

    /// \brief Square root operation.
    static F_UINT sqrt(F_UINT a, FRM_modes rm, uint32_t *pfflags) {
        if (const auto r = try_unary(a, rm, *pfflags, [](F_HOST x) {
                if constexpr (std::is_same_v<F_HOST, float>) {
                    return __builtin_sqrtf(x);
                } else {
                    return __builtin_sqrt(x);
                }
            })) [[likely]] {
            return *r;
        }
        return SFLOAT::sqrt(a, rm, pfflags);
    }
};

using i_float32 = i_hfloat<i_sfloat32, float>;  // Single-precision with hard-float fast path
using i_float64 = i_hfloat<i_sfloat64, double>; // Double-precision with hard-float fast path

} // namespace cartesi

#else // !HARD_FLOAT

namespace cartesi {

using i_float32 = i_sfloat32; // Single-precision, soft-float only
using i_float64 = i_sfloat64; // Double-precision, soft-float only

/// \brief No-op stand-in for builds without the hard-float fast path.
class hard_float_scope final {};

} // namespace cartesi

#endif

#endif
