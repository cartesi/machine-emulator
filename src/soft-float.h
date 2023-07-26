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

#ifndef SOFT_FLOAT_H
#define SOFT_FLOAT_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "compiler-defines.h"
#include "riscv-constants.h"
#include "uint128.h"

namespace cartesi {

/// \brief Returns the number of leading 0-bits in x, starting at the most significant bit position.
/// \details If x is 0, the result is size of UINT in bits.
template <typename UINT>
static inline int clz(UINT x);

template <>
inline int clz(uint32_t x) {
    return x == 0 ? 32 : __builtin_clz(x);
}

template <>
inline int clz(uint64_t x) {
    return x == 0 ? 64 : __builtin_clzll(x);
}

/// \brief Retrieves an unsigned type with double width.
template <typename U>
struct make_long_uint {};

template <>
struct make_long_uint<uint32_t> {
    using type = uint64_t;
};

template <>
struct make_long_uint<uint64_t> {
    using type = uint128_t;
};

/// \brief Compute multiplication of a * b.
/// \param plow is used to store the high bits of the result.
/// \returns The high bits of the result.
template <typename UINT>
static inline UINT mul_u(UINT *plow, UINT a, UINT b) {
    using ULONG = typename make_long_uint<UINT>::type;
    constexpr int UINT_SIZE = sizeof(UINT) * 8;
    ULONG r = static_cast<ULONG>(a) * static_cast<ULONG>(b);
    *plow = static_cast<UINT>(r);
    return static_cast<UINT>(r >> UINT_SIZE);
}

/// \brief Compute division and remainder of a / b, with a = (ah << UINT_SIZE) | al.
/// \param pr is used to store the remainder.
/// \returns the quotient.
template <typename UINT>
static inline UINT divrem_u(UINT *pr, UINT ah, UINT al, UINT b) {
    using ULONG = typename make_long_uint<UINT>::type;
    constexpr int UINT_SIZE = sizeof(UINT) * 8;
    ULONG a = (static_cast<ULONG>(ah) << UINT_SIZE) | al;
    *pr = static_cast<UINT>(a % b);
    return static_cast<UINT>(a / b);
}

/// \brief Compute sqrt(a) with a = ah*2^UINT_SIZE+al and a < 2^(UINT_SIZE - 2).
/// \param pr is used to store the result.
/// \returns true if not an exact square.
template <typename UINT>
static inline bool sqrtrem_u(UINT *pr, UINT ah, UINT al) {
    using ULONG = typename make_long_uint<UINT>::type;
    constexpr int UINT_SIZE = sizeof(UINT) * 8;
    int l = 0;
    // 2^l >= a
    if (ah != 0) {
        l = 2 * UINT_SIZE - clz(ah - 1);
    } else {
        // This branch will actually never be taken,
        // because at this moment sqrtrem_u() is only called by sqrt() which makes sure that ah > 0
        // LCOV_EXCL_START
        if (al == 0) {
            *pr = 0;
            return false;
        }
        l = UINT_SIZE - clz(al - 1);
        // LCOV_EXCL_STOP
    }
    ULONG a = (static_cast<ULONG>(ah) << UINT_SIZE) | al;
    ULONG u = static_cast<ULONG>(1) << ((l + 1) / 2);
    ULONG s = 0;
    do {
        s = u;
        u = ((a / s) + s) / 2;
    } while (u < s);
    *pr = static_cast<UINT>(s);
    return (a - s * s) != 0;
}

/// \class i_sfloat
/// \brief Interface for software floating-point operations.
/// \tparam T Unsigned integer type used to store the float binary representation.
/// \tparam MANT Width of mantissa, in bits.
/// \tparam EXP Width of exponent, in bits.
template <typename T, int MANT, int EXP>
struct i_sfloat {
    using F_UINT = T;

    /// \brief soft float constants
    enum SFLOAT_constants : int {
        MANT_SIZE = MANT,
        EXP_SIZE = EXP,
        F_SIZE = sizeof(F_UINT) * 8,
        IMANT_SIZE = (F_SIZE - 2), // internal mantissa size
        RND_SIZE = (IMANT_SIZE - MANT_SIZE)
    };

    /// \brief soft float masks
    enum SFLOAT_masks : F_UINT {
        EXP_MASK = ((static_cast<F_UINT>(1) << EXP_SIZE) - 1),
        MANT_MASK = ((static_cast<F_UINT>(1) << MANT_SIZE) - 1),
        SIGN_MASK = (static_cast<F_UINT>(1) << (F_SIZE - 1)),
        QNAN_MASK = (static_cast<F_UINT>(1) << (MANT_SIZE - 1)),
        F_QNAN = ((EXP_MASK << MANT_SIZE) | (static_cast<F_UINT>(1) << (MANT_SIZE - 1)))
    };

    /// \brief Packs a float to its binary representation.
    static inline F_UINT pack(uint32_t a_sign, uint32_t a_exp, F_UINT a_mant) {
        return (static_cast<F_UINT>(a_sign) << (F_SIZE - 1)) | (static_cast<F_UINT>(a_exp) << MANT_SIZE) |
            (a_mant & MANT_MASK);
    }

    /// \brief Unpacks a float from its binary representation.
    static inline F_UINT unpack(uint32_t *pa_sign, int32_t *pa_exp, F_UINT a) {
        *pa_sign = a >> (F_SIZE - 1);
        *pa_exp = (a >> MANT_SIZE) & EXP_MASK;
        return a & MANT_MASK;
    }

    /// \brief Right shift that takes rounding in account, used for adjust mantissa.
    static inline F_UINT mant_rshift_rnd(F_UINT a, int d) {
        if (d != 0) {
            if (d >= F_SIZE) {
                return (a != 0);
            } else {
                F_UINT mask = (static_cast<F_UINT>(1) << d) - 1;
                return (a >> d) | ((a & mask) != 0);
            }
        }
        return a;
    }

    /// \brief Normalizes mantissa of a subnormal float.
    static inline F_UINT mant_normalize_subnormal(int32_t *pa_exp, F_UINT a_mant) {
        int shift = MANT_SIZE - ((F_SIZE - 1 - clz(a_mant)));
        *pa_exp = 1 - shift;
        return a_mant << shift;
    }

    /// \brief Packs a float to its final binary representation, rounding as necessary.
    /// \details a_mant is considered to have its MSB at F_SIZE - 2 bits
    static inline F_UINT round_pack(uint32_t a_sign, int a_exp, F_UINT a_mant, FRM_modes rm, uint32_t *pfflags) {
        uint32_t addend = 0;
        switch (rm) {
            case FRM_RNE:
            case FRM_RMM:
                addend = (1 << (RND_SIZE - 1));
                break;
            case FRM_RTZ:
                addend = 0;
                break;
            default:
            case FRM_RDN:
            case FRM_RUP:
                if (a_sign ^ (rm & 1)) {
                    addend = (1 << RND_SIZE) - 1;
                } else {
                    addend = 0;
                }
                break;
        }
        int rnd_bits = 0;
        // potentially subnormal
        if (a_exp <= 0) {
            // Note: we set the underflow flag if the rounded result
            // is subnormal and inexact
            bool is_subnormal = (a_exp < 0 || (a_mant + addend) < (static_cast<F_UINT>(1) << (F_SIZE - 1)));
            int diff = 1 - a_exp;
            a_mant = mant_rshift_rnd(a_mant, diff);
            rnd_bits = a_mant & ((1 << RND_SIZE) - 1);
            if (is_subnormal && rnd_bits != 0) {
                *pfflags |= FFLAGS_UF_MASK;
            }
            a_exp = 1;
        } else {
            rnd_bits = a_mant & ((1 << RND_SIZE) - 1);
        }
        if (rnd_bits != 0) {
            *pfflags |= FFLAGS_NX_MASK;
        }
        a_mant = (a_mant + addend) >> RND_SIZE;
        // half way: select even result
        if (rm == FRM_RNE && rnd_bits == (1 << (RND_SIZE - 1))) {
            a_mant &= ~static_cast<F_UINT>(1);
        }
        // note the rounding adds at least 1, so this is the maximum value
        a_exp += a_mant >> (MANT_SIZE + 1);
        if (a_mant <= MANT_MASK) {
            // denormalized or zero
            a_exp = 0;
        } else if (a_exp >= static_cast<int>(EXP_MASK)) {
            // overflow
            if (addend == 0) {
                a_exp = EXP_MASK - 1;
                a_mant = MANT_MASK;
            } else { // infinity
                a_exp = EXP_MASK;
                a_mant = 0;
            }
            *pfflags |= FFLAGS_OF_MASK | FFLAGS_NX_MASK;
        }
        return pack(a_sign, a_exp, a_mant);
    }

    /// \brief Normalizes a float to its final binary representation, shifting and rounding as necessary.
    /// \details a_mant is considered to have at most F_SIZE - 1 bits
    static inline F_UINT normalize(uint32_t a_sign, int a_exp, F_UINT a_mant, FRM_modes rm, uint32_t *pfflags) {
        int shift = clz(a_mant) - (F_SIZE - 1 - IMANT_SIZE);
        assert(shift >= 0); // LCOV_EXCL_LINE
        a_exp -= shift;
        a_mant <<= shift;
        return round_pack(a_sign, a_exp, a_mant, rm, pfflags);
    }

    /// \brief Same as normalize() but with a double word mantissa.
    /// \details a_mant1 is considered to have at most F_SIZE - 1 bits
    static inline F_UINT normalize2(uint32_t a_sign, int a_exp, F_UINT a_mant1, F_UINT a_mant0, FRM_modes rm,
        uint32_t *pfflags) {
        int l = 0;
        if (a_mant1 == 0) {
            l = F_SIZE + clz(a_mant0);
        } else {
            l = clz(a_mant1);
        }
        int shift = l - (F_SIZE - 1 - IMANT_SIZE);
        assert(shift >= 0); // LCOV_EXCL_LINE
        a_exp -= shift;
        if (shift == 0) {
            a_mant1 |= (a_mant0 != 0);
        } else if (shift < F_SIZE) {
            a_mant1 = (a_mant1 << shift) | (a_mant0 >> (F_SIZE - shift));
            a_mant0 <<= shift;
            a_mant1 |= (a_mant0 != 0);
        } else {
            a_mant1 = a_mant0 << (shift - F_SIZE);
        }
        return round_pack(a_sign, a_exp, a_mant1, rm, pfflags);
    }

    /// \brief Checks if a float is a signaling-NaN.
    static inline bool issignan(F_UINT a) {
        uint32_t a_exp1 = (a >> (MANT_SIZE - 1)) & ((1 << (EXP_SIZE + 1)) - 1);
        F_UINT a_mant = a & MANT_MASK;
        return a_exp1 == (2 * EXP_MASK) && a_mant != 0;
    }

    /// \brief Checks if a float is a NaN.
    static inline bool isnan(F_UINT a) {
        uint32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        return a_exp == EXP_MASK && a_mant != 0;
    }

    /// \brief Addition operation.
    static F_UINT add(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        // swap so that  abs(a) >= abs(b)
        if ((a & ~SIGN_MASK) < (b & ~SIGN_MASK)) {
            F_UINT tmp = a;
            a = b;
            b = tmp;
        }
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        uint32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        uint32_t b_exp = (b >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = (a & MANT_MASK) << 3;
        F_UINT b_mant = (b & MANT_MASK) << 3;
        if (unlikely(a_exp == EXP_MASK)) {
            if (a_mant != 0) { // NaN result
                if (!(a_mant & (QNAN_MASK << 3)) || issignan(b)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else if (b_exp == EXP_MASK && a_sign != b_sign) {
                *pfflags |= FFLAGS_NV_MASK;
                return F_QNAN;
            } else { // infinity
                return a;
            }
        }
        if (a_exp == 0) {
            a_exp = 1;
        } else {
            a_mant |= static_cast<F_UINT>(1) << (MANT_SIZE + 3);
        }
        if (b_exp == 0) {
            b_exp = 1;
        } else {
            b_mant |= static_cast<F_UINT>(1) << (MANT_SIZE + 3);
        }
        b_mant = mant_rshift_rnd(b_mant, a_exp - b_exp);
        if (a_sign == b_sign) {
            // same signs : add the absolute values
            a_mant += b_mant;
        } else {
            // different signs : subtract the absolute values
            a_mant -= b_mant;
            if (a_mant == 0) {
                // zero result : the sign needs a specific handling
                a_sign = (rm == FRM_RDN);
            }
        }
        a_exp += (RND_SIZE - 3);
        return normalize(a_sign, a_exp, a_mant, rm, pfflags);
    }

    /// \brief Multiply operation.
    static F_UINT mul(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        uint32_t r_sign = a_sign ^ b_sign;
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        int32_t b_exp = (b >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        F_UINT b_mant = b & MANT_MASK;
        if (unlikely(a_exp == EXP_MASK || b_exp == EXP_MASK)) {
            if (isnan(a) || isnan(b)) {
                if (issignan(a) || issignan(b)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else { // infinity
                if ((a_exp == EXP_MASK && (b_exp == 0 && b_mant == 0)) ||
                    (b_exp == EXP_MASK && (a_exp == 0 && a_mant == 0))) {
                    *pfflags |= FFLAGS_NV_MASK;
                    return F_QNAN;
                } else {
                    return pack(r_sign, EXP_MASK, 0);
                }
            }
        }
        if (a_exp == 0) {
            if (a_mant == 0) { // zero
                return pack(r_sign, 0, 0);
            }
            a_mant = mant_normalize_subnormal(&a_exp, a_mant);
        } else {
            a_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        if (b_exp == 0) {
            if (b_mant == 0) { // zero
                return pack(r_sign, 0, 0);
            }
            b_mant = mant_normalize_subnormal(&b_exp, b_mant);
        } else {
            b_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        int32_t r_exp = a_exp + b_exp - (1 << (EXP_SIZE - 1)) + 2;
        F_UINT r_mant_low = 0;
        F_UINT r_mant = mul_u(&r_mant_low, a_mant << RND_SIZE, b_mant << (RND_SIZE + 1));
        r_mant |= (r_mant_low != 0);
        return normalize(r_sign, r_exp, r_mant, rm, pfflags);
    }

    /// \brief Fused multiply and add operation.
    static F_UINT fma(F_UINT a, F_UINT b, F_UINT c, FRM_modes rm, uint32_t *pfflags) {
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        uint32_t c_sign = c >> (F_SIZE - 1);
        uint32_t r_sign = a_sign ^ b_sign;
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        int32_t b_exp = (b >> MANT_SIZE) & EXP_MASK;
        int32_t c_exp = (c >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        F_UINT b_mant = b & MANT_MASK;
        F_UINT c_mant = c & MANT_MASK;
        if (unlikely(a_exp == EXP_MASK || b_exp == EXP_MASK || c_exp == EXP_MASK)) {
            // The fused multiply-add instructions must set the invalid operation exception flag
            // when the multiplicands are infinite and zero, even when the addend is a quiet NaN.
            if (((a_exp == EXP_MASK && a_mant == 0) && (b_exp == 0 && b_mant == 0)) ||
                ((b_exp == EXP_MASK && b_mant == 0) && (a_exp == 0 && a_mant == 0))) {
                *pfflags |= FFLAGS_NV_MASK;
                return F_QNAN;
            }
            if (isnan(a) || isnan(b) || isnan(c)) {
                if (issignan(a) || issignan(b) || issignan(c)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else { // infinities
                if ((a_exp == EXP_MASK || b_exp == EXP_MASK) && (c_exp == EXP_MASK && r_sign != c_sign)) {
                    *pfflags |= FFLAGS_NV_MASK;
                    return F_QNAN;
                } else if (c_exp == EXP_MASK) {
                    return pack(c_sign, EXP_MASK, 0);
                } else {
                    return pack(r_sign, EXP_MASK, 0);
                }
            }
        }
        if ((a_exp == 0 && a_mant == 0) || (b_exp == 0 && b_mant == 0)) {
            if (c_exp == 0 && c_mant == 0) {
                if (c_sign != r_sign) {
                    r_sign = (rm == FRM_RDN);
                }
                return pack(r_sign, 0, 0);
            } else {
                return c;
            }
        }
        if (a_exp == 0) {
            a_mant = mant_normalize_subnormal(&a_exp, a_mant);
        } else {
            a_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        if (b_exp == 0) {
            b_mant = mant_normalize_subnormal(&b_exp, b_mant);
        } else {
            b_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        // multiply
        int32_t r_exp = a_exp + b_exp - (1 << (EXP_SIZE - 1)) + 3;
        F_UINT r_mant0 = 0;
        F_UINT r_mant1 = mul_u(&r_mant0, a_mant << RND_SIZE, b_mant << RND_SIZE);
        // normalize to F_SIZE - 3
        if (r_mant1 < (static_cast<F_UINT>(1) << (F_SIZE - 3))) {
            r_mant1 = (r_mant1 << 1) | (r_mant0 >> (F_SIZE - 1));
            r_mant0 <<= 1;
            r_exp--;
        }
        // add
        if (c_exp == 0) {
            if (c_mant == 0) {
                // add zero
                r_mant1 |= (r_mant0 != 0);
                return normalize(r_sign, r_exp, r_mant1, rm, pfflags);
            }
            c_mant = mant_normalize_subnormal(&c_exp, c_mant);
        } else {
            c_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        c_exp++;
        F_UINT c_mant1 = c_mant << (RND_SIZE - 1);
        F_UINT c_mant0 = 0;
        // ensure that abs(r) >= abs(c)
        if (!(r_exp > c_exp || (r_exp == c_exp && r_mant1 >= c_mant1))) {
            // swap
            F_UINT tmp = r_mant1;
            r_mant1 = c_mant1;
            c_mant1 = tmp;
            tmp = r_mant0;
            r_mant0 = c_mant0;
            c_mant0 = tmp;
            int32_t c_tmp = r_exp;
            r_exp = c_exp;
            c_exp = c_tmp;
            c_tmp = static_cast<int32_t>(r_sign);
            r_sign = c_sign;
            c_sign = static_cast<uint32_t>(c_tmp);
        }
        // right shift c_mant
        int32_t shift = r_exp - c_exp;
        if (shift >= 2 * F_SIZE) {
            c_mant0 = (c_mant0 | c_mant1) != 0;
            c_mant1 = 0;
        } else if (shift >= F_SIZE + 1) {
            c_mant0 = mant_rshift_rnd(c_mant1, shift - F_SIZE);
            c_mant1 = 0;
        } else if (shift == F_SIZE) {
            c_mant0 = c_mant1 | (c_mant0 != 0);
            c_mant1 = 0;
        } else if (shift != 0) {
            F_UINT mask = (static_cast<F_UINT>(1) << shift) - 1;
            c_mant0 = (c_mant1 << (F_SIZE - shift)) | (c_mant0 >> shift) | ((c_mant0 & mask) != 0);
            c_mant1 = c_mant1 >> shift;
        }
        // add or subtract
        if (r_sign == c_sign) {
            r_mant0 += c_mant0;
            r_mant1 += c_mant1 + (r_mant0 < c_mant0);
        } else {
            F_UINT tmp = r_mant0;
            r_mant0 -= c_mant0;
            r_mant1 = r_mant1 - c_mant1 - (r_mant0 > tmp);
            if ((r_mant0 | r_mant1) == 0) {
                // zero result : the sign needs a specific handling
                r_sign = (rm == FRM_RDN);
            }
        }
        return normalize2(r_sign, r_exp, r_mant1, r_mant0, rm, pfflags);
    }

    /// \brief Division operation.
    static F_UINT div(F_UINT a, F_UINT b, FRM_modes rm, uint32_t *pfflags) {
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        uint32_t r_sign = a_sign ^ b_sign;
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        int32_t b_exp = (b >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        F_UINT b_mant = b & MANT_MASK;
        if (unlikely(a_exp == EXP_MASK)) {
            if (a_mant != 0 || isnan(b)) {
                if (issignan(a) || issignan(b)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else if (b_exp == EXP_MASK) {
                *pfflags |= FFLAGS_NV_MASK;
                return F_QNAN;
            } else {
                return pack(r_sign, EXP_MASK, 0);
            }
        } else if (unlikely(b_exp == EXP_MASK)) {
            if (b_mant != 0) {
                if (issignan(b)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else {
                return pack(r_sign, 0, 0);
            }
        }
        if (b_exp == 0) {
            if (unlikely(b_mant == 0)) { // zero
                if (a_exp == 0 && a_mant == 0) {
                    *pfflags |= FFLAGS_NV_MASK;
                    return F_QNAN;
                } else {
                    *pfflags |= FFLAGS_DZ_MASK;
                    return pack(r_sign, EXP_MASK, 0);
                }
            }
            b_mant = mant_normalize_subnormal(&b_exp, b_mant);
        } else {
            b_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        if (a_exp == 0) {
            if (a_mant == 0) { // zero
                return pack(r_sign, 0, 0);
            }
            a_mant = mant_normalize_subnormal(&a_exp, a_mant);
        } else {
            a_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        int32_t r_exp = a_exp - b_exp + (1 << (EXP_SIZE - 1)) - 1;
        F_UINT r = 0;
        F_UINT r_mant = divrem_u(&r, a_mant, static_cast<F_UINT>(0), b_mant << 2);
        if (r != 0) {
            r_mant |= 1;
        }
        return normalize(r_sign, r_exp, r_mant, rm, pfflags);
    }

    /// \brief Square root operation.
    static F_UINT sqrt(F_UINT a, FRM_modes rm, uint32_t *pfflags) {
        uint32_t a_sign = a >> (F_SIZE - 1);
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        if (unlikely(a_exp == EXP_MASK)) {
            if (a_mant != 0) {
                if (issignan(a)) {
                    *pfflags |= FFLAGS_NV_MASK;
                }
                return F_QNAN;
            } else if (a_sign) {
                *pfflags |= FFLAGS_NV_MASK;
                return F_QNAN;
            } else { // infinity
                return a;
            }
        }
        if (a_sign) {
            if (likely(a_exp == 0 && a_mant == 0)) { // zero
                return a;
            }
            *pfflags |= FFLAGS_NV_MASK;
            return F_QNAN;
        }
        if (a_exp == 0) {
            if (a_mant == 0) { // zero
                return pack(0, 0, 0);
            }
            a_mant = mant_normalize_subnormal(&a_exp, a_mant);
        } else {
            a_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        a_exp -= EXP_MASK / 2;
        // simpler to handle an even exponent
        if (a_exp & 1) {
            a_exp--;
            a_mant <<= 1;
        }
        a_exp = (a_exp >> 1) + EXP_MASK / 2;
        a_mant <<= (F_SIZE - 4 - MANT_SIZE);
        if (sqrtrem_u(&a_mant, a_mant, static_cast<F_UINT>(0))) {
            a_mant |= 1;
        }
        return normalize(a_sign, a_exp, a_mant, rm, pfflags);
    }

    /// \brief Min/max operation for NaN float.
    static inline F_UINT min_max_nan(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (issignan(a) || issignan(b)) {
            *pfflags |= FFLAGS_NV_MASK;
        }
        if (isnan(a)) {
            if (isnan(b)) {
                return F_QNAN;
            } else {
                return b;
            }
        } else {
            return a;
        }
    }

    /// \brief Min operation.
    static F_UINT min(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (isnan(a) || isnan(b)) {
            return min_max_nan(a, b, pfflags);
        }
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        if (a_sign != b_sign) {
            return a_sign ? a : b;
        } else {
            return ((a < b) ^ a_sign) ? a : b;
        }
    }

    /// \brief Max operation.
    static F_UINT max(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (isnan(a) || isnan(b)) {
            return min_max_nan(a, b, pfflags);
        }
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        if (a_sign != b_sign) {
            return a_sign ? b : a;
        } else {
            return ((a < b) ^ a_sign) ? b : a;
        }
    }

    /// \brief Equal operation.
    static bool eq(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (unlikely(isnan(a) || isnan(b))) {
            if (issignan(a) || issignan(b)) {
                *pfflags |= FFLAGS_NV_MASK;
            }
            return false;
        }
        if (((a | b) << 1) == 0) { // zero case
            return true;
        }
        return a == b;
    }

    /// \brief Less or equal than operation.
    static bool le(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (unlikely(isnan(a) || isnan(b))) {
            *pfflags |= FFLAGS_NV_MASK;
            return false;
        }
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        if (a_sign != b_sign) {
            return a_sign || (((a | b) << 1) == 0);
        } else {
            return a_sign ? (a >= b) : (a <= b);
        }
    }

    /// \brief Less than operation.
    static bool lt(F_UINT a, F_UINT b, uint32_t *pfflags) {
        if (unlikely(isnan(a) || isnan(b))) {
            *pfflags |= FFLAGS_NV_MASK;
            return false;
        }
        uint32_t a_sign = a >> (F_SIZE - 1);
        uint32_t b_sign = b >> (F_SIZE - 1);
        if (a_sign != b_sign) {
            return a_sign && (((a | b) << 1) != 0);
        } else {
            return a_sign ? (a > b) : (a < b);
        }
    }

    /// \brief Retrieves float class.
    static uint32_t fclass(F_UINT a) {
        uint32_t a_sign = a >> (F_SIZE - 1);
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        if (unlikely(a_exp == EXP_MASK)) {
            if (a_mant != 0) {
                return (a_mant & QNAN_MASK) ? FCLASS_QNAN : FCLASS_SNAN;
            } else {
                return a_sign ? FCLASS_NINF : FCLASS_PINF;
            }
        } else if (a_exp == 0) {
            if (a_mant == 0) {
                return a_sign ? FCLASS_NZERO : FCLASS_PZERO;
            } else {
                return a_sign ? FCLASS_NSUBNORMAL : FCLASS_PSUBNORMAL;
            }
        } else {
            return a_sign ? FCLASS_NNORMAL : FCLASS_PNORMAL;
        }
    }

    /// \brief Conversion from float to integer.
    template <typename ICVT_INT>
    static ICVT_INT cvt_f_i(F_UINT a, FRM_modes rm, uint32_t *pfflags) {
        using ICVT_UINT = typename std::make_unsigned<ICVT_INT>::type;
        constexpr bool IS_UNSIGNED = std::is_unsigned<ICVT_INT>::value;
        constexpr int ICVT_SIZE = sizeof(ICVT_UINT) * 8;
        uint32_t a_sign = a >> (F_SIZE - 1);
        int32_t a_exp = (a >> MANT_SIZE) & EXP_MASK;
        F_UINT a_mant = a & MANT_MASK;
        if (a_exp == EXP_MASK && a_mant != 0) {
            a_sign = 0; // NaN is like +infinity
        }
        if (a_exp == 0) {
            a_exp = 1;
        } else {
            a_mant |= static_cast<F_UINT>(1) << MANT_SIZE;
        }
        a_mant <<= RND_SIZE;
        a_exp = a_exp - (EXP_MASK / 2) - MANT_SIZE;
        ICVT_UINT r_max = 0;
        if constexpr (IS_UNSIGNED) {
            r_max = static_cast<ICVT_UINT>(a_sign) - 1;
        } else {
            r_max = (static_cast<ICVT_UINT>(1) << (ICVT_SIZE - 1)) - static_cast<ICVT_UINT>(a_sign ^ 1);
        }
        ICVT_UINT r = 0;
        if (a_exp >= 0) {
            if (likely(a_exp <= (ICVT_SIZE - 1 - MANT_SIZE))) {
                r = static_cast<ICVT_UINT>(a_mant >> RND_SIZE) << a_exp;
                if (unlikely(r > r_max)) {
                    *pfflags |= FFLAGS_NV_MASK;
                    return r_max;
                }
            } else {
                *pfflags |= FFLAGS_NV_MASK;
                return r_max;
            }
        } else {
            a_mant = mant_rshift_rnd(a_mant, -a_exp);
            uint32_t addend = 0;
            switch (rm) {
                case FRM_RNE:
                case FRM_RMM:
                    addend = (1 << (RND_SIZE - 1));
                    break;
                case FRM_RTZ:
                    addend = 0;
                    break;
                default:
                case FRM_RDN:
                case FRM_RUP:
                    if (a_sign ^ (rm & 1)) {
                        addend = (1 << RND_SIZE) - 1;
                    } else {
                        addend = 0;
                    }
                    break;
            }
            uint32_t rnd_bits = a_mant & ((1 << RND_SIZE) - 1);
            a_mant = (a_mant + addend) >> RND_SIZE;
            // half way: select even result
            if (rm == FRM_RNE && rnd_bits == (1 << (RND_SIZE - 1))) {
                a_mant &= ~static_cast<F_UINT>(1);
            }
            if (unlikely(a_mant > r_max)) {
                *pfflags |= FFLAGS_NV_MASK;
                return r_max;
            }
            r = a_mant;
            if (rnd_bits != 0) {
                *pfflags |= FFLAGS_NX_MASK;
            }
        }
        if (a_sign) {
            r = -r;
        }
        return static_cast<ICVT_INT>(r);
    }

    /// \brief Conversion from integer to float.
    template <typename ICVT_INT>
    static F_UINT cvt_i_f(ICVT_INT a, FRM_modes rm, uint32_t *pfflags) {
        using ICVT_UINT = typename std::make_unsigned<ICVT_INT>::type;
        constexpr bool IS_UNSIGNED = std::is_unsigned<ICVT_INT>::value;
        constexpr int ICVT_SIZE = sizeof(ICVT_UINT) * 8;
        uint32_t a_sign = 0;
        ICVT_UINT r = static_cast<ICVT_UINT>(a);
        if constexpr (!IS_UNSIGNED) {
            if (a < 0) {
                a_sign = 1;
                r = -static_cast<ICVT_UINT>(a);
            }
        }
        int32_t a_exp = (EXP_MASK / 2) + F_SIZE - 2;
        // need to reduce range before generic float normalization
        int l = ICVT_SIZE - clz<ICVT_UINT>(r) - (F_SIZE - 1);
        if (l > 0) {
            ICVT_UINT mask = r & ((static_cast<ICVT_UINT>(1) << l) - 1);
            r = (r >> l) | ((r & mask) != 0);
            a_exp += l;
        }
        F_UINT a_mant = r;
        return normalize(a_sign, a_exp, a_mant, rm, pfflags);
    }
};

using i_sfloat32 = i_sfloat<uint32_t, 23, 8>;  // Interface for single-precision floating-point
using i_sfloat64 = i_sfloat<uint64_t, 52, 11>; // Interface for double-precision floating-point

/// \brief Conversion from float32 to float64.
static uint64_t sfloat_cvt_f32_f64(uint32_t a, uint32_t *pfflags) {
    uint32_t a_sign = 0;
    int32_t a_exp = 0;
    i_sfloat64::F_UINT a_mant = i_sfloat32::unpack(&a_sign, &a_exp, a);
    if (unlikely(a_exp == 0xff)) {
        if (a_mant != 0) { // NaN
            if (i_sfloat32::issignan(a)) {
                *pfflags |= FFLAGS_NV_MASK;
            }
            return i_sfloat64::F_QNAN;
        } else { // infinity
            return i_sfloat64::pack(a_sign, i_sfloat64::EXP_MASK, 0);
        }
    }
    if (a_exp == 0) {
        if (a_mant == 0) { // zero
            return i_sfloat64::pack(a_sign, 0, 0);
        }
        a_mant = i_sfloat32::mant_normalize_subnormal(&a_exp, a_mant);
    }
    // convert the exponent value
    a_exp = a_exp - 0x7f + (static_cast<int32_t>(i_sfloat64::EXP_MASK) / 2);
    // shift the mantissa
    a_mant <<= i_sfloat64::MANT_SIZE - 23;
    // we assume the target float is large enough to that no
    // normalization is necessary
    return i_sfloat64::pack(a_sign, a_exp, a_mant);
}

/// \brief Conversion from float64 to float32.
static uint32_t sfloat_cvt_f64_f32(uint64_t a, FRM_modes rm, uint32_t *pfflags) {
    uint32_t a_sign = 0;
    int32_t a_exp = 0;
    i_sfloat64::F_UINT a_mant = i_sfloat64::unpack(&a_sign, &a_exp, a);
    if (unlikely(a_exp == i_sfloat64::EXP_MASK)) {
        if (a_mant != 0) { // nan
            if (i_sfloat64::issignan(a)) {
                *pfflags |= FFLAGS_NV_MASK;
            }
            return i_sfloat32::F_QNAN;
        } else { // infinity
            return i_sfloat32::pack(a_sign, 0xff, 0);
        }
    }
    if (a_exp == 0) {
        if (a_mant == 0) { // zero
            return i_sfloat32::pack(a_sign, 0, 0);
        }
        i_sfloat64::mant_normalize_subnormal(&a_exp, a_mant);
    } else {
        a_mant |= static_cast<i_sfloat64::F_UINT>(1) << i_sfloat64::MANT_SIZE;
    }
    // convert the exponent value
    a_exp = a_exp - (static_cast<int32_t>(i_sfloat64::EXP_MASK) / 2) + 0x7f;
    // shift the mantissa
    a_mant = i_sfloat64::mant_rshift_rnd(a_mant, i_sfloat64::MANT_SIZE - (32 - 2));
    return i_sfloat32::normalize(a_sign, a_exp, a_mant, rm, pfflags);
}

} // namespace cartesi

#endif
