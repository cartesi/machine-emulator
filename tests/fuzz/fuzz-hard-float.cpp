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
/// \brief libFuzzer harness for the hard-float fast path.
///
/// Each input decodes an operation, a rounding mode, initial fflags, and up to three
/// operands, then asserts that the hard-float implementation (host FPU with guards and
/// soft-float fallback) produces exactly the soft-float result bits and fflags. Aborts
/// on the first divergence. Header-only, no libcartesi needed.
///
/// Input layout: [op] [rm] [fflags] [a:8] [b:8] [c:8]

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <hard-float.hpp>
#include <soft-float.hpp>

using namespace cartesi;

template <typename SFLOAT, typename HFLOAT>
static void check(int op, FRM_modes rm, uint32_t fflags, uint64_t a64, uint64_t b64, uint64_t c64) {
    using U = SFLOAT::F_UINT;
    const auto a = static_cast<U>(a64);
    const auto b = static_cast<U>(b64);
    const auto c = static_cast<U>(c64);
    uint32_t fs = fflags;
    uint32_t fh = fflags;
    U rs = 0;
    U rh = 0;
    switch (op) {
        case 0:
            rs = SFLOAT::add(a, b, rm, &fs);
            rh = HFLOAT::add(a, b, rm, &fh);
            break;
        case 1:
            rs = SFLOAT::mul(a, b, rm, &fs);
            rh = HFLOAT::mul(a, b, rm, &fh);
            break;
        case 2:
            rs = SFLOAT::div(a, b, rm, &fs);
            rh = HFLOAT::div(a, b, rm, &fh);
            break;
        case 3:
            rs = SFLOAT::sqrt(a, rm, &fs);
            rh = HFLOAT::sqrt(a, rm, &fh);
            break;
        default:
            rs = SFLOAT::fma(a, b, c, rm, &fs);
            rh = HFLOAT::fma(a, b, c, rm, &fh);
            break;
    }
    if (rs != rh || fs != fh) {
        (void) std::fprintf(stderr,
            "hard-float divergence: op=%d rm=%d fflags=%02" PRIx32 " a=%016" PRIx64 " b=%016" PRIx64 " c=%016" PRIx64
            " soft=%016" PRIx64 "/%02" PRIx32 " hard=%016" PRIx64 "/%02" PRIx32 "\n",
            op, static_cast<int>(rm), fflags, a64, b64, c64, static_cast<uint64_t>(rs), fs, static_cast<uint64_t>(rh),
            fh);
        std::abort();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    constexpr size_t NEED = 3 + (3 * sizeof(uint64_t));
    if (size < NEED) {
        return 0;
    }
    const hard_float_scope scope;
    const int op = data[0] % 10;
    const auto rm = static_cast<FRM_modes>(data[1] % 5);
    const auto fflags = static_cast<uint32_t>(data[2] & FCSR_FFLAGS_RW_MASK);
    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t c = 0;
    std::memcpy(&a, &data[3], sizeof(a));
    std::memcpy(&b, &data[3 + sizeof(a)], sizeof(b));
    std::memcpy(&c, &data[3 + (2 * sizeof(a))], sizeof(c));
    if (op < 5) {
        check<i_sfloat64, i_float64>(op, rm, fflags, a, b, c);
    } else {
        check<i_sfloat32, i_float32>(op - 5, rm, fflags, a, b, c);
    }
    return 0;
}
