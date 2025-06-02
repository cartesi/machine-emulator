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

#ifndef COMPILER_DEFINES_H
#define COMPILER_DEFINES_H

// NOLINTBEGIN(cppcoreguidelines-macro-usage)

#ifndef CODE_COVERAGE
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
// Avoid using always_inline attribute when code coverage is enabled,
// because it makes code coverage results harder to read
#define FORCE_INLINE inline
#endif

#define NO_INLINE __attribute__((noinline))

#define NO_RETURN [[noreturn]]

// These macros are used only in very hot code paths (such as TLB hit checks).
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define PACKED __attribute__((packed))

// Helper macros for stringification
#define TO_STRING_HELPER(X) #X
#define TO_STRING(X) TO_STRING_HELPER(X)

// Define loop unrolling depending on the compiler
#if defined(__clang__)
#define UNROLL_LOOP(n) _Pragma(TO_STRING(unroll(n)))
#define UNROLL_LOOP_FULL(n) _Pragma(TO_STRING(unroll))
#elif defined(__GNUC__) && !defined(__clang__)
#define UNROLL_LOOP(n) _Pragma(TO_STRING(GCC unroll(n)))
#define UNROLL_LOOP_FULL(n) _Pragma(TO_STRING(GCC unroll(65534)))
#else
#define UNROLL_LOOP(n)
#define UNROLL_LOOP_FULL(n)
#endif

#if defined(__GNUC__) && defined(__amd64__) && !defined(NO_MULTIVERSIONING)
#define USE_MULTIVERSINING_AMD64
#define MULTIVERSION_GENERIC __attribute__((target("default")))
#define MULTIVERSION_AMD64_AVX2_BMI_BMI2 __attribute__((target("avx2,bmi,bmi2")))
#define MULTIVERSION_AMD64_AVX512_BMI_BMI2 __attribute__((target("avx512f,avx512vl,bmi,bmi2")))
#define MULTIVERSION_AMD64_AVX2 __attribute__((target("avx2")))
#define MULTIVERSION_AMD64_AVX512 __attribute__((target("avx512f,avx512vl")))
#else
#define MULTIVERSION_GENERIC __attribute__((noinline))
#endif

// NOLINTEND(cppcoreguidelines-macro-usage)

#endif
