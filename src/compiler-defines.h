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
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define likely(x) __builtin_expect((x), 1)
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define unlikely(x) __builtin_expect((x), 0)
//??E Although using PGO (Profile Guided Optimizations) makes use of these macros unneeded,
//    using them allows for more performance without the need to compile with PGO,
//    useful when doing benchmark of code changes.

#define PACKED __attribute__((packed))

#endif
