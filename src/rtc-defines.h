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

#ifndef RTC_DEFINES_H
#define RTC_DEFINES_H
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

/// \brief Number of cycles between RTC ticks
/// Changing this value affects the machine state hash
/// Higher values decrease the performance of the interactive machine emulator
/// Using base 2 values optimizes division and multiplications in the interpreter loop
#ifndef RTC_FREQ_DIV_DEF
#define RTC_FREQ_DIV_DEF 8192
#endif

/// \brief Arbitrary CPU clock frequency.
/// We have to make sure the clock frequency is divisible by RTC_FREQ_DIV_DEF and 10^6
/// Overridable for clock-ratio experiments (tail-call.md item 19): the guest
/// clock is a function of mcycle, so the advertised frequency sets how many
/// guest-seconds -- and therefore kernel timer ticks -- a given instruction
/// count spans. Default raised 128 MHz to 1024 MHz (2026-08-21): with the
/// SUM-toggle flush storm fixed by the context-partitioned TLB, the
/// remeasured tick cost was a consistent ~4 percent across the balanced
/// board (nop -15, regs -8, tree -7), with stock and copy-patch builds
/// bit-identical to each other at the new clock. Machine state hashes
/// change with this value (the DTB advertises timebase-frequency), so all
/// fixed-cycle references recorded before this date used 128 MHz.
#ifndef RTC_CLOCK_FREQ_DEF
#define RTC_CLOCK_FREQ_DEF 1024000000 ///< 1024 MHz frequency
#endif
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: RTC_DEFINES_H */
