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
#define RTC_FREQ_DIV_DEF 16384

/// \brief Arbitrary CPU clock frequency.
/// We have to make sure the clock frequency is divisible by RTC_FREQ_DIV_DEF and 10^6
#define RTC_CLOCK_FREQ_DEF 256000000 ///< 256 MHz frequency
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: RTC_DEFINES_H */
