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

extern "C" {

// Mongoose log is disabled because it generates code using __FILE__ macro,
// which is reported as an error when packaging in some Linux distributions.
#ifdef NDEBUG
#define MG_ENABLE_LOG 0 // NOLINT(cppcoreguidelines-macro-usage)
#endif

// Disable some features we don't need
#define MG_ENABLE_MD5 0 // NOLINT(cppcoreguidelines-macro-usage)

#include <mongoose.c> // NOLINT(bugprone-suspicious-include)
}
