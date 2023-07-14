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

#ifndef MACHINE_EMULATOR_SDK_MACHINE_C_DEFINES_H
#define MACHINE_EMULATOR_SDK_MACHINE_C_DEFINES_H

// Compiler visibility definition
#ifndef CM_API
#define CM_API __attribute__((visibility("default"))) // NOLINT(cppcoreguidelines-macro-usage)
#endif

#define CM_MACHINE_HASH_BYTE_SIZE 32    // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_MACHINE_X_REG_COUNT 32       // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_MACHINE_F_REG_COUNT 32       // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_MACHINE_UARCH_X_REG_COUNT 32 // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)

#define CM_TREE_LOG2_WORD_SIZE 3          // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_TREE_LOG2_PAGE_SIZE 12         // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_TREE_LOG2_ROOT_SIZE 64         // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)
#define CM_FLASH_DRIVE_CONFIGS_MAX_SIZE 8 // NOLINT(cppcoreguidelines-macro-usage, modernize-macro-to-enum)

#include "machine-c-version.h"

#endif // MACHINE_EMULATOR_SDK_MACHINE_C_DEFINES_H
