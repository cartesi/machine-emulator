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

#ifndef CM_C_API_INTERNAL_H
#define CM_C_API_INTERNAL_H

#include <string>

#include "access-log.h"
#include "machine-c-api.h"
#include "machine-config.h"
#include "machine-merkle-tree.h"
#include "machine-runtime-config.h"
#include "semantic-version.h"

/// \brief Helper function that returns error result from C api function
cm_error cm_result_failure();

/// \brief Helper function that returns success result from C api function
cm_error cm_result_success();

/// \brief Helper function that parses hash from C api structure
cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash *c_hash);

#endif // CM_C_API_INTERNAL_H
