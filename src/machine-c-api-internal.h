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

#include "machine-c-api.h"

/// \brief Helper function that returns error result from C api function
CM_API cm_error cm_result_failure();

/// \brief Helper function that returns success result from C api function
CM_API cm_error cm_result_success();

/// \brief Helper function that stores a string to a temporary thread local.
CM_API const char *cm_set_temp_string(const std::string &s);

#endif // CM_C_API_INTERNAL_H
