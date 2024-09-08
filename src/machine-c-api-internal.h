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

void cm_set_last_error_message(const std::string &err_msg);

/// \brief Helper function that returns error result from C api function
int cm_result_failure();

/// \brief Helper function that returns success result from C api function
int cm_result_success();

/// \brief Helper function that copies a C++ string over to C string buffer
char *string_to_buf(char *dest, size_t maxlen, const std::string &src);

/// \brief Helper function that create empty string in case that C string is NULL
std::string null_to_empty(const char *s);

/// \brief Helper function converts a semantic version to C api structure
cm_semantic_version *convert_to_c(const cartesi::semantic_version &cpp_version);

/// \brief Helper function that parses hash from C api structure
cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash *c_hash);

/// \brief Helper function that parses access log type from C
cartesi::access_log::type convert_from_c(const cm_access_log_type *type);

/// \brief Helper function that parses access log from C api structure
cm_access_log *convert_to_c(const cartesi::access_log &cpp_access_log);

/// \brief Helper function converts access log to C api structure
cartesi::access_log convert_from_c(const cm_access_log *c_acc_log);

/// \brief Helper function converts C++ string to allocated C string
char *convert_to_c(const std::string &cpp_str);

#endif // CM_C_API_INTERNAL_H
