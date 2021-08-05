// Copyright 2021 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

/// \file
/// \brief Cartesi machine emulator C API interface helper functions
/// meant use internally inside cartesi library

#ifndef CM_C_API_INTERNAL_H
#define CM_C_API_INTERNAL_H

#include <string>
#include "machine-c-defines.h"

#include "machine-c-defines.h"
#include "machine-c-api.h"
#include "machine.h"

/// \brief Helper function that returns error result from C api function
CM_API int cm_result_failure(char **err_msg);

/// \brief Helper function that returns success result from C api function
CM_API int cm_result_success(char **err_msg);


/// \brief Helper function that returns unknown error result from
/// C api function
CM_API int cm_result_unknown_error(char **err_msg);


/// \brief Helper function that create empty string in case
/// that C string is NULL
CM_API std::string null_to_empty(const char *s);


/// \brief Helper function that parses machine configuration cartesi::machine_config
/// from C api structure cm_machine_config
CM_API cartesi::machine_config convert_from_c(const cm_machine_config *c_config);

/// \brief Helper function that parses machine runtime configuration
/// from C api structure cm_machine_runtime_config
CM_API cartesi::machine_runtime_config convert_from_c(const cm_machine_runtime_config *c_config);

/// \brief Helper function converts machine configuration to C api structure
CM_API const cm_machine_config *convert_to_c(const cartesi::machine_config &cpp_config);

/// \brief Helper function that parses hash from C api structure
CM_API cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash* c_hash);

/// \brief Helper function that parses access log tyoe from C
CM_API cartesi::access_log::type convert_from_c(const cm_access_log_type *type);

/// \brief Helper function that parses access log from C api structure
CM_API cm_access_log *convert_to_c(const cartesi::access_log &cpp_access_log);

/// \brief Helper function converts access log to C api structure
CM_API cartesi::access_log convert_from_c(const cm_access_log *c_acc_log);

/// \brief Helper function converts C++ string to allocated C string
CM_API char *convert_to_c(const std::string &cpp_str);

#endif //CM_C_API_INTERNAL_H
