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

#include <string>

/// \brief Helper function that returns error result from C api function
int cm_result_failure(char **err_msg);

/// \brief Helper function that returns success result from C api function
int cm_result_success(char **err_msg);


/// \brief Helper function that returns unknown error result from
/// C api function
int cm_result_unknown_error(char **err_msg);


/// \brief Helper function that create empty string in case
/// that C string is NULL
std::string null_to_empty(const char *s);


/// \brief Helper function that parses machine configuration cartesi::machine_config
/// from C api structure cm_machine_config
cartesi::machine_config convert_from_c(const cm_machine_config *c_config);

/// \brief Helper function that parses machine runtime configuration
/// from C api structure cm_machine_runtime_config
cartesi::machine_runtime_config convert_from_c(const cm_machine_runtime_config *c_config);