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
/// \brief Cartesi machine emulator C API grpc related interface


#ifndef CM_GRPC_C_API_H
#define CM_GRPC_C_API_H

#ifndef __cplusplus

#include <stdbool.h>

#endif

#include "machine-c-defines.h"
#include "machine-c-api.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Semantic version
typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    const char *pre_release;
    const char *build;
} cm_semantic_version;

/// \brief Create remote machine instance
/// \param config Machine configuration. Must be pointer to valid object
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param address Address of the remote grpc Cartesi machine server
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_create_grpc_machine(const cm_machine_config *config, const cm_machine_runtime_config *runtime_config,
                                  const char *address, cm_machine **new_machine, char **err_msg);

/// \brief Create remote machine instance from previously serialized directory
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param address Address of the remote grpc Cartesi machine server
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_load_grpc_machine(const char *dir, const cm_machine_runtime_config *runtime_config,
                                const char *address, cm_machine **new_machine, char **err_msg);


/// \brief Ged default machine config from server
/// \param address Address of the remote grpc Cartesi machine server
/// \param config Receives the default configuration
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_grpc_get_default_config(const char *address, const cm_machine_config **config, char **err_msg);


/// \brief Checks the internal consistency of an access log
/// \param address Address of the remote grpc Cartesi machine server
/// \param log State access log to be verified.
/// \param one_based Use 1-based indices when reporting errors.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_grpc_verify_access_log(const char *address, const cm_access_log *log, bool one_based, char **err_msg);

/// \brief Checks the validity of a state transition
/// \param address Address of the remote grpc Cartesi machine server
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_verify_state_transition(const char *address, const cm_hash *root_hash_before,
                                           const cm_access_log *log, const cm_hash *root_hash_after,
                                           bool one_based, char **err_msg);

/// \brief Gets the address of a general-purpose register from remote cartesi server
/// \param address Address of the remote grpc Cartesi machine server
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_get_x_address(const char *address, int i, uint64_t *val, char **err_msg);


/// \brief Gets the address of any CSR from remote server
/// \param address Address of the remote grpc Cartesi machine server
/// \param w The command and status register
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_get_csr_address(const char *address, CM_PROC_CSR w, uint64_t *val, char **err_msg);

/// \brief  Gets the address of a DHD h register from remote server
/// \param address Address of the remote grpc Cartesi machine server
/// \param i Register index. Between 0 and DHD_H_REG_COUNT-1, inclusive
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
int cm_grpc_dhd_h_address(const char *address, int i, uint64_t *val, char **err_msg);

/// \brief Gets the semantic version of remote server machine
/// \param address Address of the remote grpc Cartesi machine server
/// \param version Receives semantic version
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
int cm_grpc_get_version(const char *address, cm_semantic_version *version, char **err_msg);

/// \brief Performs shutdown
/// \param address Address of the remote grpc Cartesi machine server
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
int cm_grpc_shutdown(const char *address, char **err_msg);

#ifdef __cplusplus
}
#endif

#endif //CM_GRPC_C_API_H