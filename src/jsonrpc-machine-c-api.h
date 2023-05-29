// Copyright 2023 Cartesi Pte. Ltd.
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
/// \brief Cartesi machine emulator C API jsonrpc related interface

#ifndef CM_JSONRPC_C_API_H
#define CM_JSONRPC_C_API_H

#ifndef __cplusplus

#include <stdbool.h>

#endif

#include "machine-c-api.h"
#include "machine-c-defines.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Handle of the jsonrpc connection manager
typedef struct cm_jsonrpc_mg_mgr_tag cm_jsonrpc_mg_mgr; // NOLINT(modernize-use-using)

/// \brief Create a connection manager to the remote Cartesi Machine server
/// \param remote_address Address of the remote Cartesi server
/// \param mgr Receives new connection manager instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_create_jsonrpc_mg_mgr(const char *remote_address, cm_jsonrpc_mg_mgr **mgr, char **err_msg);

/// \brief Deletes a connection manager instance
/// \param m Valid pointer to the existing jsonrpc mgr instance
CM_API void cm_delete_jsonrpc_mg_mgr(const cm_jsonrpc_mg_mgr *mgr);

/// \brief Create remote machine instance
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param config Machine configuration. Must be pointer to valid object
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_create_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, const cm_machine_config *config,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg);

/// \brief Create remote machine instance from previously serialized directory
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_load_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, const char *dir,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg);

/// \brief Get remote machine instance that was previously created in the server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_get_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, cm_machine **new_machine, char **err_msg);

/// \brief Ged default machine config from server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param config Receives the default configuration
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_get_default_config(const cm_jsonrpc_mg_mgr *mgr, const cm_machine_config **config,
    char **err_msg);

/// \brief Checks the internal consistency of an access log
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param log State access log to be verified.
/// \param runtime_config Runtime config to be used
/// \param one_based Use 1-based indices when reporting errors.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_7_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_verify_access_log(const cm_jsonrpc_mg_mgr *mgr, const cm_access_log *log,
    const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg);

/// \brief Checks the validity of a state transition
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param runtime_config Runtime config to be used
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_verify_state_transition(const cm_jsonrpc_mg_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, const cm_machine_runtime_config *runtime_config,
    bool one_based, char **err_msg);

/// \brief Forks the server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param address Receives address of new server if function execution succeeds or NULL
/// otherwise. In case of success, address must be deleted by the function caller using
/// cm_delete_cstring.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_fork(const cm_jsonrpc_mg_mgr *mgr, char **address, char **err_msg);

/// \brief Gets the address of a general-purpose register from remote cartesi server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_get_x_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg);

/// \brief Gets the address of a floating-point register from remote cartesi server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param i Register index. Between 0 and F_REG_COUNT-1, inclusive.
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_get_f_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg);

/// \brief Gets the address of a general-purpose register in the microemulator from remote cartesi server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_get_uarch_x_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg);

/// \brief Gets the address of any CSR from remote server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param w The command and status register
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_get_csr_address(const cm_jsonrpc_mg_mgr *mgr, CM_PROC_CSR w, uint64_t *val, char **err_msg);

/// \brief Gets the semantic version of remote server machine
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param version Receives semantic version
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_get_semantic_version(const cm_jsonrpc_mg_mgr *mgr, const cm_semantic_version **version,
    char **err_msg);

/// \brief Performs shutdown
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_shutdown(const cm_jsonrpc_mg_mgr *mgr, char **err_msg);

#ifdef __cplusplus
}
#endif

#endif // CM_JSONRPC_C_API_H
