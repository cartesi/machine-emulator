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

#ifndef CM_JSONRPC_MACHINE_C_API_H // NOLINTBEGIN
#define CM_JSONRPC_MACHINE_C_API_H

#include "machine-c-api.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Handle of the JSONRPC connection.
/// \details It's used only as an opaque handle to pass JSONRPC connection through the C API.
typedef struct cm_jsonrpc_connection cm_jsonrpc_connection;

// -------------------------------------
// Remote server management

/// \brief Creates a JSONRPC connection instance connected to a remote machine server.
/// \param remote_address Address of the remote machine server to connect to.
/// \param con Receives new JSONRPC connection instance.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_create_connection(const char *remote_address, cm_jsonrpc_connection **con);

/// \brief Destroys a connection instance.
/// \param con Pointer a JSONRPC connection (can be NULL).
/// \returns 0 for success, non zero code for error.
/// \details The connection is deallocated and its pointer must not be used after this call.
CM_API void cm_jsonrpc_destroy_connection(const cm_jsonrpc_connection *con);

/// \brief Forks the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param address Receives address of new server if function execution succeeds or NULL otherwise,
/// guaranteed to remain valid only until the next C API is called from the same thread.
/// \param pid Receives the forked child process id if function execution succeeds or 0 otherwise.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_fork(const cm_jsonrpc_connection *con, const char **address, int32_t *pid);

/// \brief Changes the address the remote server is listening to.
/// \param con Pointer to a valid JSONRPC connection.
/// \param address New address that the remote server should bind to.
/// \param new_address Receives the new address that the remote server actually bound to,
/// guaranteed to remain valid only until the next C API is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_rebind(const cm_jsonrpc_connection *con, const char *address, const char **new_address);

/// \brief Shutdowns remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_shutdown(const cm_jsonrpc_connection *con);

/// \brief Gets the semantic version of the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param semantic_version Receives the semantic version as a JSON string,
/// guaranteed to remain valid only until the next C API is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_version(const cm_jsonrpc_connection *con, const char **version);

/// \brief Gets a JSON string for the default machine config from the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param config Receives the default configuration,
/// guaranteed to remain valid only until the next C API is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_default_config(const cm_jsonrpc_connection *con, const char **config);

/// \brief Gets the address of any register from the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param reg The register.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_reg_address(const cm_jsonrpc_connection *con, cm_reg reg, uint64_t *val);

// -------------------------------------
// Machine API functions

/// \brief Creates a remote machine instance.
/// \param con Pointer to a valid JSONRPC connection.
/// \param config Machine configuration as a JSON string.
/// \param runtime_config Machine runtime configuration as a JSON string, it can be NULL.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_create_machine(const cm_jsonrpc_connection *con, const char *config,
    const char *runtime_config, cm_machine **new_machine);

/// \brief Creates a remote machine instance from previously stored directory in the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON string, it can be NULL.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_load_machine(const cm_jsonrpc_connection *con, const char *dir, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Get remote machine instance that was previously created in the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param new_machine Receives the pointer to remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_machine(const cm_jsonrpc_connection *con, cm_machine **new_machine);

// -------------------------------------
// Verifying

/// \brief Checks the validity of a state transition produced by cm_log_step_uarch.
/// \param con Pointer to a valid JSONRPC connection.
/// \param root_hash_before State hash before load.
/// \param log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_verify_step_uarch(const cm_jsonrpc_connection *con, const cm_hash *root_hash_before,
    const char *log, const cm_hash *root_hash_after);

/// \brief Checks the validity of a state transition produced by cm_log_verify_reset_uarch.
/// \param con Pointer to a valid JSONRPC connection.
/// \param root_hash_before State hash before load.
/// \param log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_verify_reset_uarch(const cm_jsonrpc_connection *con, const cm_hash *root_hash_before,
    const char *log, const cm_hash *root_hash_after);

/// \brief Checks the validity of a state transition produced by cm_log_send_cmio_response.
/// \param con Pointer to a valid JSONRPC connection.
/// \param reason Reason for sending the response.
/// \param data The response sent when the log was generated.
/// \param length Length of response.
/// \param root_hash_before State hash before load.
/// \param log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_verify_send_cmio_response(const cm_jsonrpc_connection *con, uint16_t reason,
    const uint8_t *data, uint64_t length, const cm_hash *root_hash_before, const char *log,
    const cm_hash *root_hash_after);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
