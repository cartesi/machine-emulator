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

#ifndef CM_JSONRPC_C_API_H // NOLINTBEGIN
#define CM_JSONRPC_C_API_H

#include "machine-c-api.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Handle of the jsonrpc connection manager
typedef struct cm_jsonrpc_mgr cm_jsonrpc_mgr;

/// \brief Create a connection manager to the remote Cartesi Machine server
/// \param remote_address Address of the remote Cartesi server
/// \param mgr Receives new connection manager instance
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_create_mgr(const char *remote_address, cm_jsonrpc_mgr **mgr);

/// \brief Deletes a connection manager instance
/// \param m Valid pointer to the existing jsonrpc mgr instance
CM_API void cm_jsonrpc_destroy_mgr(const cm_jsonrpc_mgr *mgr);

/// \brief Create remote machine instance
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param config Machine configuration. Must be pointer to valid object
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_create_machine(const cm_jsonrpc_mgr *mgr, const char *config, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Create remote machine instance from previously serialized directory
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_load_machine(const cm_jsonrpc_mgr *mgr, const char *dir, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Get remote machine instance that was previously created in the server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_get_machine(const cm_jsonrpc_mgr *mgr, cm_machine **new_machine);

/// \brief Ged default machine config from server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param config Receives the default configuration
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_get_default_config(const cm_jsonrpc_mgr *mgr, const char **config);

/// \brief Checks the internal consistency of an access log
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param log State access log to be verified.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_verify_step_uarch_log(const cm_jsonrpc_mgr *mgr, const cm_access_log *log, bool one_based);

/// \brief Checks the internal consistency of an access log produced by a reset uarch.
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param log State access log to be verified.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_verify_reset_uarch_log(const cm_jsonrpc_mgr *mgr, const cm_access_log *log, bool one_based);

/// \brief Checks the validity of a state transition caused by a reset uarch.
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param root_hash_before State hash before step
/// \param log State access log to be verified.
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_verify_reset_uarch_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, bool one_based);

/// \brief Checks the validity of a state transition
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_verify_step_uarch_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, bool one_based);

/// \brief Forks the server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param address Receives address of new server if function execution succeeds,
/// remains valid until the next time this same function is called on the same thread.
/// In case of failure receives NULL.
/// \param pid Receives the forked child process id.
/// In case of failure receives 0.
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_fork(const cm_jsonrpc_mgr *mgr, const char **address, int *pid);

/// \brief Changes the address the server is listening to
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param address New address that the remote server should bind to
/// \param new_address Receives the new address that the remote server actually bound to,
/// remains valid until the next time this same function is called on the same thread.
/// In case of failure receives NULL.
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_rebind(const cm_jsonrpc_mgr *mgr, const char *address, const char **new_address);

/// \brief Gets the address of any CSR from remote server
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param csr The command and status register
/// \param val Receives address of the register
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_get_csr_address(const cm_jsonrpc_mgr *mgr, CM_CSR csr, uint64_t *val);

/// \brief Gets the semantic version of remote server machine
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param semantic_version Receives the semantic version as a JSON string.
/// remains valid until the next time this same function is called on the same thread.
/// In case of failure receives NULL.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_version(const cm_jsonrpc_mgr *mgr, const char **version);

/// \brief Performs shutdown
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_jsonrpc_shutdown(const cm_jsonrpc_mgr *mgr);

/// \brief Checks the internal consistency of an access log produced by send_cmio_response
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param reason Reason for sending response
/// \param data Response data to send.
/// \param length Length of data response data.
/// \param log State access log to be verified.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error
CM_API int cm_jsonrpc_verify_send_cmio_response_log(const cm_jsonrpc_mgr *mgr, uint16_t reason,
    const unsigned char *data, size_t length, const cm_access_log *log, bool one_based);

/// \brief Checks the validity of a state transition caused by send_cmio_response
/// \param mgr Cartesi jsonrpc connection manager. Must be pointer to valid object
/// \param reason Reason for sending response.
/// \param data Response data to send.
/// \param length Length of data response data.
/// \param root_hash_before State hash before load.
/// \param log State access log to be verified.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_jsonrpc_verify_send_cmio_response_state_transition(const cm_jsonrpc_mgr *mgr, uint16_t reason,
    const unsigned char *data, size_t length, const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, bool one_based);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
