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

/// \brief Handle of the JSONRPC connection manager.
/// \details It's used only as an opaque handle to pass JSONRPC connection manager through the C API.
typedef struct cm_jsonrpc_mgr cm_jsonrpc_mgr;

// -------------------------------------
// Remote server management

/// \brief Creates a JSONRPC connection manager instance connected to a remote machine server.
/// \param remote_address Address of the remote machine server to connect to.
/// \param mgr Receives new JSONRPC connection manager instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_create_mgr(const char *remote_address, cm_jsonrpc_mgr **mgr);

/// \brief Deletes a connection manager instance.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \returns 0 for success, non zero code for error.
CM_API void cm_jsonrpc_delete_mgr(const cm_jsonrpc_mgr *mgr);

/// \brief Forks the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param address Receives address of new server if function execution succeeds or NULL otherwise,
/// remains valid until the next time this same function is called on the same thread.
/// \param pid Receives the forked child process id if function execution succeeds or 0 otherwise.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_fork(const cm_jsonrpc_mgr *mgr, const char **address, int32_t *pid);

/// \brief Changes the address the remote server is listening to.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param address New address that the remote server should bind to.
/// \param new_address Receives the new address that the remote server actually bound to,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_rebind(const cm_jsonrpc_mgr *mgr, const char *address, const char **new_address);

/// \brief Shutdowns remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_shutdown(const cm_jsonrpc_mgr *mgr);

/// \brief Gets the semantic version of the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param semantic_version Receives the semantic version as a JSON string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_get_version(const cm_jsonrpc_mgr *mgr, const char **version);

/// \brief Gets a JSON string for the default machine config from the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param config Receives the default configuration,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_get_default_config(const cm_jsonrpc_mgr *mgr, const char **config);

/// \brief Gets the address of any CSR from the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param csr The CSR.
/// \param val Receives address of the CSR.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_get_csr_address(const cm_jsonrpc_mgr *mgr, cm_csr csr, uint64_t *val);

// -------------------------------------
// Machine API functions

/// \brief Creates a remote machine instance.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param config Machine configuration as a JSON string.
/// \param runtime_config Machine runtime configuration as a JSON string, it can be NULL.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_create_machine(const cm_jsonrpc_mgr *mgr, const char *config, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Creates a remote machine instance from previously stored directory in the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON string, it can be NULL.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_load_machine(const cm_jsonrpc_mgr *mgr, const char *dir, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Get remote machine instance that was previously created in the remote server.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param new_machine Receives the pointer to remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_jsonrpc_get_machine(const cm_jsonrpc_mgr *mgr, cm_machine **new_machine);

// -------------------------------------
// Verifying

/// \brief Checks the validity of a state transition for one micro cycle.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param root_hash_before State hash before load.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
/// \details In case both root_hash_before and root_hash_after are NULL,
/// then it just verifies the access log integrity.
CM_API int32_t cm_jsonrpc_verify_step_uarch(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const char *access_log, const cm_hash *root_hash_after, bool one_based);

/// \brief Checks the validity of a state transition produced by a microarchitecture state reset.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param root_hash_before State hash before load.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
/// \details In case both root_hash_before and root_hash_after are NULL,
/// then it just verifies the access log integrity.
CM_API int32_t cm_jsonrpc_verify_reset_uarch(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const char *access_log, const cm_hash *root_hash_after, bool one_based);

/// \brief Checks the validity of state transitions produced by a send cmio response.
/// \param mgr Pointer to a valid JSONRPC connection manager.
/// \param reason Reason for sending the response.
/// \param data The response sent when the log was generated.
/// \param length Length of response.
/// \param root_hash_before State hash before load.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
/// \details In case both root_hash_before and root_hash_after are NULL,
/// then it just verifies the access log integrity.
CM_API int32_t cm_jsonrpc_verify_send_cmio_response(const cm_jsonrpc_mgr *mgr, uint16_t reason, const uint8_t *data,
    uint64_t length, const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after,
    bool one_based);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
