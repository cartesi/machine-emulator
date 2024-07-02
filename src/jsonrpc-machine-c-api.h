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

#ifndef CM_JSONRPC_C_API_H
#define CM_JSONRPC_C_API_H

#include "machine-c-api.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// \brief Handle of the jsonrpc connection manager.
typedef struct cm_jsonrpc_mgr_tag cm_jsonrpc_mgr;

// -------------------------------------
// Connection manager related

/// \brief Creates a jsonrpc connection manager instance connected to a remote machine server.
/// \param remote_address Address of the remote machine server to connect to.
/// \param mgr Receives new jsonrpc connection manager instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_create_mgr(const char *remote_address, cm_jsonrpc_mgr **mgr);

/// \brief Destroys a jsonrpc connection manager instance.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_destroy_mgr(const cm_jsonrpc_mgr *mgr);

/// \brief Forks the server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param address Receives address of new server if function execution succeeds or NULL otherwise.
/// Remains valid until this same function is called again for the same jsonrpc connection manager instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_fork(const cm_jsonrpc_mgr *mgr, char **address);

/// \brief Changes the address the server is listening to
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param address New address that the remote server should bind to
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_rebind(const cm_jsonrpc_mgr *mgr, const char *address);

/// \brief Performs shutdown
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_shutdown(const cm_jsonrpc_mgr *mgr);

/// \brief Gets the semantic version of remote server machine
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param major Receives semantic major version.
/// \param minor Receives semantic minor version.
/// \param patch Receives semantic patch version.
/// \param pre_release Receives pre release string,
/// remains valid until this same function is called again for the same machine.
/// \param build Receives build string,
/// remains valid until this same function is called again for the same machine.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_semantic_version(const cm_jsonrpc_mgr *mgr, uint32_t *major, uint32_t *minor, uint32_t *patch,
    const char **pre_release, const char **build);

// -------------------------------------
// Machine related

/// \brief Create remote machine instance.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param config Machine configuration as a JSON string.
/// \param runtime_config Machine runtime configuration as a JSON string.
/// \param new_machine Receives the pointer to new machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_create_jsonrpc_machine(const cm_jsonrpc_mgr *mgr, const char *config, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Create remote machine instance from previously serialized directory.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param dir Directory where previous machine is serialized.
/// \param runtime_config Machine runtime configuration as a JSON string.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_load_machine(const cm_jsonrpc_mgr *mgr, const char *dir, const char *runtime_config,
    cm_machine **new_machine);

/// \brief Get remote machine instance that was previously created in the server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param new_machine Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_machine(const cm_jsonrpc_mgr *mgr, cm_machine **new_machine);

// -------------------------------------
// Getting

/// \brief Get last error message from server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param err_msg Receives the error message.
/// \returns 0 for success, non zero code for error.
/// \details It uses a thread local variable, so it's safe to call from different threads.
/// The string returned by this function must not be changed nor deallocated.
/// In case the last API call was successful it returns an empty string.
/// The error message is only updated by functions that can return a CM_ERROR code.
CM_API int cm_jsonrpc_get_last_error_message(const cm_jsonrpc_mgr *mgr, const char **err_msg);

/// \brief Get default machine config from server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param config Receives the default configuration
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_default_config(const cm_jsonrpc_mgr *mgr, const char **config);

/// \brief Get default machine runtime config from server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param config Receives the default configuration
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_default_runtime_config(const cm_jsonrpc_mgr *mgr, const char **config);

/// \brief Gets the address of any CSR from remote server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param csr The CSR register.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_csr_address(const cm_jsonrpc_mgr *mgr, CM_CSR csr, uint64_t *val);

/// \brief Gets the address of a general-purpose register from remote server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_x_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val);

/// \brief Gets the address of a floating-point register from remote server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param i Register index. Between 0 and F_REG_COUNT-1, inclusive.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_f_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val);

/// \brief Gets the address of a general-purpose microarchitecture from remote server.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_get_uarch_x_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val);

// -------------------------------------
// Verifying

/// \brief Checks the internal consistency of an access log.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param access_log State access log to be verified as a JSON string.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_verify_uarch_step_log(const cm_jsonrpc_mgr *mgr, const char *access_log, bool one_based);

/// \brief Checks the validity of a state transition.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param root_hash_before State hash before step.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after step.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_verify_uarch_step_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const char *access_log, const cm_hash *root_hash_after, bool one_based);

/// \brief Checks the internal consistency of an access log produced by cm_jsonrpc_log_reset_uarch.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param access_log State access log to be verified as a JSON string.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_verify_reset_uarch_log(const cm_jsonrpc_mgr *mgr, const char *access_log, bool one_based);

/// \brief Checks the validity of a state transition caused by uarch state reset.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param root_hash_before State hash before step.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after step.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_verify_reset_uarch_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const char *access_log, const cm_hash *root_hash_after, bool one_based);

/// \brief Checks the internal consistency of an access log produced by send_cmio_response.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param reason Reason for sending response.
/// \param data Response data to send.
/// \param length Length of data response data.
/// \param access_log State access log to be verified as a JSON string.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error.
CM_API int cm_jsonrpc_verify_send_cmio_response_log(const cm_jsonrpc_mgr *mgr, uint16_t reason,
    const unsigned char *data, size_t length, const char *access_log, bool one_based);

/// \brief Checks the validity of a state transition caused by send_cmio_response.
/// \param mgr Pointer to a valid jsonrpc connection manager.
/// \param reason Reason for sending response.
/// \param data Response data to send.
/// \param length Length of data response data.
/// \param root_hash_before State hash before load.
/// \param access_log State access log to be verified as a JSON string.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for successfull verification, non zero code for error.
CM_API int cm_jsonrpc_verify_send_cmio_response_state_transition(const cm_jsonrpc_mgr *mgr, uint16_t reason,
    const unsigned char *data, size_t length, const cm_hash *root_hash_before, const char *access_log,
    const cm_hash *root_hash_after, bool one_based);

#ifdef __cplusplus
}
#endif

#endif // CM_JSONRPC_C_API_H
