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

// -----------------------------------------------------------------------------
// API enums and structures
// -----------------------------------------------------------------------------

/// \brief Handle of the JSONRPC connection.
/// \details It's used only as an opaque handle to pass JSONRPC connection through the C API.
typedef struct cm_jsonrpc_connection cm_jsonrpc_connection;

// -----------------------------------------------------------------------------
// API functions
// -----------------------------------------------------------------------------

// ------------------------------------
// Remote server management
// ------------------------------------

/// \brief Connects to an existing JSONRPC remote machine server.
/// \param address Address of the remote machine server to connect to.
/// \param detach_server When non-zero, do not implicitly call
/// cm_jsonrpc_shutdown_server() server on cm_jsonrpc_release_connection().
/// \param con If function succeeds, receives new JSONRPC connection. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_connect(const char *address, int detach_server, cm_jsonrpc_connection **con);

/// \brief Spawns a new JSONRPC remote machine server and connect to it.
/// \param address Address (in local host) to bind the new JSONRPC remote machine server.
/// \param detach_server When non-zero, do not implicitly call
/// cm_jsonrpc_shutdown_server() server on cm_jsonrpc_release_connection().
/// \param con If function succeeds, receives new JSONRPC connection. Set to NULL on failure.
/// \param bound_address_bound Receives the address that the remote server actually bound to, guaranteed to remain valid
/// only until the next CM_API function is called again on the same thread. Set to NULL on failure.
/// \param pid If function suceeds, receives the forked child process id. Set to 0 on failure.
/// \details If the jsonrpc-remote-cartesi-machine executable is not in the path,
/// the environment variable JSONRPC_REMOTE_CARTESI_MACHINE should point to the executable.
CM_API cm_error cm_jsonrpc_spawn_server(const char *address, int detach_server, cm_jsonrpc_connection **con,
    const char **bound_address, int32_t *pid);

/// \brief Releases a reference to a JSONRPC connection to remote machine server.
/// \param con Pointer a JSONRPC connection (can be NULL).
/// \returns 0 for success, non zero code for error.
/// \details When the last reference to the connection is released, if the
/// server is not detached, implicitly call cm_jsonrpc_shutdown_server() to
/// shutdown the server. This might fail silently. To know if the shutdown of
/// a server was successful, call cm_jsonrpc_shutdown_server() explicitly before
/// calling cm_jsonrpc_release_connection().
/// The connection pointer must not be used after this call.
CM_API void cm_jsonrpc_release_connection(const cm_jsonrpc_connection *con);

/// \brief Forks the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param address If function succeeds, receives address of new server, guaranteed to remain valid
/// only until the next CM_API function is called again on the same thread. Set to NULL on failure.
/// \param pid If function suceeds, receives the forked child process id (can be NULL). Set to 0 on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_fork_server(const cm_jsonrpc_connection *con, const char **address, int32_t *pid);

/// \brief Shutdowns remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_shutdown_server(const cm_jsonrpc_connection *con);

/// \brief Changes the address the remote server is listening to.
/// \param con Pointer to a valid JSONRPC connection.
/// \param address Address the remote server should bind to.
/// \param address_bound Receives the address that the remote server actually bound to, guaranteed to remain valid
/// only until the next CM_API function is called again on the same thread. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_rebind_server(const cm_jsonrpc_connection *con, const char *address,
    const char **address_bound);

/// \brief Gets the semantic version of the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param semantic_version Receives the semantic version as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called again on the
/// same thread. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_server_version(const cm_jsonrpc_connection *con, const char **version);

/// \brief Returns a JSON object in a string with the default machine config from the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param config Receives the default configuration, guaranteed to remain valid only until
/// the next CM_API function is called again on the same thread.
/// \returns 0 for success, non zero code for error.
/// \details The returned config is not sufficient to run a machine.
/// Additional configurations, such as RAM length, RAM image, flash drives,
/// and entrypoint are still needed.
CM_API cm_error cm_jsonrpc_get_default_config(const cm_jsonrpc_connection *con, const char **config);

/// \brief Gets the address of any x, f, or control state register from the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param reg The register.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_reg_address(const cm_jsonrpc_connection *con, cm_reg reg, uint64_t *val);

// ------------------------------------
// Machine API functions
// ------------------------------------

/// \brief Creates a remote machine instance.
/// \param con Pointer to a valid JSONRPC connection.
/// \param detach_machine When non-zero, do not implicitly call cm_destroy_machine() on cm_release_machine().
/// \param config Machine configuration as a JSON string.
/// \param runtime_config Machine runtime configuration as a JSON string (can be NULL).
/// \param m Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
/// \details The machine instance holds its own reference to the connection.
CM_API cm_error cm_jsonrpc_create_machine(const cm_jsonrpc_connection *con, int detach_machine, const char *config,
    const char *runtime_config, cm_machine **m);

/// \brief Creates a remote machine instance from previously stored directory in the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param detach_machine When non-zero, do not implicitly call cm_destroy_machine() on cm_release_machine().
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON string (can be NULL).
/// \param m Receives the pointer to new remote machine instance.
/// \returns 0 for success, non zero code for error.
/// \details The machine instance holds its own reference to the connection.
CM_API cm_error cm_jsonrpc_load_machine(const cm_jsonrpc_connection *con, int detach_machine, const char *dir,
    const char *runtime_config, cm_machine **m);

/// \brief Get remote machine instance that was previously created in the remote server.
/// \param con Pointer to a valid JSONRPC connection.
/// \param detach_machine When non-zero, do not implicitly call cm_destroy_machine() on cm_release_machine().
/// \param m Receives the pointer to remote machine instance.
/// \returns 0 for success, non zero code for error.
/// \details The machine instance holds its own reference to the connection.
CM_API cm_error cm_jsonrpc_get_machine(const cm_jsonrpc_connection *con, int detach_machine, cm_machine **m);

/// \brief Get new reference to a connection to JSONRPC server given a remote machine instance.
/// \param m Pointer to a valid machine instance.
/// \param con Receives the pointer to JSONRPC connection. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_connection(cm_machine *m, const cm_jsonrpc_connection **con);

// ------------------------------------
// Verifying
// ------------------------------------

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
