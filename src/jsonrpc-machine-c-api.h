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
// API enums
// -----------------------------------------------------------------------------

/// \brief Resources to cleanup when a machine object is deleted.
typedef enum cm_jsonrpc_cleanup_call {
    CM_JSONRPC_NOTHING, ///< Just delete the object
    CM_JSONRPC_DESTROY, ///< Implicitly calls cm_destroy()
    CM_JSONRPC_SHUTDOWN ///< Implicitly calls cm_jsonrpc_shutdown_server()
} cm_jsonrpc_cleanup_call;

// -----------------------------------------------------------------------------
// Server API functions
// -----------------------------------------------------------------------------

/// \brief Spawns a new remote machine server.
/// \param address Address (in the local host) to bind the new remote machine server.
/// \param spawn_timeout_ms Maximum time in milliseconds to wait for the remote server to spawn before giving up
/// and returning an error. Use -1 for no timeout.
/// \param new_m Receives the pointer to the new JSONRPC remote machine object. Set to NULL on failure.
/// \param bound_address Receives the address that the remote machine server actually bound to,
/// guaranteed to remain valid only until the next CM_API function is called again on the same thread.
/// Set to NULL on failure.
/// \param pid Receives the spawned server process id. Set to 0 on failure.
/// \returns 0 for success, non zero code for error.
/// \details A newly spawned remote machine server does not hold a machine instance.
/// Use cm_create() or cm_load() to instantiate a machine into the object.
/// Use cm_delete() to delete the object.
/// \details The spawned process is in the process group of the caller.
/// Use cm_jsonrpc_emancipate_server() to make it leader of its own process group.
/// \details The machine object is configured to implicitly cleanup with a shutdown during cm_delete().
/// Use cm_jsonrpc_set_cleanup_call() to change this setting.
/// \details Unless the desired cartesi-jsonrpc-machine executable is in the path,
/// the environment variable CARTESI_JSONRPC_MACHINE must point directly to the executable.
CM_API cm_error cm_jsonrpc_spawn_server(const char *address, int64_t spawn_timeout_ms, cm_machine **new_m,
    const char **bound_address, uint32_t *pid);

/// \brief Connects to an existing remote machine server.
/// \param address Address of the remote machine server to connect to.
/// \param connect_timeout_ms Maximum time in milliseconds to wait for the remote server to connect before giving up
/// and returning an error. Use -1 for no timeout.
/// \param new_m Receives the pointer to the new JSONRPC remote machine object. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details The machine object is not configured to implicitly cleanup anything on cm_delete().
/// Use cm_jsonrpc_set_cleanup_call() to change this setting.
/// \details If the remote machine server already holds a machine instance, it is ready for use.
/// Otherwise, use cm_create() or cm_load() to instantiate a machine into the object.
/// Use cm_delete() to delete the object.
CM_API cm_error cm_jsonrpc_connect_server(const char *address, int64_t connect_timeout_ms, cm_machine **new_m);

/// \brief Forks the remote machine server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param forked_m Receives the pointer to the forked JSONRPC remote machine object. Set to NULL on failure.
/// \param address Receives the address the forked server bound to if the function succeeds,
/// guaranteed to remain valid only until the next CM_API function is called again on the same thread.
/// Set to NULL on failure.
/// \param pid If function succeeds, receives the forked child process id (can be NULL). Set to 0 on failure.
/// \returns 0 for success, non zero code for error.
/// \details If the remote machine server already holds a machine instance, the forked copy is ready for use.
/// Otherwise, use cm_create() or cm_load() to instantiate a machine into the forked server object.
/// Use cm_delete() to delete the object.
/// \details The forked process is in the process group of the remote server.
/// Use cm_jsonrpc_emancipate_server() to make it leader of its own process group.
/// \details The machine object implicit cleanup on cm_delete() is inherited from the original machine.
/// Use cm_jsonrpc_set_cleanup_call() to change this setting.
/// \details The communication timeout is inherited from the original machine object.
/// Use cm_jsonrpc_set_timeout() to change this setting.
/// \warning If the server is running on a remote host, the pid is also remote and cannot be signaled.
/// Trying to do so may signal an entirely unrelated process in the local host.
CM_API cm_error cm_jsonrpc_fork_server(const cm_machine *m, cm_machine **forked_m, const char **address, uint32_t *pid);

/// \brief Shuts down the remote machine server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \returns 0 for success, non zero code for error.
/// \details cm_delete() may fail silently when implicitly calling cm_jsonrpc_shutdown_server().
/// To make sure the server was successfully shut down, call cm_jsonrpc_shutdown_server() explicitly.
/// \details This function does not delete the machine object.
/// You must still call cm_delete() afterwards.
CM_API cm_error cm_jsonrpc_shutdown_server(cm_machine *m);

/// \brief Changes the address that the remote machine server is listening to.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param address Address the remote machine server should bind to.
/// \param address_bound Receives the address that the remote machine server actually bound to,
/// guaranteed to remain valid only until the next CM_API function is called again on the same thread.
/// Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details This function automatically updates the address the machine object uses to communicate with the server.
CM_API cm_error cm_jsonrpc_rebind_server(cm_machine *m, const char *address, const char **address_bound);

/// \brief Gets the semantic version of the remote machine server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param version Receives the semantic version as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called again on the same thread.
/// Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_server_version(const cm_machine *m, const char **version);

/// \brief Breaks the server out of its parent process group.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \returns 0 for success, non zero code for error.
/// \details A spawned/forked server process starts in the same process group as its parent.
/// This function makes it the leader of its own process group.
CM_API cm_error cm_jsonrpc_emancipate_server(cm_machine *m);

// -----------------------------------------------------------------------------
// Client API functions
// -----------------------------------------------------------------------------

/// \brief Sets a timeout for communication with remote machine server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param ms Number of milliseconds to wait before returning due to a timeout. Use -1 to block indefinitely.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_set_timeout(cm_machine *m, int64_t ms);

/// \brief Gets the current timeout for communication with remote machine server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param ms Receives the number of milliseconds to wait before returning due to a timeout. (-1 blocks indefinitely).
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_timeout(cm_machine *m, int64_t *ms);

/// \brief Configures the implicit cleanup call at object deletion.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param call If set to CM_JSONRPC_DESTROY, implicitly call cm_destroy() on cm_delete().
/// If set to CM_JSONRPC_SHUTDOWN, implicitly call cm_jsonrpc_shutdown_server() on cm_delete().
/// Otherwise (i.e., CM_JSONRPC_NOTHING), simply delete object on cm_delete().
/// This is the default behavior.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_set_cleanup_call(cm_machine *m, cm_jsonrpc_cleanup_call call);

/// \brief Retrieves the implicit cleanup call at the time of object deletion.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param call Receives either CM_JSONRPC_NOTHING, CM_JSONRPC_DESTROY, or CM_JSONRPC_SHUTDOWN.
/// See cm_jsonrpc_set_cleanup_call().
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_cleanup_call(cm_machine *m, cm_jsonrpc_cleanup_call *call);

/// \brief Retrieves the address of the remote server.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param address Receives the address of the remote machine, guaranteed to remain valid only until
/// the next CM_API function is called again on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_get_server_address(cm_machine *m, const char **address);

// -----------------------------------------------------------------------------
// Debugging and testing
// -----------------------------------------------------------------------------

/// \brief Asks the server to delay the next request by a given amount of time.
/// \param m Pointer to a valid JSONRPC remote machine object.
/// \param ms Number of milliseconds to delay the next request.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_jsonrpc_delay_next_request(cm_machine *m, uint64_t ms);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
