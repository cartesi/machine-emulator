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

/// \brief Handle of the grpc stub
/// \details cm_machine is already defined void
/// so for template specialisation this needs to be different
/// type
typedef struct {
} cm_grpc_machine_stub;


/// \brief Create server stub for remote Cartesi machine server
/// \param address Address of the remove Cartesi server
/// \param stub Receives new server stub instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_create_grpc_machine_stub(const char *address, cm_grpc_machine_stub **stub, char **err_msg);

/// \brief Deletes grpc machine stub instance
/// \param m Valid pointer to the existing grpc stub instance
CM_API void cm_delete_grpc_machine_stub(const cm_grpc_machine_stub *stub);

/// \brief Create remote machine instance
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param config Machine configuration. Must be pointer to valid object
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_create_grpc_machine(const cm_grpc_machine_stub *stub, const cm_machine_config *config,
                                  const cm_machine_runtime_config *runtime_config,
                                  cm_machine **new_machine, char **err_msg);

/// \brief Create remote machine instance from previously serialized directory
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new remote machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_load_grpc_machine(const cm_grpc_machine_stub *stub, const char *dir,
                                const cm_machine_runtime_config *runtime_config,
                                cm_machine **new_machine, char **err_msg);


/// \brief Ged default machine config from server
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param config Receives the default configuration
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_grpc_get_default_config(const cm_grpc_machine_stub *stub, const cm_machine_config **config, char **err_msg);


/// \brief Checks the internal consistency of an access log
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param log State access log to be verified.
/// \param one_based Use 1-based indices when reporting errors.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_7_error_message
/// \returns 0 for success, non zero code for error
CM_API int cm_grpc_verify_access_log(const cm_grpc_machine_stub *stub, const cm_access_log *log, bool one_based, char **err_msg);

/// \brief Checks the validity of a state transition
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_verify_state_transition(const cm_grpc_machine_stub *stub, const cm_hash *root_hash_before,
                                           const cm_access_log *log, const cm_hash *root_hash_after,
                                           bool one_based, char **err_msg);

/// \brief Gets the address of a general-purpose register from remote cartesi server
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_get_x_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg);


/// \brief Gets the address of any CSR from remote server
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param w The command and status register
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_get_csr_address(const cm_grpc_machine_stub *stub, CM_PROC_CSR w, uint64_t *val, char **err_msg);

/// \brief  Gets the address of a DHD h register from remote server
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param i Register index. Between 0 and DHD_H_REG_COUNT-1, inclusive
/// \param val Receives address of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_dhd_h_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg);

/// \brief Gets the semantic version of remote server machine
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param version Receives semantic version
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_get_semantic_version(const cm_grpc_machine_stub *stub, const cm_semantic_version **version,
                                        char **err_msg);

/// \brief Deletes semantic version instance
/// \param m Valid pointer to the existing semantic version instance
CM_API void cm_delete_semantic_version(const cm_semantic_version *version);

/// \brief Performs shutdown
/// \param stub Cartesi grpc machine stub. Must be pointer to valid object
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_error_message
/// \returns 0 for successfull verification, non zero code for error
CM_API int cm_grpc_shutdown(const cm_grpc_machine_stub *stub, char **err_msg);

#ifdef __cplusplus
}
#endif

#endif //CM_GRPC_C_API_H