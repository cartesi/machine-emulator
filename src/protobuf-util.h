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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include "cartesi-machine.pb.h"
#include "versioning.pb.h"
#pragma GCC diagnostic pop

#include "access-log.h"
#include "machine-c-defines.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-runtime-config.h"
#include "semantic-version.h"

namespace cartesi {

/// \brief Converts proto MachineConfig to C++ machine_config
/// \param proto_c Proto MachineConfig to convert
/// \returns Converted C++ machine_config
CM_API machine_config get_proto_machine_config(const CartesiMachine::MachineConfig &proto_c);

/// \brief Converts C++ machine_config to proto MachineConfig
/// \param c C++ machine_config to convert
/// \param proto_c Pointer to proto MachineConfig receiving result of conversion
CM_API void set_proto_machine_config(const machine_config &c, CartesiMachine::MachineConfig *proto_c);

/// \brief Converts proto MachineRuntimeConfig to C++ machine_runtime_config
/// \param proto_c Proto MachineRuntimeConfig to convert
/// \returns Converted C++ machine_runtime_config
CM_API machine_runtime_config get_proto_machine_runtime_config(const CartesiMachine::MachineRuntimeConfig &proto_r);

/// \brief Converts C++ machine_runtime_config to proto MachineRuntimeConfig
/// \param r C++ machine_runtime_config to convert
/// \param proto_r Pointer to proto MachineRuntimeConfig receiving
///  result of conversion
CM_API void set_proto_machine_runtime_config(const machine_runtime_config &r,
    CartesiMachine::MachineRuntimeConfig *proto_r);

/// \brief Converts proto ProcessorConfig to C++ processor_config
/// \param proto_p Proto ProcessorConfig to convert
/// \returns Converted C++ processor_config
CM_API processor_config get_proto_processor_config(const CartesiMachine::ProcessorConfig &proto_p);

/// \brief Converts Proto AccessLogType to C++ access_log::type
/// \param proto_lt Proto AccessLogType to convert
/// \returns Converted C++ access_log::type
CM_API access_log::type get_proto_log_type(const CartesiMachine::AccessLogType &proto_lt);

/// \brief Converts proto Hash to C++ hash
/// \param proto_hash Proto Hash to convert
/// \returns Converted C++ hash
CM_API machine_merkle_tree::hash_type get_proto_hash(const CartesiMachine::Hash &proto_hash);

/// \brief Converts C++ hash to proto Hash
/// \param h C++ hash to convert
/// \param proto_h Pointer to proto Hash receiving result of conversion
CM_API void set_proto_hash(const machine_merkle_tree::hash_type &h, CartesiMachine::Hash *proto_h);

/// \brief Converts C++ Merkle tree proof to proto Merkle tree Proof
/// \param p C++ proof to convert
/// \param proto_p Pointer to proto Proof receiving result of conversion
CM_API void set_proto_merkle_tree_proof(const machine_merkle_tree::proof_type &p,
    CartesiMachine::MerkleTreeProof *proto_p);

/// \brief Converts proto Proof to C++ proof
/// \param proto_proof Proto proof to convert
/// \returns Converted C++ proof
CM_API machine_merkle_tree::proof_type get_proto_merkle_tree_proof(const CartesiMachine::MerkleTreeProof &proto_proof);

/// \brief Converts C++ access_log to proto Access_Log
/// \param al C++ access_log to convert
/// \param proto_al Pointer to proto AccessLog receiving result of conversion
CM_API void set_proto_access_log(const access_log &al, CartesiMachine::AccessLog *proto_al);

/// \brief Converts proto AccessLog to C++ access_log
/// \param proto_al Proto AccessLog to convert
/// \returns Converted C++ access_log
CM_API access_log get_proto_access_log(const CartesiMachine::AccessLog &proto_al);

/// \brief Converts proto MemoryRangeConfig to C++ memory_range_config
/// \param proto_m Proto MemoryRangeConfig to convert
/// \returns Converted C++ memory_range_config
CM_API memory_range_config get_proto_memory_range_config(const CartesiMachine::MemoryRangeConfig &proto_m);

/// \brief Converts proto BracketType to C++ bracket_type
/// \param proto_b Proto BracketType  to convert
/// \returns Converted C++ bracket_type
CM_API bracket_type get_proto_bracket_type(CartesiMachine::BracketNote_BracketNoteType proto_b);

/// \brief Converts proto AccessType to C++ access_type
/// \param proto_at Proto AccessType to convert
/// \returns Converted C++ access_type
CM_API access_type get_proto_access_type(CartesiMachine::AccessType proto_at);

/// \brief Converts proto SemanticVersion to C++ semantic_version
/// \param proto_v Proto SemanticVersion to convert
/// \returns Converted C++ semantic_version
CM_API semantic_version get_proto_semantic_version(const Versioning::SemanticVersion &proto_v);

/// \brief Converts C++ machine_memory_range_descr to proto MemoryRangeDescription
/// \param d C++ machine_memory_range_descr to convert
/// \param proto_d Pointer to proto repeated MemoryRangeDescription receiving result of conversion
CM_API void set_proto_memory_range_descr(const machine_memory_range_descr &d,
    CartesiMachine::MemoryRangeDescription *proto_d);

/// \brief Converts proto MemoryRangeDescription to C++ machine_memory_range_descr
/// \param proto_d Proto MemoryRangeDescription to convert
/// \returns Converted C++ machine_memory_range_descr
CM_API machine_memory_range_descr get_proto_memory_range_descr(const CartesiMachine::MemoryRangeDescription &proto_d);

} // namespace cartesi
