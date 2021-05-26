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

#ifndef MERKLE_PROOF_H
#define MERKLE_PROOF_H

/// \file
/// \brief Merkle proof structure

#include <cstdint>
#include <array>

namespace cartesi {

/// \brief Merkle proof structure
/// \details \{
/// This structure holds a proof that the node spanning a log2_size
/// at a given address in the tree has a certain hash.
/// \}
/// \tparam HASH_TYPE the type that holds a hash
/// \tparam DEPTH the tree depth
/// \tparam ADDRESS_TYPE the type that holds an address
template <
    typename HASH_TYPE,
    int DEPTH,
    typename ADDRESS_TYPE = uint64_t
>
struct merkle_proof {
    /// \brief Storage for the hashes of the siblings of all nodes along
    /// the path from the root to target node (at most DEPTH entries).
    using siblings_type = std::array<HASH_TYPE, DEPTH>;
    ADDRESS_TYPE address{0};        ///< Address of target node
    int log2_size{0};               ///< log<sub>2</sub> of size subintended by target node.
    HASH_TYPE target_hash{};        ///< Hash of target node
    siblings_type sibling_hashes{}; ///< Hashes of siblings
    HASH_TYPE root_hash{};          ///< Hash of root node
};

} // namespace cartesi

#endif
