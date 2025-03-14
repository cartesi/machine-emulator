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

#ifndef I_DENSE_HASH_TREE_H
#define I_DENSE_HASH_TREE_H

#include "hash-tree-constants.h"
#include "machine-hash.h"

namespace cartesi {

class i_dense_hash_tree {
public:
    machine_hash_view node_hash_view(uint64_t offset, int log2_size) noexcept {
        return do_node_hash_view(offset, log2_size);
    }
    const_machine_hash_view node_hash_view(uint64_t offset, int log2_size) const noexcept {
        return do_node_hash_view(offset, log2_size);
    }
    const_machine_hash_view root_hash_view() const noexcept {
        return do_root_hash_view();
    }

protected:
    machine_hash_view no_hash_view() noexcept {
        static machine_hash no_hash{};
        return machine_hash_view{no_hash};
    }
    const_machine_hash_view no_hash_view() const noexcept {
        static constexpr machine_hash no_hash{};
        return const_machine_hash_view{no_hash};
    }

private:
    virtual const_machine_hash_view do_node_hash_view(uint64_t offset, int log2_size) const noexcept = 0;
    virtual machine_hash_view do_node_hash_view(uint64_t offset, int log2_size) noexcept = 0;
    virtual const_machine_hash_view do_root_hash_view() const noexcept = 0;
};

class empty_dense_hash_tree : public i_dense_hash_tree {
    const_machine_hash_view do_node_hash_view(uint64_t, int) const noexcept override {
        return no_hash_view();
    }
    machine_hash_view do_node_hash_view(uint64_t, int) noexcept override {
        return no_hash_view();
    }
    const_machine_hash_view do_root_hash_view() const noexcept override {
        return no_hash_view();
    }
};

} // namespace cartesi

#endif // I_DENSE_HASH_TREE_H
