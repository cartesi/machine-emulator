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

#include <string>

#include <back-merkle-tree.h>
#include <keccak-256-hasher.h>
#include <machine-c-api.h>

using hash_type = cartesi::keccak_256_hasher::hash_type;

// Calculate root hash for data buffer of log2_size
namespace detail {

constexpr int WORD_LOG2_SIZE = 5;
constexpr int MERKLE_PAGE_LOG2_SIZE = 12;
constexpr int MERKLE_PAGE_SIZE = (UINT64_C(1) << MERKLE_PAGE_LOG2_SIZE);

static hash_type merkle_hash(cartesi::keccak_256_hasher &h, const std::string_view &data, int log2_size) {
    hash_type result;
    if (log2_size > WORD_LOG2_SIZE) {
        --log2_size;
        auto half_size = data.size() / 2;
        auto left = merkle_hash(h, std::string_view{data.data(), half_size}, log2_size);
        auto right = merkle_hash(h, std::string_view{data.data() + half_size, half_size}, log2_size);
        get_concat_hash(h, left, right, result);
    } else {
        h.begin();
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        h.add_data(reinterpret_cast<const unsigned char *>(data.data()), data.size());
        h.end(result);
    }
    return result;
}

} // namespace detail

static hash_type merkle_hash(const std::string_view &data, int log2_size) {
    if (log2_size > 63) {
        throw std::domain_error("log2_size is too large");
    }
    if (log2_size < 3) {
        throw std::domain_error("log2_size is too small");
    }
    if ((UINT64_C(1) << log2_size) != data.size()) {
        throw std::invalid_argument("log2_size does not match data size");
    }
    cartesi::keccak_256_hasher h;
    return detail::merkle_hash(h, data, log2_size);
}

static hash_type calculate_proof_root_hash(const cm_merkle_tree_proof *proof) {
    hash_type hash;
    memcpy(hash.data(), proof->target_hash, sizeof(cm_hash));
    for (int log2_size = static_cast<int>(proof->log2_target_size); log2_size < static_cast<int>(proof->log2_root_size);
         ++log2_size) {
        cartesi::keccak_256_hasher h;
        auto bit = (proof->target_address & (UINT64_C(1) << log2_size));
        hash_type first;
        hash_type second;
        if (bit) {
            memcpy(first.data(), proof->sibling_hashes.entry[log2_size - proof->log2_target_size], sizeof(cm_hash));
            second = hash;
        } else {
            first = hash;
            memcpy(second.data(), proof->sibling_hashes.entry[log2_size - proof->log2_target_size], sizeof(cm_hash));
        }
        get_concat_hash(h, first, second, hash);
    }
    return hash;
}

static hash_type calculate_emulator_hash(cm_machine *machine) {
    cartesi::back_merkle_tree tree(CM_TREE_LOG2_ROOT_SIZE, CM_TREE_LOG2_PAGE_SIZE, CM_TREE_LOG2_WORD_SIZE);
    std::string page;
    page.resize(detail::MERKLE_PAGE_SIZE);
    cm_memory_range_descr_array *mrds = nullptr;
    auto mrds_deleter = [](cm_memory_range_descr_array **mrds) { cm_delete_memory_range_descr_array(*mrds); };
    std::unique_ptr<cm_memory_range_descr_array *, decltype(mrds_deleter)> auto_mrds(&mrds, mrds_deleter);
    char *err_msg = nullptr;
    auto err_msg_deleter = [](char **str) { cm_delete_cstring(*str); };
    std::unique_ptr<char *, decltype(err_msg_deleter)> auto_err_msg(&err_msg, err_msg_deleter);
    if (cm_get_memory_ranges(machine, &mrds, &err_msg) != 0) {
        throw std::runtime_error{err_msg};
    }
    uint64_t last = 0;
    for (size_t i = 0; i < mrds->count; ++i) {
        const auto &m = mrds->entry[i];
        tree.pad_back((m.start - last) >> detail::MERKLE_PAGE_LOG2_SIZE);
        auto end = m.start + m.length;
        for (uint64_t s = m.start; s < end; s += detail::MERKLE_PAGE_SIZE) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            if (cm_read_memory(machine, s, reinterpret_cast<unsigned char *>(page.data()), page.size(), &err_msg) !=
                0) {
                throw std::runtime_error{err_msg};
            }
            auto page_hash = merkle_hash(page, detail::MERKLE_PAGE_LOG2_SIZE);
            tree.push_back(page_hash);
        }
        last = end;
    }
    return tree.get_root_hash();
}
