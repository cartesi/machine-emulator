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
#include <hash-tree-proof.h>
#include <json-util.h>
#include <machine-c-api.h>
#include <machine-hash.h>
#include <variant-hasher.h>

// Calculate root hash for data buffer of log2_size
namespace detail {

constexpr int HASH_TREE_WORD_LOG2_SIZE = 5;
constexpr int HASH_TREE_PAGE_LOG2_SIZE = 12;
constexpr int HASH_TREE_PAGE_SIZE = (UINT64_C(1) << HASH_TREE_PAGE_LOG2_SIZE);

static cartesi::machine_hash merkle_hash(cartesi::variant_hasher &h, const std::string_view &data, int log2_size) {
    cartesi::machine_hash result;
    if (log2_size > HASH_TREE_WORD_LOG2_SIZE) {
        --log2_size;
        auto half_size = data.size() / 2;
        auto left = merkle_hash(h, std::string_view{data.data() + 0, half_size}, log2_size);
        auto right = merkle_hash(h, std::string_view{data.data() + half_size, half_size}, log2_size);
        get_concat_hash(h, left, right, result);
    } else {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        h.hash(data, result);
    }
    return result;
}

} // namespace detail

// \brief Creates a hasher object compatible with the one used by the machine's config
static cartesi::hash_function_type get_machine_hash_function(cm_machine *machine) {
    const char *cfg_jsonstr{};
    cm_error error_code = cm_get_initial_config(machine, &cfg_jsonstr);
    if (error_code != 0) {
        throw std::runtime_error{cm_get_last_error_message()};
    }
    const auto cfg = cartesi::from_json<cartesi::machine_config>(cfg_jsonstr, "config");
    return cfg.hash_tree.hash_function;
}

static cartesi::machine_hash merkle_hash(cartesi::variant_hasher &h, const std::string_view &data, int log2_size) {
    if (log2_size > 63) {
        throw std::domain_error("log2_size is too large");
    }
    if (log2_size < 3) {
        throw std::domain_error("log2_size is too small");
    }
    if ((UINT64_C(1) << log2_size) != data.size()) {
        throw std::invalid_argument("log2_size does not match data size");
    }
    return detail::merkle_hash(h, data, log2_size);
}

static cartesi::machine_hash calculate_proof_root_hash(cartesi::variant_hasher &h,
    const cartesi::hash_tree_proof &proof) {
    cartesi::machine_hash hash;
    memcpy(hash.data(), proof.get_target_hash().data(), sizeof(cm_hash));
    for (int log2_size = proof.get_log2_target_size(); log2_size < proof.get_log2_root_size(); ++log2_size) {
        auto bit = (proof.get_target_address() & (UINT64_C(1) << log2_size));
        cartesi::machine_hash first;
        cartesi::machine_hash second;
        if (bit != 0) {
            memcpy(first.data(), proof.get_sibling_hashes()[log2_size - proof.get_log2_target_size()].data(),
                sizeof(cm_hash));
            second = hash;
        } else {
            first = hash;
            memcpy(second.data(), proof.get_sibling_hashes()[log2_size - proof.get_log2_target_size()].data(),
                sizeof(cm_hash));
        }
        get_concat_hash(h, first, second, hash);
    }
    return hash;
}

static cartesi::machine_hash calculate_emulator_hash(cm_machine *machine) {
    const auto hash_function = get_machine_hash_function(machine);
    cartesi::variant_hasher h{hash_function};
    const auto pristine_pad_hashes = cartesi::back_merkle_tree::make_pristine_pad_hashes(CM_HASH_TREE_LOG2_ROOT_SIZE,
        CM_HASH_TREE_LOG2_PAGE_SIZE, CM_HASH_TREE_LOG2_WORD_SIZE, hash_function);
    cartesi::back_merkle_tree tree{CM_HASH_TREE_LOG2_ROOT_SIZE, CM_HASH_TREE_LOG2_PAGE_SIZE,
        CM_HASH_TREE_LOG2_WORD_SIZE, hash_function};
    std::string page;
    page.resize(detail::HASH_TREE_PAGE_SIZE);
    const char *ranges_jsonstr{};
    if (cm_get_address_ranges(machine, &ranges_jsonstr) != 0) {
        throw std::runtime_error{cm_get_last_error_message()};
    }
    const auto mrds = cartesi::from_json<cartesi::address_range_descriptions>(ranges_jsonstr, "memory_ranges");
    uint64_t last = 0;
    for (const auto &m : mrds) {
        tree.pad_back((m.start - last) >> detail::HASH_TREE_PAGE_LOG2_SIZE, pristine_pad_hashes);
        auto end = m.start + m.length;
        for (uint64_t s = m.start; s < end; s += detail::HASH_TREE_PAGE_SIZE) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            if (cm_read_memory(machine, s, reinterpret_cast<unsigned char *>(page.data()), page.size()) != 0) {
                throw std::runtime_error{cm_get_last_error_message()};
            }
            auto page_hash = merkle_hash(h, page, detail::HASH_TREE_PAGE_LOG2_SIZE);
            tree.push_back(page_hash);
        }
        last = end;
    }
    tree.pad_back(tree.get_remaining_leaf_count(), pristine_pad_hashes);
    return tree.get_root_hash();
}
