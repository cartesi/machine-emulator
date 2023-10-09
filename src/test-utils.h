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

#include <array>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "back-merkle-tree.h"
#include "keccak-256-hasher.h"
#include "machine-c-api.h"
#include "pma-constants.h"

using hash_type = cartesi::keccak_256_hasher::hash_type;

// Calculate root hash for data buffer of log2_size
namespace detail {

constexpr int WORD_LOG2_SIZE = 3;
constexpr int PAGE_LOG2_SIZE = 12;
constexpr int PAGE_SIZE = (UINT64_C(1) << PAGE_LOG2_SIZE);

static hash_type merkle_hash(cartesi::keccak_256_hasher &h, const std::string_view &data, int log2_size) {
    hash_type result;
    if (log2_size > WORD_LOG2_SIZE) {
        --log2_size;
        auto half_size = data.size() / 2;
        auto left = merkle_hash(h, std::string_view{data.data(), half_size}, log2_size);
        auto right = merkle_hash(h, std::string_view{data.data() + half_size, half_size}, log2_size);
        get_concat_hash(h, left, right, result);
    } else {
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

// static std::string load_file(const std::string &path) {
// std::ifstream ifs(path, std::ios::binary);
// return std::string{std::istreambuf_iterator<char>{ifs}, {}};
//}

static std::string load_file(const std::string &path) {
    std::streampos size;
    std::ifstream file(path, std::ios::binary);
    file.seekg(0, std::ios::end);
    size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::string data;
    data.resize(size);
    file.read(data.data(), data.size());
    return data;
}

static hash_type calculate_proof_root_hash(const cm_merkle_tree_proof *proof) {
    hash_type hash;
    memcpy(hash.data(), proof->target_hash, sizeof(cm_hash));
    for (int log2_size = static_cast<int>(proof->log2_target_size); log2_size < static_cast<int>(proof->log2_root_size);
         ++log2_size) {
        cartesi::keccak_256_hasher h;
        auto bit = (proof->target_address & (UINT64_C(1) << log2_size));
        hash_type first, second;
        if (bit) {
            memcpy(first.data(), proof->sibling_hashes.entry[proof->log2_root_size - log2_size - 1], sizeof(cm_hash));
            second = hash;
        } else {
            first = hash;
            memcpy(second.data(), proof->sibling_hashes.entry[proof->log2_root_size - log2_size - 1], sizeof(cm_hash));
        }
        get_concat_hash(h, first, second, hash);
    }
    return hash;
}

static int ceil_log2(uint64_t x) {
    return static_cast<int>(std::ceil(std::log2(static_cast<double>(x))));
}

static hash_type calculate_emulator_hash(const std::vector<std::string> &pmas_files) {
    struct pma_entry {
        std::string path;
        uint64_t start;
        uint64_t length;
        std::string data;
    };
    std::vector<pma_entry> pma_entries;
    std::transform(pmas_files.begin(), pmas_files.end(), std::back_inserter(pma_entries), [](const std::string &path) {
        uint64_t start;
        uint64_t length;
        int end = 0;
        if (sscanf(path.data(), "%" SCNx64 "--%" SCNx64 ".bin%n", &start, &length, &end) != 2 ||
            static_cast<int>(path.size()) != end) {
            throw std::invalid_argument("PMA filename '" + path + "' does not match '%x--%x.bin'");
        }
        if ((length >> detail::PAGE_LOG2_SIZE) << detail::PAGE_LOG2_SIZE != length) {
            throw std::invalid_argument("PMA '" + path + "' length not multiple of page length");
        }
        if ((start >> detail::PAGE_LOG2_SIZE) << detail::PAGE_LOG2_SIZE != start) {
            throw std::invalid_argument("PMA '" + path + "' start not page-aligned");
        }
        auto data = load_file(path);
        if (data.length() != length) {
            throw std::invalid_argument("PMA '" + path + "' length does not match filename");
        }
        return pma_entry{path, start, length, std::move(data)};
    });
    std::sort(pma_entries.begin(), pma_entries.end(),
        [](const pma_entry &a, const pma_entry &b) { return a.start < b.start; });
    cartesi::back_merkle_tree tree(64, 12, 3);
    uint64_t last = 0;
    for (const auto &e : pma_entries) {
        tree.pad_back((e.start - last) >> detail::PAGE_LOG2_SIZE);
        for (uint64_t s = 0; s < e.length; s += detail::PAGE_SIZE) {
            std::string_view page{e.data.data() + s, detail::PAGE_SIZE};
            auto page_hash = merkle_hash(page, detail::PAGE_LOG2_SIZE);
            tree.push_back(page_hash);
        }
        last = e.start + e.length;
    }
    return tree.get_root_hash();
}
