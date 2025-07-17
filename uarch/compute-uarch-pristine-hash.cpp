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

#include <cstring>
#include <iomanip>
#include <iostream>

#include <back-merkle-tree.h>
#include <hash-tree-constants.h>
#include <keccak-256-hasher.h>
#include <shadow-uarch-state.h>
#include <uarch-constants.h>
#include <uarch-pristine.h>
#include <uarch-processor-state.h>
#include <unique-c-ptr.h>

/// \file
/// \brief This program computes the hash of the pristine uarch state ad writes it to stdout

using namespace cartesi;

static constexpr auto word_size = HASH_TREE_WORD_SIZE;
static constexpr auto log2_word_size = HASH_TREE_LOG2_WORD_SIZE;
static constexpr auto page_size = HASH_TREE_PAGE_SIZE;
static constexpr auto log2_page_size = HASH_TREE_LOG2_PAGE_SIZE;

static_assert(AR_PAGE_SIZE == page_size, "address-range and hash-tree page sizes must match");
static_assert(sizeof(shadow_uarch_state) <= page_size, "shadow_uarch_state must fit in one page");
static_assert(AR_SHADOW_UARCH_STATE_LENGTH >= sizeof(shadow_uarch_state),
    "shadow uarch state must fit in its address range");
static_assert(AR_SHADOW_UARCH_STATE_LENGTH >= page_size,
    "shadow uarch state address range must be a least one page long");
static_assert(AR_UARCH_RAM_START % page_size == 0, "uarch ram start must be aligned to page size");
static_assert(AR_SHADOW_UARCH_STATE_START % page_size == 0, "shadow uarch state start must be aligned to page size");
static_assert(AR_UARCH_RAM_START >= AR_SHADOW_UARCH_STATE_START + AR_SHADOW_UARCH_STATE_LENGTH,
    "shadow ram must start after shadow uarch state");

/// \brief Prints help message
static void help(const char *name) {
    std::cerr << R"(Usage:

  )" << name << R"( [options]

Computes the hash of the pristine uarch state.

Options:

  --help
  Prints this message and returns.
)";
    exit(0);
}

int main(int argc, char *argv[]) try {
    back_merkle_tree tree{UARCH_STATE_LOG2_SIZE, log2_page_size, log2_word_size, hash_function_type::keccak256};
    keccak_256_hasher hasher{};
    machine_hash hash{};

    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
        } else {
            std::cerr << "unrecognized option '" << argv[i] << "'\n";
            exit(1);
        }
    }

    // Allocate scratch page buffer
    auto scratch = make_unique_calloc<unsigned char>(page_size, std::nothrow_t{});
    if (!scratch) {
        throw std::runtime_error("Could not allocate scratch memory");
    }
    auto scratch_span = std::span<unsigned char>{scratch.get(), page_size};
    machine_hash pristine_hash;
    get_merkle_tree_hash(hasher, scratch_span, word_size, pristine_hash);

    // Build pristine shadow uarch state
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *shadow = reinterpret_cast<shadow_uarch_state *>(scratch.get());
    memset(scratch.get(), 0, page_size);
    shadow->halt_flag = UARCH_HALT_FLAG_INIT;
    shadow->pc = UARCH_PC_INIT;
    shadow->cycle = UARCH_CYCLE_INIT;
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        shadow->x[i] = UARCH_X_INIT;
    }
    // Add shadow uarch state to merkle tree
    get_merkle_tree_hash(hasher, scratch_span, word_size, hash);
    tree.push_back(hash);
    // Add pristine gap between shadow uarch state and uarch RAM
    if (auto gap = (AR_UARCH_RAM_START - page_size - AR_SHADOW_UARCH_STATE_START) / page_size; gap != 0) {
        tree.pad_back(gap);
    }
    // Add all pages of uarch ram to merkle tree
    for (uint32_t p = 0; p < uarch_pristine_ram_len; p += page_size) {
        const auto *page_data = uarch_pristine_ram + p;
        if (p + page_size > uarch_pristine_ram_len) {
            memset(scratch.get(), 0, page_size);
            memcpy(scratch.get(), uarch_pristine_ram + p, uarch_pristine_ram_len - p);
            page_data = scratch.get();
        }
        std::span<const unsigned char, page_size> page_data_span(page_data, page_size);
        get_merkle_tree_hash(hasher, page_data_span, word_size, hash);
        tree.push_back(hash);
    }
    // Get uarch state hash
    auto uarch_state_hash = tree.get_root_hash();
    // Print header
    std::cout << "// This file is auto-generated and should not be modified\n";
    // Print hash
    std::cout << "unsigned char uarch_pristine_hash[] = {\n  ";
    int i = 0;
    for (auto c : uarch_state_hash) {
        if (i > 0 && i % 12 == 0) {
            std::cout << ",\n  ";
        } else if (i > 0) {
            std::cout << ", ";
        }
        std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(c);
        i++;
    }
    std::cout << "\n};\nunsigned int uarch_pristine_hash_len = " << std::dec << uarch_state_hash.size() << ";\n";
    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
