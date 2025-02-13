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

#include <machine-merkle-tree.h>
#include <shadow-uarch-state.h>
#include <uarch-constants.h>
#include <uarch-pristine.h>
#include <uarch-state.h>
#include <unique-c-ptr.h>

/// \file
/// \brief This program computes the hash of the pristine uarch state ad writes it to stdout

using namespace cartesi;

using tree_type = machine_merkle_tree;
using hash_type = tree_type::hash_type;
using hashertype = tree_type::hasher_type;
using proof_type = tree_type::proof_type;

static_assert(PMA_PAGE_SIZE == tree_type::get_page_size(), "PMA and machine_merkle_tree page sizes must match");
static_assert(sizeof(shadow_uarch_state) <= PMA_PAGE_SIZE, "shadow_uarch_state must fit in one page");

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
    tree_type tree{};
    hashertype hasher{};
    hash_type hash{};

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
    auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        throw std::runtime_error("Could not allocate scratch memory");
    }

    // Build pristine shadow uarch state
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *shadow = reinterpret_cast<shadow_uarch_state *>(scratch.get());
    memset(scratch.get(), 0, PMA_PAGE_SIZE);
    shadow->halt_flag = UARCH_HALT_FLAG_INIT;
    shadow->pc = UARCH_PC_INIT;
    shadow->cycle = UARCH_CYCLE_INIT;
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        shadow->x[i] = UARCH_X_INIT;
    }

    // Start updating merkle tree
    tree.begin_update();
    // Add shadow uarch state to merkle tree
    tree.get_page_node_hash(hasher, scratch.get(), hash);
    if (!tree.update_page_node_hash(UARCH_SHADOW_START_ADDRESS, hash)) {
        throw std::runtime_error("Could not update uarch shadow tree node hash");
    }
    // Add all pages of uarch ram to merkle tree
    for (uint32_t p = 0; p < uarch_pristine_ram_len; p += PMA_PAGE_SIZE) {
        const auto *page_data = uarch_pristine_ram + p;
        if (p + PMA_PAGE_SIZE > uarch_pristine_ram_len) {
            memset(scratch.get(), 0, PMA_PAGE_SIZE);
            memcpy(scratch.get(), uarch_pristine_ram + p, uarch_pristine_ram_len - p);
            page_data = scratch.get();
        }
        tree.get_page_node_hash(hasher, page_data, hash);
        if (!tree.update_page_node_hash(UARCH_RAM_START_ADDRESS + p, hash)) {
            throw std::runtime_error("Could not update uarch ram tree node hash");
        }
    }

    // Get uarch root hash
    if (!tree.end_update(hasher)) {
        throw std::runtime_error("end_update merkle tree failed");
    }
    proof_type proof = tree.get_proof(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE, nullptr);
    auto &uarch_state_hash = proof.get_target_hash();

    // Print header
    std::cout << "// This file is auto-generated and should not be modified" << std::endl;

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
    std::cout << "\n};\nunsigned int uarch_pristine_hash_len = " << std::dec << uarch_state_hash.size() << ";"
              << std::endl;

    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
