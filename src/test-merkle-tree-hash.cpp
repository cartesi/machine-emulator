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
#include <cassert>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>

#include "back-merkle-tree.h"
#include "complete-merkle-tree.h"
#include "full-merkle-tree.h"
#include "merkle-tree-proof.h"
#include "pristine-merkle-tree.h"
#include "unique-c-ptr.h"
#include "xkcp-keccak-256-hasher.h"

using namespace cartesi;
using hasher_type = xkcp_keccak_256_hasher;
using hash_type = hasher_type::hash_type;

/// \brief Checks if string matches prefix and captures remaninder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remaninder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    const size_t len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        *val = str + len;
        return true;
    }
    return false;
}

/// \brief Checks if string matches prefix and captures int that follows
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix and conversion to int succeeds, points
/// to converted int
/// \returns True if string matches prefix and conversion succeeds,
/// false otherwise
static bool intval(const char *pre, const char *str, int *val) {
    const size_t len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        str += len;
        int end = 0;
        // NOLINTNEXTLINE(cert-err34-c): %n is used toverify conversion errors
        return sscanf(str, "%d%n", val, &end) == 1 && !str[end];
    }
    return false;
}

/// \brief Prints hash in hex to file
/// \param hash Hash to be printed.
/// \param f File to print to
static void print_hash(const hash_type &hash, FILE *f) {
    for (auto b : hash) {
        (void) fprintf(f, "%02x", static_cast<int>(b));
    }
    (void) fprintf(f, "\n");
}

#if 0 // Unused
/// \brief Reads a hash in hex from file
/// \param f File to read from
/// \returns Hash if successful, nothing otherwise
static std::optional<hash_type> read_hash(FILE *f) {
    std::array<char, hasher_type::hash_size * 2> hex_hash{};
    if (fread(hex_hash.data(), 1, hex_hash.size(), f) != hex_hash.size()) {
        return {};
    }
    hash_type h;
    for (size_t i = 0; i < hasher_type::hash_size; ++i) {
        std::array<char, 3> hex_c = {hex_hash[2 * i], hex_hash[2 * i + 1], '\0'};
        unsigned c = 0;
        // NOLINTNEXTLINE(cert-err34-c): we just generated the string so we don't need to verify it
        if (sscanf(hex_c.data(), "%x", &c) != 1) {
            return {};
        }
        h[i] = c;
    }
    return h;
}
#endif

/// \brief Prints formatted message to stderr
/// \param fmt Format string
/// \param ... Arguments, if any
// NOLINTNEXTLINE(cert-dcl50-cpp): this vararg is safe because the compiler can check the format
__attribute__((format(printf, 1, 2))) static void error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    (void) vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

/// \brief Computes the hash of a word
/// \param h Hasher object
/// \param leaf Pointer to leaf data. Must contain 2^log2_word_size bytes
/// \param log2_word Log<sub>2</sub> of word size
/// \param hash Receives the leaf hash
static void get_word_hash(hasher_type &h, const unsigned char *word, int log2_word_size, hash_type &hash) {
    h.begin();
    h.add_data(word, 1 << log2_word_size);
    h.end(hash);
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param h Hasher object
/// \param log2_word_size Log<sub>2</sub> of word size
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(hasher_type &h, int log2_word_size, const unsigned char *leaf_data, int log2_leaf_size) {
    assert(log2_leaf_size >= log2_word_size);
    if (log2_leaf_size > log2_word_size) {
        hash_type left = get_leaf_hash(h, log2_word_size, leaf_data, log2_leaf_size - 1);
        const hash_type right =
            get_leaf_hash(h, log2_word_size, leaf_data + (1 << (log2_leaf_size - 1)), log2_leaf_size - 1);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        hash_type leaf;
        get_word_hash(h, leaf_data, log2_word_size, leaf);
        return leaf;
    }
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param log2_word_size Log<sub>2</sub> of word size
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(int log2_word_size, const unsigned char *leaf_data, int log2_leaf_size) {
    hasher_type h;
    return get_leaf_hash(h, log2_word_size, leaf_data, log2_leaf_size);
}

/// \brief Prints help message
static void help(const char *name) {
    (void) fprintf(stderr,
        "Usage:\n  %s [--input=<filename>] "
        "[--log2-word-size=<w>] [--log2-leaf-size=<p>] "
        "[--log2-root-size=<t>]\n",
        name);
    exit(0);
}

int main(int argc, char *argv[]) try {
    const char *input_name = nullptr;
    int log2_word_size = 3;
    int log2_leaf_size = 12;
    int log2_root_size = 30;
    // int incremental = false;
    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            return 1;
        } else if (stringval("--input=", argv[i], &input_name)) {
            ;
        } else if (intval("--log2-word-size=", argv[i], &log2_word_size)) {
            ;
        } else if (intval("--log2-leaf-size=", argv[i], &log2_leaf_size)) {
            ;
        } else if (intval("--log2-root-size=", argv[i], &log2_root_size)) {
            ;
        } else {
            error("unrecognized option '%s'\n", argv[i]);
            return 1;
        }
    }
    if (log2_word_size < 0 || log2_word_size > 64 || log2_leaf_size < log2_word_size || log2_leaf_size >= 64 ||
        log2_leaf_size > log2_root_size || log2_root_size >= 64) {
        error("invalid word size (%d) / leaf size (%d) / root size (%d) combination\n", log2_word_size, log2_leaf_size,
            log2_root_size);
        return 1;
    }
    // Read from stdin if no input name was given
    auto input_file = unique_file_ptr{stdin};
    if (input_name) {
        input_file = unique_fopen(input_name, "ro", std::nothrow_t{});
        if (!input_file) {
            error("unable to open input file '%s'\n", input_name);
            return 1;
        }
    }

    // Allocate buffer for leaf data
    uint64_t leaf_size = UINT64_C(1) << log2_leaf_size;
    auto leaf_buf = unique_calloc<unsigned char>(leaf_size, std::nothrow_t{});
    if (!leaf_buf) {
        error("unable to allocate leaf buffer\n");
        return 1;
    }

    std::cerr << "instantiating back tree\n";
    back_merkle_tree back_tree{log2_root_size, log2_leaf_size, log2_word_size};

    std::cerr << "instantiating complete tree\n";
    complete_merkle_tree complete_tree{log2_root_size, log2_leaf_size, log2_word_size};

    std::vector<hash_type> leaf_hashes;

    uint64_t max_leaves = UINT64_C(1) << (log2_root_size - log2_leaf_size);
    uint64_t leaf_count = 0;
    // Loop reading leaves from file until done or error
    // As each leaf is loaded, we check that all four implementations
    // have a consistent root:
    // 1) The back_merkle_tree can receive leaf hashes and incrementally
    // obtain the tree root in log time and keeping log size state
    // 2) The full_merkle_tree builds a tree from scratch based on
    // all leaf hashes
    // 3) The full_merkle_tree can also receive leaf hashes and a
    // log-size proof for the leaf currently in the tree and udpate
    // the root hash in log time keeping only constant size state.
    // 4) The complete_merkle_tree can receive leaf hashes and maintain
    // only the part of the tree that is not pristine
    hasher_type h;
    while (true) {
        auto got = fread(leaf_buf.get(), 1, leaf_size, input_file.get());
        if (got == 0) {
            if (ferror(input_file.get())) {
                error("error reading input\n");
                return 1;
            } else {
                break;
            }
        }
        if (leaf_count >= max_leaves) {
            error("too many leaves for tree\n");
            return 1;
        }
        // Pad leaf with zeros if file ended before next leaf boundary
        memset(leaf_buf.get() + got, 0, leaf_size - got);
        // Compute leaf hash
        auto leaf_hash = get_leaf_hash(log2_word_size, leaf_buf.get(), log2_leaf_size);
        // Add to array of leaf hashes
        leaf_hashes.push_back(leaf_hash);
        // Print leaf hash
        print_hash(leaf_hash, stderr);
        // Get value proof for position of new leaf from incremental tree
        auto back_leaf_proof = back_tree.get_next_leaf_proof();
        // Add new leaf to back tree
        back_tree.push_back(leaf_hash);
        // Build full tree from array of leaf hashes
        full_merkle_tree tree_from_scratch(log2_root_size, log2_leaf_size, log2_word_size, leaf_hashes);
        // Compare the root hash for the back tree and the tree
        // from scratch
        if (back_tree.get_root_hash() != tree_from_scratch.get_root_hash()) {
            error("mismatch in root hash for back tree and "
                  "tree from scratch\n");
            return 1;
        }
        // Update back proof with new leaf
        back_leaf_proof.set_root_hash(back_leaf_proof.bubble_up(h, leaf_hash));
        back_leaf_proof.set_target_hash(leaf_hash);
        if (!back_leaf_proof.verify(h)) {
            error("updated back leaf proof failed verification\n");
            return 1;
        }
        // Compare updated proof with proof generated from full tree
        auto from_scratch_leaf_proof = tree_from_scratch.get_proof(leaf_count << log2_leaf_size, log2_leaf_size);
        if (back_leaf_proof != from_scratch_leaf_proof) {
            error("mismatch in leaf proofs for back tree and "
                  "tree from scratch\n");
        }
        // Add new leaf to complete tree
        complete_tree.push_back(leaf_hash);
        // Compare the root hash for the coimplete tree and the tree
        // from scratch
        if (complete_tree.get_root_hash() != tree_from_scratch.get_root_hash()) {
            error("mismatch in root hash for complete tree and "
                  "tree from scratch\n");
            return 1;
        }
        // Compare proof generated from full tree with proof generated
        // from complete tree
        auto complete_leaf_proof = complete_tree.get_proof(leaf_count << log2_leaf_size, log2_leaf_size);
        if (from_scratch_leaf_proof != complete_leaf_proof) {
            error("mismatch in leaf proofs for full tree and "
                  "tree from scratch\n");
        }
        ++leaf_count;
    }
    (void) fprintf(stderr, "passed test\n");
    print_hash(back_tree.get_root_hash(), stdout);
    return 0;
} catch (std::exception &x) {
    std::cerr << "Caught exception: " << x.what() << '\n';
    exit(1);
}
