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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>

#include "back-merkle-tree.h"
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
        std::array<char, 3> hex_c{hex_hash[2 * i], hex_hash[2 * i + 1], '\0'};
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
/// \param word Pointer to word data. Must contain 2^log2_word_size bytes
/// \param log2_word_size Log<sub>2</sub> of word size
/// \param hash Receives the word hash
static void get_word_hash(hasher_type &h, const unsigned char *word, int log2_word_size, hash_type &hash) {
    h.begin();
    h.add_data(word, 1 << log2_word_size);
    h.end(hash);
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param h Hasher object
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \param log2_word_size Log<sub>2</sub> of word size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(hasher_type &h, const unsigned char *leaf_data, int log2_leaf_size, int log2_word_size) {
    assert(log2_leaf_size >= log2_word_size);
    if (log2_leaf_size > log2_word_size) {
        hash_type left = get_leaf_hash(h, leaf_data, log2_leaf_size - 1, log2_word_size);
        const hash_type right =
            get_leaf_hash(h, leaf_data + (1 << (log2_leaf_size - 1)), log2_leaf_size - 1, log2_word_size);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        hash_type leaf;
        get_word_hash(h, leaf_data, log2_word_size, leaf);
        return leaf;
    }
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \param log2_word_size Log<sub>2</sub> of word size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(const unsigned char *leaf_data, int log2_leaf_size, int log2_word_size) {
    hasher_type h;
    return get_leaf_hash(h, leaf_data, log2_leaf_size, log2_word_size);
}

/// \brief Prints help message
static void help(const char *name) {
    (void) fprintf(stderr, R"(Usage:

  %s --log2-root-size=<integer> [options]

Computes the Merkle tree root hash of 2^log2_root_size bytes read from
a file. If the file contains fewer than 2^log2_root_size bytes, it is
ostensibly padded with zeros to 2^log2_root_size bytes.

Each node hash corresponding to a data range with 2^log2_node_size bytes
is the hash of the concatenation of the node hashes of its two subranges
with 2^(log2_node_size-1) bytes.

The node hash corresponding to word with 2^log2_word_size bytes is simply
the hash of the data in the range.

The Merkle tree root hash is simply the node hash corresponding to the
entire 2^log2_root_size range.

The hash function used is Keccak-256.

Options:

  --input=<filename>                    default: reads from standard input
  Gives the input filename.

  --log2-word-size=<integer>            default: 3
  (> 0 and <= 64)
  Number of bytes subintended by each word, i.e., the number of bytes in the
  input data from which each hash is computed.

  --log2-leaf-size=<integer>            default: 12
  (> 0 and <= log2_root_size)
  The granularity in which bytes are read from the input file.

  --help
  Prints this message and returns.
)",
        name);
    exit(0);
}

int main(int argc, char *argv[]) {
    const char *input_name = nullptr;
    int log2_word_size = 3;
    int log2_leaf_size = 12;
    int log2_root_size = 0;
    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
        } else if (stringval("--input=", argv[i], &input_name)) {
            ;
        } else if (intval("--log2-word-size=", argv[i], &log2_word_size)) {
            ;
        } else if (intval("--log2-leaf-size=", argv[i], &log2_leaf_size)) {
            ;
        } else if (intval("--log2-root-size=", argv[i], &log2_root_size)) {
            ;
        } else if (intval("--page-log2-size=", argv[i], &log2_leaf_size)) {
            std::cerr << "--page-log2-size is deprecated. "
                         "use --log2-leaf-size instead\n";
        } else if (intval("--tree-log2-size=", argv[i], &log2_root_size)) {
            std::cerr << "--tree-log2-size is deprecated. "
                         "use --log2-root-size instead\n";
        } else {
            error("unrecognized option '%s'\n", argv[i]);
        }
    }
    if (log2_leaf_size < log2_word_size || log2_leaf_size >= 64 || log2_root_size >= 64 ||
        log2_leaf_size > log2_root_size) {
        error("invalid word size (%d) / invalid leaf size (%d) / root size (%d) combination\n", log2_word_size,
            log2_leaf_size, log2_root_size);
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
    const uint64_t leaf_size = UINT64_C(1) << log2_leaf_size;
    auto leaf_buf = unique_calloc<unsigned char>(leaf_size, std::nothrow_t{});
    if (!leaf_buf) {
        error("unable to allocate leaf buffer\n");
        return 1;
    }

    back_merkle_tree back_tree{log2_root_size, log2_leaf_size, log2_word_size};

    const uint64_t max_leaves = UINT64_C(1) << (log2_root_size - log2_leaf_size);
    uint64_t leaf_count = 0;
    // Loop reading leaves from file until done or error
    while (true) {
        auto got = fread(leaf_buf.get(), 1, leaf_size, input_file.get());
        if (got == 0) {
            if (ferror(input_file.get())) {
                error("error reading input\n");
            } else {
                break;
            }
        }
        if (leaf_count >= max_leaves) {
            error("too many leaves for tree\n");
        }
        // Pad leaf with zeros if file ended before next leaf boundary
        memset(leaf_buf.get() + got, 0, leaf_size - got);
        // Compute leaf hash
        auto leaf_hash = get_leaf_hash(leaf_buf.get(), log2_leaf_size, log2_word_size);
        // Add leaf to incremental tree
        back_tree.push_back(leaf_hash);
        // Compare the root hash for the incremental tree and the
        // proof-by-proof tree
        ++leaf_count;
    }
    print_hash(back_tree.get_root_hash(), stdout);
    return 0;
}
