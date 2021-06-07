// Copyright 2019 Cartesi Pte. Ltd.
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

#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <optional>
#include <array>

#include "cryptopp-keccak-256-hasher.h"
#include "unique-c-ptr.h"
#include "back-merkle-tree.h"

using namespace cartesi;
using hasher_type = cryptopp_keccak_256_hasher;
using hash_type = hasher_type::hash_type;
constexpr int LOG2_WORD_SIZE = 3;

/// \brief Checks if string matches prefix and captures remaninder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remaninder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    int len = strlen(pre);
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
    int len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        str += len;
        int end = 0;
        if (sscanf(str, "%d%n", val, &end) == 1 && !str[end]) {
            return true;
        }
        return false;
    }
    return false;
}

/// \brief Prints hash in hex to file
/// \param hash Hash to be printed.
/// \param f File to print to
static void print_hash(const hash_type &hash, FILE *f) {
    for (auto b: hash) {
        fprintf(f, "%02x", (int) b);
    }
    fprintf(f, "\n");
}

/// \brief Reads a hash in hex from file
/// \param f File to read from
/// \returns Hash if successful, nothing otherwise
static std::optional<hash_type> read_hash(FILE *f) {
    char hex_hash[hasher_type::hash_size*2];
    if (fread(hex_hash, 1, sizeof(hex_hash), f) != sizeof(hex_hash))
        return {};
    hash_type h;
    for (unsigned i = 0; i < hasher_type::hash_size; ++i) {
        char hex_c[3] = {hex_hash[2*i], hex_hash[2*i+1], 0};
        unsigned c = 0;
        if (sscanf(hex_c, "%x", &c) != 1)
            return {};
        h[i] = c;
    }
    return h;
}

/// \brief Prints formatted message to stderr
/// \param fmt Format string
/// \param ... Arguments, if any
static void error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

/// \brief Computes the hash of a word
/// \param h Hasher object
/// \param leaf Pointer to leaf data. Must contain 2^LOG2_WORD_SIZE bytes
/// \param hash Receives the leaf hash
static void get_word_hash(hasher_type &h,
    const unsigned char *word, hash_type &hash) {
    h.begin();
    h.add_data(word, 1 << LOG2_WORD_SIZE);
    h.end(hash);
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param h Hasher object
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(hasher_type &h, const unsigned char *leaf_data,
    int log2_leaf_size) {
    assert(log2_leaf_size >= LOG2_WORD_SIZE);
    if (log2_leaf_size > LOG2_WORD_SIZE) {
        hash_type left = get_leaf_hash(h, leaf_data, log2_leaf_size-1);
        hash_type right = get_leaf_hash(h, leaf_data+(1<<(log2_leaf_size-1)),
            log2_leaf_size-1);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        hash_type leaf;
        get_word_hash(h, leaf_data, leaf);
        return leaf;
    }
}

/// \brief Computes the Merkle hash of a leaf of data
/// \param leaf_data Pointer to buffer containing leaf data with
/// at least 2^log2_leaf_size bytes
/// \param log2_leaf_size Log<sub>2</sub> of leaf size
/// \returns Merkle hash of leaf data
static hash_type get_leaf_hash(const unsigned char *leaf_data,
    int log2_leaf_size) {
    hasher_type h;
    return get_leaf_hash(h, leaf_data, log2_leaf_size);
}

/// \brief Prints help message
static void help(const char *name) {
    fprintf(stderr, "Usage:\n  %s [--input=<filename>] "
                    "--log2-leaf-size=<p> --log2-root-size=<t>\n", name);
    exit(0);
}

int main(int argc, char *argv[]) {
    const char *input_name = nullptr;
    int log2_leaf_size = 10;
    int log2_root_size = 0;
    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
        } else if (stringval("--input=", argv[i], &input_name)) {
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
    if (log2_leaf_size < LOG2_WORD_SIZE || log2_leaf_size >= 64 ||
        log2_root_size >= 64 || log2_leaf_size > log2_root_size) {
        error("invalid leaf size (%d) / tree size (%d) combination\n",
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
    uint64_t leaf_size = UINT64_C(1) << log2_leaf_size;
    auto leaf_buf = unique_calloc<unsigned char>(leaf_size, std::nothrow_t{});
    if (!leaf_buf) {
        error("unable to allocate leaf buffer\n");
        return 1;
    }

    back_merkle_tree back_tree{log2_root_size, log2_leaf_size, LOG2_WORD_SIZE};

    uint64_t max_leaves = UINT64_C(1) << (log2_root_size - log2_leaf_size);
    uint64_t leaf_count = 0;
    size_t got = leaf_size;
    // Loop reading leaves from file until done or error
    while (1) {
        got = fread(leaf_buf.get(), 1, leaf_size, input_file.get());
        if (got == 0) {
            if (ferror(input_file.get())) {
                error("error reading input\n");
            } else break;
        }
        if (leaf_count >= max_leaves) {
            error("too many leaves for tree\n");
        }
        // Pad leaf with zeros if file ended before next leaf boundary
        memset(leaf_buf.get()+got, 0, leaf_size-got);
        // Compute leaf hash
        auto leaf_hash = get_leaf_hash(leaf_buf.get(), log2_leaf_size);
        // Add leaf to incremental tree
        back_tree.push_back(leaf_hash);
        // Compare the root hash for the incremental tree and the
        // proof-by-proof tree
        ++leaf_count;
    }
    print_hash(back_tree.get_root_hash(), stdout);
    return 0;
}
