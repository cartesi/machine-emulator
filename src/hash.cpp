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

using namespace cartesi;
using hasher_type = cryptopp_keccak_256_hasher;
using hash_type = hasher_type::hash_type;
constexpr int LEAF_LOG2_SIZE = 3;

/// \brief Computes the hash of concatenated hashes
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \param result Receives the hash of the concatenation
static void get_concat_hash(hasher_type &h, const hash_type &left, const hash_type &right, hash_type &result) {
    h.begin();
    h.add_data(left.data(), left.size());
    h.add_data(right.data(), right.size());
    h.end(result);
}

/// \brief Computes the hash of a leaf
/// \param h Hasher object
/// \param leaf Pointer to leaf data. Must contain 2^LEAF_LOG2_SIZE bytes
/// \param hash Receives the leaf hash
static void get_leaf_hash(hasher_type &h, const unsigned char *leaf, hash_type &hash) {
    h.begin();
    h.add_data(leaf, 1 << LEAF_LOG2_SIZE);
    h.end(hash);
}

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

/// \brief Prints help message
static void help(void) {
    fprintf(stderr, "Usage:\n  hash [--input=<filename>] "
                    "--page-log2-size=<p> --tree-log2-size=<t>\n");
    exit(0);
}

/// \brief Computes the Merkle hash of a page of data
/// \param h Hasher object
/// \param page_data Pointer to buffer containing page data with
/// at least 2^page_log2_size bytes
/// \param page_log2_size Log<sub>2</sub> of page size
/// \returns Merkle hash of page data
static hash_type get_page_hash(hasher_type &h, const unsigned char *page_data,
    int page_log2_size) {
    assert(page_log2_size >= LEAF_LOG2_SIZE);
    if (page_log2_size > LEAF_LOG2_SIZE) {
        hash_type left = get_page_hash(h, page_data, page_log2_size-1);
        hash_type right = get_page_hash(h, page_data+(1<<(page_log2_size-1)),
            page_log2_size-1);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        hash_type leaf;
        get_leaf_hash(h, page_data, leaf);
        return leaf;
    }
}

/// \brief Computes the Merkle hash of a page of data
/// \param page_data Pointer to buffer containing page data with
/// at least 2^page_log2_size bytes
/// \param page_log2_size Log<sub>2</sub> of page size
/// \returns Merkle hash of page data
static hash_type get_page_hash(const unsigned char *page_data,
    int page_log2_size) {
    hasher_type h;
    return get_page_hash(h, page_data, page_log2_size);
}

/// \brief Hashes of pristine subtrees for all sizes
class pristine_hashes {
    std::vector<hash_type> m_hashes; ///< Vector with hashes
    int m_page_log2_size,            ///< Log<sub>2</sub> of page size
        m_tree_log2_size;            ///< Log<sub>2</sub> of tree size
public:

    /// \brief Computes and returns the Merkle tree hash of a pristine page
    /// \param h Hasher object
    /// \param page_log2_size Log<sub>2</sub> of page size
    /// \returns Merkle hash of pristine page
    static hash_type get_pristine_page_hash(hasher_type &h, int page_log2_size) {
        hash_type hash;
        unsigned char zero[8];
        memset(zero, 0, sizeof(zero));
        get_leaf_hash(h, zero, hash);
        for (int i = LEAF_LOG2_SIZE; i < page_log2_size; ++i) {
            get_concat_hash(h, hash, hash, hash);
        }
        return hash;
    }

    /// \brief Constructor
    /// \param page_log2_size Log<sub>2</sub> of page size
    /// \param tree_log2_size Log<sub>2</sub> of tree size
    pristine_hashes(int page_log2_size, int tree_log2_size):
        m_page_log2_size(page_log2_size), m_tree_log2_size(tree_log2_size) {
        assert(tree_log2_size >= LEAF_LOG2_SIZE && tree_log2_size <= 64);
        m_hashes.resize(tree_log2_size-page_log2_size+1);
        hasher_type h;
        m_hashes[0] = get_pristine_page_hash(h, page_log2_size);
        for (int i = 0; i < tree_log2_size-page_log2_size; ++i) {
            get_concat_hash(h, m_hashes[i], m_hashes[i], m_hashes[i+1]);
        }
    }

    /// \brief Returns hash of pristine subtree
    /// \param log2_size Log<sub>2</sub> of subtree size. Must be between
    /// page_log2_size (inclusive) and tree_log2_size (inclusive) passed
    /// to constructor.
    const hash_type &get_hash(int log2_size) const {
        assert(log2_size <= m_tree_log2_size && log2_size >= m_page_log2_size);
        return m_hashes[log2_size-m_page_log2_size];
    }
};

/// \brief Merkle proof for a given page
struct merkle_proof {
    uint64_t page_number{0}; ///< Page number in tree
    int page_log2_size{0};   ///< Log<sub>2</sub> of page size
    int tree_log2_size{0};   ///< Log<sub>2</sub> of tree size
    hash_type page_hash{};   ///< Hash of page data
    hash_type root_hash{};   ///< Hash of tree root
    std::vector<hash_type> sibling_hashes; ///< Hash of all siblings in the path from root to page
    bool operator==(const merkle_proof &other) const {
        if (page_number != other.page_number) return false;
        if (page_log2_size != other.page_log2_size) return false;
        if (tree_log2_size != other.tree_log2_size) return false;
        if (page_hash != other.page_hash) return false;
        if (root_hash != other.root_hash) return false;
        if (sibling_hashes != other.sibling_hashes) return false;
        return true;
    }
    bool operator!=(const merkle_proof &other) const {
        return !(operator==(other));
    }
};

/// \brief Full Merkle tree of pages
/// \details This class implements a tree in which the leaves represent
/// page hashes, and the root represents the Merkle hash for the entire tree
class full_merkle_tree_of_pages {
    std::vector<hash_type> m_tree;   ///< Binary heap with tree node hashes
    int m_page_log2_size,            ///< Log<sub>2</sub> of page size
        m_tree_log2_size;            ///< Log<sub>2</sub> of tree size

    /// \brief Returns the index of the left child of node at given index
    int left_child_index(int index) const {
        return 2*index;
    }

    /// \brief Returns the index of the right child of node at given index
    int right_child_index(int index) const {
        return 2*index+1;
    }

    /// \brief Initialize all nodes for the pristine subtree with root
    /// at a given index
    /// \param pristine Hashes for pristine subtree nodes of all sizes
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    void init_pristine_subtree(const pristine_hashes &pristine, int index,
        int log2_size) {
        if (log2_size >= m_page_log2_size) {
            m_tree[index] = pristine.get_hash(log2_size);
            init_pristine_subtree(pristine, left_child_index(index),
                log2_size-1);
            init_pristine_subtree(pristine, right_child_index(index),
                log2_size-1);
        }
    }

    /// \brief Initialize all nodes for the subtree with root at a given index
    /// \param h Hasher object
    /// \param index Index of root for subtree to initialize
    /// \param log2_size Log<sub>2</sub> size of root at index
    /// \details The nodes corresponding to subtrees of size page_log2_size
    /// are assumed to have already been set prior to calling this function
    void init_subtree(hasher_type &h, int index, int log2_size) {
        if (log2_size > m_page_log2_size) {
            init_subtree(h, left_child_index(index), log2_size-1);
            init_subtree(h, right_child_index(index), log2_size-1);
            get_concat_hash(h, m_tree[left_child_index(index)],
                m_tree[right_child_index(index)], m_tree[index]);
        }
    }

    /// \brief Initialize tree from a list of consecutive page hashes
    /// \param page_hashes List of page hashes
    /// \details The page hashes in page_hashes are copied to the appropriate
    /// subtree nodes, in order, and the rest are filled with pristine
    /// page hashes
    void init_tree(const std::vector<hash_type> &page_hashes) {
        uint64_t max_pages = UINT64_C(1) << (m_tree_log2_size-m_page_log2_size);
        m_tree.resize(2*max_pages);
        uint64_t npage_hashes = page_hashes.size();
        assert(npage_hashes <= max_pages);
        std::copy(page_hashes.begin(), page_hashes.end(), &m_tree[max_pages]);
        hasher_type h;
        std::fill_n(&m_tree[max_pages+npage_hashes],  max_pages-npage_hashes,
            pristine_hashes::get_pristine_page_hash(h, m_page_log2_size));
        init_subtree(h, 1, m_tree_log2_size);
    }

public:

    /// \brief Constructor for pristine tree
    /// \param page_log2_size Log<sub>2</sub> of page size
    /// \param tree_log2_size Log<sub>2</sub> of tree size
    full_merkle_tree_of_pages(int page_log2_size, int tree_log2_size):
        m_page_log2_size(page_log2_size), m_tree_log2_size(tree_log2_size) {
        uint64_t max_pages = UINT64_C(1) << (m_tree_log2_size-m_page_log2_size);
        m_tree.resize(2*max_pages);
        init_pristine_subtree(pristine_hashes{page_log2_size, tree_log2_size},
            1, tree_log2_size);
    }

    /// \brief Constructor for list of consecutive page hashes
    /// \param page_log2_size Log<sub>2</sub> of page size
    /// \param tree_log2_size Log<sub>2</sub> of tree size
    /// \param page_hashes List of page hashes
    full_merkle_tree_of_pages(int page_log2_size, int tree_log2_size,
        const std::vector<hash_type> &page_hashes):
        m_page_log2_size(page_log2_size), m_tree_log2_size(tree_log2_size) {
        init_tree(page_hashes);
    }

    /// \brief Returns the root tree hash
    /// \returns Root tree hash
    hash_type get_root_hash(void) const {
        return m_tree[1];
    }

    /// \brief Returns proof for a given page
    /// \param page_number Index of page for which to obtain proof
    /// \returns Proof for page at given index, or nothing if index is invalid
    std::optional<merkle_proof> get_page_proof(uint64_t page_number) const {
        uint64_t max_pages = UINT64_C(1) << (m_tree_log2_size-m_page_log2_size);
        if (page_number >= max_pages) return {};
        merkle_proof proof;
        proof.page_number = page_number;
        proof.page_log2_size = m_page_log2_size;
        proof.tree_log2_size = m_tree_log2_size;
        proof.root_hash = m_tree[1];
        proof.page_hash = m_tree[max_pages+page_number];
        proof.sibling_hashes.reserve(m_tree_log2_size-m_page_log2_size);
        int index = 1;
        for (int child_log2_size = m_tree_log2_size-m_page_log2_size-1;
            child_log2_size >= 0; --child_log2_size) {
            index *= 2;
            int bit = (page_number & (UINT64_C(1) << child_log2_size)) != 0;
            proof.sibling_hashes.push_back(m_tree[index+!bit]);
            index += bit;
        }
        return proof;
    }

    /// \brief Replaces a page node in the tree
    /// \returns Proof for page at given index, or nothing if index is invalid
    bool replace_page(const hash_type &page_hash, const merkle_proof &proof) {
        if (m_page_log2_size != proof.page_log2_size) return false;
        if (m_tree_log2_size != proof.tree_log2_size) return false;
        if (proof.root_hash != get_root_hash()) return false;
        uint64_t max_pages = UINT64_C(1) <<
            (m_tree_log2_size - m_page_log2_size);
        if (proof.page_number >= max_pages) return false;
        auto hash = proof.page_hash;
        hasher_type h;
        int sibling_count = m_tree_log2_size-m_page_log2_size;
        // Verify proof
        for (int i = 0; i < sibling_count; ++i) {
            int bit = (proof.page_number & (UINT64_C(1) << i)) != 0;
            const hash_type &sibling = proof.sibling_hashes[sibling_count-i-1];
            get_concat_hash(h, bit? sibling: hash, bit? hash: sibling, hash);
        }
        if (hash != proof.root_hash) return false;
        int index = max_pages+proof.page_number;
        if (proof.page_hash != m_tree[index]) return false; // unecessary check
        // Replace hashes in path from page to root
        hash = page_hash;
        m_tree[index] = hash;
        for (int i = 0; i < sibling_count; ++i) {
            int bit = (proof.page_number & (UINT64_C(1) << i)) != 0;
            const hash_type &sibling = proof.sibling_hashes[sibling_count-i-1];
            get_concat_hash(h, bit? sibling: hash, bit? hash: sibling, hash);
            index /= 2;
            m_tree[index] = hash;
            // unecessary check
            if (bit) {
                if (m_tree[left_child_index(index)] != sibling) return false;
            } else {
                if (m_tree[right_child_index(index)] != sibling) return false;
            }
        }
        return true;
    }

};

/// \brief Incremental way of maintaining a Merkle tree for a stream of
/// page hashes
/// \details This is surprisingly efficient in both time and space.
/// Adding the next page takes O(log(n)) in the worst case, but is
/// this is amortized to O(1) time when adding n pages.
/// Obtaining the proof for the current page takes theta(log(n)) time.
/// Computing the tree root hash also takes theta(log(n)) time.
/// The class only ever stores log(n) hashes (1 for each tree level).
class incremental_merkle_tree_of_pages {
    pristine_hashes m_pristine_hashes; ///< Hash of pristine subtrees of all sizes
    std::vector<hash_type> m_context;  ///< Hashes of bits set in page_count
    int m_page_log2_size,              ///< Log<sub>2</sub> of page size
        m_tree_log2_size;              ///< Log<sub>2</sub> of tree size
    uint64_t m_page_count;             ///< Number of pages already added to stream
    uint64_t m_max_pages;              ///< Maximum number of pages that fit in tree

public:

    /// \brief Constructor
    /// \param page_log2_size Log<sub>2</sub> of page size
    /// \param tree_log2_size Log<sub>2</sub> of tree size
    incremental_merkle_tree_of_pages(int page_log2_size, int tree_log2_size):
        m_pristine_hashes{page_log2_size, tree_log2_size},
        m_page_log2_size{page_log2_size},
        m_tree_log2_size{tree_log2_size},
        m_page_count{0},
        m_max_pages{UINT64_C(1) << (tree_log2_size - page_log2_size)} {
        m_context.resize(tree_log2_size-page_log2_size+1);
    }

    /// \brief Adds the next page to the tree
    /// \param page_hash Hash of page data
    /// \details
    /// Consider the tree down to the page level.
    /// The tree is only complete after 2^(tree_log2_size-page_log2_size) pages
    /// have been added.
    /// Before that, when page_count pages have been added, we assume the rest
    /// of the pages are filled with zeros (i.e., they are pristine).
    /// The trick is that we do not need to store the hashes of all page_count
    /// pages already added to the stream.
    /// This is because, whenever a subtree is complete, all we need is its
    /// root hash.
    /// The complete subtrees are disjoint, abutting, and appear in decreasing
    /// size.
    /// In fact, there is exactly one complete subtree for each bit set in
    /// page_count.
    /// We only need tree_log2_size-page_log2_size+1 bits to represent
    /// page_count.
    /// So our context is a vector with tree_log2_size-page_log2_size+1 entries,
    /// where entry i contains the hash for a complete subtree of
    /// size 2^i pages.
    /// We will only use the entries i if the corresponding bit is set
    /// in page_count.
    /// Adding a new page hash exactly like adding 1 to page_count.
    /// We scan from least to most significant bit in page_count.
    /// We start with the right = page_hash and i = 0.
    /// If the bit i is set in page_count, we replace
    /// context[i] = hash(context[i], right) and move up a bit.
    /// If the bit is not set, we simply store context[i] = right and break
    /// In other words, we can update the context in
    /// log time (tree_log2_size-page_log2_size)
    void add_page(const hash_type &page_hash) {
        hasher_type h;
        hash_type right = page_hash;
        assert(m_page_count < m_max_pages);
        int depth = m_tree_log2_size-m_page_log2_size;
        for (int i = 0; i <= depth; ++i) {
            if (m_page_count & (UINT64_C(1) << i)) {
                const auto &left = m_context[i];
                get_concat_hash(h, left, right, right);
            } else {
                m_context[i] = right;
                break;
            }
        }
        ++m_page_count;
    }

    /// \brief Returns the root tree hash
    /// \returns Root tree hash
    /// \details
    /// We can produce the tree root hash from the context at any time, also
    /// in log time
    /// Ostensibly, we add pristine pages until the page_count
    /// hits 2^(tree_log2_size-page_log2_size)
    /// To do this in log time, we start by precomputing the hashes for all
    /// completely pristine subtree sizes
    /// If page_count is already 2^(tree_log2_size-page_log2_size), we
    /// return context[i]
    /// Otherwise, we start with i = 0 and root = pristine[i+page_log2_size]
    /// (i.e., the invariant is that root contains the hash of the rightmost
    /// subtree whose log size is i + page_log2_size)
    /// If bit i is set, we set root = hash(context[i], root) and move up a bit
    /// (i.e., the subtree we are growing is to the right of what is
    /// in the context)
    /// If bit i is not set, we set
    /// root = hash(root, pristine[i+page_log2_size]) and move up a bit
    /// (i.e., to grow our subtree, we need to pad it on the right with
    /// a pristine subtree of the same size)
    hash_type get_root_hash(void) const {
        hasher_type h;
        assert(m_page_count <= m_max_pages);
        int depth = m_tree_log2_size-m_page_log2_size;
        if (m_page_count < m_max_pages) {
            auto root = m_pristine_hashes.get_hash(m_page_log2_size);
            for (int i = 0; i < depth; ++i) {
                if (m_page_count & (UINT64_C(1) << i)) {
                    const auto &left = m_context[i];
                    get_concat_hash(h, left, root, root);
                } else {
                    const auto &right = m_pristine_hashes.get_hash(
                        m_page_log2_size+i);
                    get_concat_hash(h, root, right, root);
                }
            }
            return root;
        } else {
            return m_context[depth];
        }
    }

    /// \brief Returns proof for the next pristine page
    /// \returns Proof for page at given index, or nothing if index is invalid
    /// \details This is basically the same algorithm as
    /// incremental_merkle_tree_of_pages::get_root_hash.
    std::optional<merkle_proof> get_next_page_proof(void) const {
        int depth = m_tree_log2_size-m_page_log2_size;
        uint64_t max_pages = UINT64_C(1) << depth;
        if (m_page_count >= max_pages) return {};
        hasher_type h;
        merkle_proof proof;
        proof.page_number = m_page_count;
        proof.page_log2_size = m_page_log2_size;
        proof.tree_log2_size = m_tree_log2_size;
        proof.page_hash = m_pristine_hashes.get_hash(m_page_log2_size);
        proof.sibling_hashes.resize(depth);
        proof.root_hash = m_pristine_hashes.get_hash(m_page_log2_size);
        for (int i = 0; i < depth; ++i) {
            if (m_page_count & (UINT64_C(1) << i)) {
                const auto &left = m_context[i];
                proof.sibling_hashes[depth-i-1] = left;
                get_concat_hash(h, left, proof.root_hash, proof.root_hash);
            } else {
                const auto &right = m_pristine_hashes.get_hash(
                    m_page_log2_size+i);
                proof.sibling_hashes[depth-i-1] = right;
                get_concat_hash(h, proof.root_hash, right, proof.root_hash);
            }
        }
        return proof;
    }
};

#ifdef CONSISTENCY_TEST
int main(int argc, char *argv[]) {
    const char *input_name = nullptr;
    const char *page_hashes_name = nullptr;
    int page_log2_size = 0;
    int tree_log2_size = 0;
    //int incremental = false;
    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help();
            return 1;
        } else if (stringval("--input=", argv[i], &input_name)) {
            ;
        } else if (stringval("--page-hashes=", argv[i], &page_hashes_name)) {
            ;
        } else if (intval("--page-log2-size=", argv[i], &page_log2_size)) {
            ;
        } else if (intval("--tree-log2-size=", argv[i], &tree_log2_size)) {
            ;
        } else {
            error("unrecognized option '%s'\n", argv[i]);
            return 1;
        }
    }
    if (page_log2_size < LEAF_LOG2_SIZE || page_log2_size >= 64 ||
        tree_log2_size >= 64 || page_log2_size > tree_log2_size) {
        error("invalid page size (%d) / tree size (%d) combination\n",
            page_log2_size, tree_log2_size);
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

    // Write to stdout if no output name was given
    auto page_hashes_file = unique_file_ptr{stdout};
    if (page_hashes_name) {
        page_hashes_file = unique_fopen(page_hashes_name, "w", std::nothrow_t{});
        if (!page_hashes_file) {
            error("unable to open page hashes file '%s'\n", page_hashes_name);
            return 1;
        }
    }

    // Allocate buffer for page data
    uint64_t page_size = UINT64_C(1) << page_log2_size;
    auto page_buf = unique_calloc<unsigned char>(1, page_size, std::nothrow_t{});
    if (!page_buf) {
        error("unable to allocate page buffer\n");
        return 1;
    }

    incremental_merkle_tree_of_pages incremental_tree(page_log2_size,
        tree_log2_size);
    full_merkle_tree_of_pages proof_by_proof_tree(page_log2_size, tree_log2_size);
    std::vector<hash_type> page_hashes;

    uint64_t max_pages = UINT64_C(1) << (tree_log2_size - page_log2_size);
    uint64_t page_count = 0;
    size_t got = page_size;
    // Loop reading pages from file until done or error
    // As each page is loaded, we check that all three implementations
    // have a consistent root:
    // 1) The implementation that can receive page hashes and incrementally add
    // obtain the tree root in log time and keeping log size state
    // 2) The implementation that builds a tree from scratch based on all page
    // hashes
    // 3) The implementation that can receive page hashes and a
    // log-size proof for the page currently in the tree and udpate
    // the root hash in log time keeping only constant size state.
    while (1) {
        got = fread(page_buf.get(), 1, page_size, input_file.get());
        if (got == 0) {
            if (ferror(input_file.get())) {
                error("error reading input\n");
                return 1;
            } else break;
        }
        if (page_count >= max_pages) {
            error("too many pages for tree\n");
            return 1;
        }
        // Pad page with zeros if file ended before next page boundary
        memset(page_buf.get()+got, 0, page_size-got);
        // Compute page hash
        auto page_hash = get_page_hash(page_buf.get(), page_log2_size);
        // Add to array of page hashes
        page_hashes.push_back(page_hash);
        // Print page hash
        print_hash(page_hash, stderr);
        // Get value proof for position of new page from incremental tree
        auto incremental_page_proof = incremental_tree.get_next_page_proof();
        if (!incremental_page_proof.has_value()) {
            error("incremental proof failed\n");
            return 1;
        }
        // Directly add page to incremental tree
        incremental_tree.add_page(page_hash);
        // Build full tree from array of page hashes
        full_merkle_tree_of_pages tree_from_scratch(page_log2_size,
            tree_log2_size, page_hashes);
        // Compare the root hash for the incremental tree and the tree
        // from scratch
        if (incremental_tree.get_root_hash() !=
            tree_from_scratch.get_root_hash()) {
            error("mismatch in root hash for incremental tree and "
                "tree from scratch\n");
            return 1;
        }
        // Get value proof for pristine page at position page_count
        // in proof-by-proof tree
        auto page_proof = proof_by_proof_tree.get_page_proof(page_count);
        if (!page_proof.has_value()) {
            error("proof failed\n");
            return 1;
        }
        // Compare proof with incremental proof
        if (page_proof.value() != incremental_page_proof.value()) {
            error("proof and incremental proof differ\n");
            return 1;
        }
        // Use proof to replace pristine page that was there with the
        // page we just read
        if (!proof_by_proof_tree.replace_page(page_hash, page_proof.value())) {
            error("page replacement failed\n");
            return 1;
        }
        // Compare the root hash for the incremental tree and the
        // proof-by-proof tree
        if (incremental_tree.get_root_hash() !=
            proof_by_proof_tree.get_root_hash()) {
            error("mismatch in root hash for incremental tree and "
                "proof-by-proof tree\n");
            return 1;
        }
        ++page_count;
    }
    fprintf(stderr, "passed test\n");

    return 0;
}
#else
int main(int argc, char *argv[]) {
    const char *input_name = nullptr;
    int page_log2_size = 0;
    int tree_log2_size = 0;
    // Process command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            help();
        } else if (stringval("--input=", argv[i], &input_name)) {
            ;
        } else if (intval("--page-log2-size=", argv[i], &page_log2_size)) {
            ;
        } else if (intval("--tree-log2-size=", argv[i], &tree_log2_size)) {
            ;
        } else {
            error("unrecognized option '%s'\n", argv[i]);
        }
    }
    if (page_log2_size < LEAF_LOG2_SIZE || page_log2_size >= 64 ||
        tree_log2_size >= 64 || page_log2_size > tree_log2_size) {
        error("invalid page size (%d) / tree size (%d) combination\n",
            page_log2_size, tree_log2_size);
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

    // Allocate buffer for page data
    uint64_t page_size = UINT64_C(1) << page_log2_size;
    auto page_buf = unique_calloc<unsigned char>(1, page_size, std::nothrow_t{});
    if (!page_buf) {
        error("unable to allocate page buffer\n");
        return 1;
    }

    incremental_merkle_tree_of_pages incremental_tree(page_log2_size,
        tree_log2_size);

    uint64_t max_pages = UINT64_C(1) << (tree_log2_size - page_log2_size);
    uint64_t page_count = 0;
    size_t got = page_size;
    // Loop reading pages from file until done or error
    while (1) {
        got = fread(page_buf.get(), 1, page_size, input_file.get());
        if (got == 0) {
            if (ferror(input_file.get())) {
                error("error reading input\n");
            } else break;
        }
        if (page_count >= max_pages) {
            error("too many pages for tree\n");
        }
        // Pad page with zeros if file ended before next page boundary
        memset(page_buf.get()+got, 0, page_size-got);
        // Compute page hash
        auto page_hash = get_page_hash(page_buf.get(), page_log2_size);
        // Add page to incremental tree
        incremental_tree.add_page(page_hash);
        // Compare the root hash for the incremental tree and the
        // proof-by-proof tree
        ++page_count;
    }
    print_hash(incremental_tree.get_root_hash(), stdout);
    return 0;
}
#endif
