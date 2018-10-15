#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

/// \file
/// \brief Certified memory implementation.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <iomanip>
#include <type_traits>
#include <deque>
#include <array>
#include <vector>
#include <unordered_map>
#include <cryptopp/keccak.h>

/// \class merkle_tree_t
/// \details The merkle_tree_t class implements a Merkle tree
/// covering LOG2_TREE_SIZE bits of address space.
///
/// Upon creation, the memory is *pristine*, i.e., completely
/// filled with zeros.
///
/// To optimize for space, subtrees corresponding to pristine
/// memory are represented by <tt>nullptr</tt> nodes.
/// Additionaly, the tree is truncated below *page* nodes
/// subintending LOG2_PAGE_SIZE bits of address space.
/// The trees corresponding to pages are implicitly built from the
/// orgiginal data whenever needed and never stored.
/// Pages are divided into *words* that cover LOG2_WORD_SIZE
/// bits of address space.
/// The tree leaves contain hashes of individual words.
///
/// Tree contents are updated page-by-page using calls to
/// merkle_tree_t#begin_update, merkle_tree_t#update_page, ...,
/// merkle_tree_t#update_page, merkle_tree_t#end_update.
///
/// \tparam LOG2_TREE_SIZE Number of bits covered by the address space.
/// I.e., log<sub>2</sub> of number of bytes subintended by the tree root.
/// \tparam LOG2_PAGE_SIZE Number of bits covered by a page.
/// I.e., log<sub>2</sub> of number of bytes subintended by the
/// the deepest explicitly represented nodes.
template <
    int LOG2_TREE_SIZE = 64,
    int LOG2_PAGE_SIZE = 12
>
class merkle_tree_t final {
private:

    using word = uint64_t;
    static constexpr int LOG2_WORD_SIZE = 3; // Must match word size
    static constexpr size_t m_word_size = 1 << LOG2_WORD_SIZE;

    static constexpr uint64_t m_page_index_mask =
        ((~0ull) >> (64-LOG2_TREE_SIZE)) << LOG2_PAGE_SIZE;
    static constexpr uint64_t m_page_offset_mask = ~m_page_index_mask;
    static constexpr size_t m_page_size = 1 << LOG2_PAGE_SIZE;

    static constexpr size_t m_hash_size = 32;

public:
    /// \brief Error codes.
    /// \details All public methods return an error code with a descriptive
    /// name.  These error codes can be cast to int. The result is positive
    /// for success and negative for failure.
    enum class status_code {
        success = 1, ///< Success
        error = -1, ///< Error
        error_should_not_happen = -2, ///< Unexpected error
        error_out_of_memory = -3, ///< Failure due to lack of memory
    };

    /// \brief Checks if error code is an error
    static constexpr int is_error(status_code code) {
        return static_cast<int>(code) < 0;
    }

    /// \brief Returns the LOG2_TREE_SIZE template parameter.
    static constexpr int get_log2_tree_size(void) { return LOG2_TREE_SIZE; }
    /// \brief Returns the LOG2_PAGE_SIZE template parameter.
    static constexpr int get_log2_page_size(void) { return LOG2_PAGE_SIZE; }
    /// \brief Returns the LOG2_WORD_SIZE template parameter.
    static constexpr int get_log2_word_size(void) { return LOG2_WORD_SIZE; }
    /// \brief Returns the page size.
    static constexpr int get_page_size(void) { return m_page_size; }
    /// \brief Returns the word size.
    static constexpr int get_word_size(void) { return m_word_size; }
    /// \brief Returns the hash size.
    static constexpr int get_hash_size(void) { return m_hash_size; }

    /// \brief Storage for a Keccak 256 hash.
    using keccak_256_hash = std::array<uint8_t, get_hash_size()>;

    /// \brief Storage for the proof of a word value.
    using word_value_proof = std::array<keccak_256_hash,
        LOG2_TREE_SIZE-LOG2_WORD_SIZE+1>;

private:
    // Merkle tree node structure
    //
    // Whether a node is a inner-node or a page-node is known implicitly
    // based on its height in the tree.
    struct tree_node {
        // Keccak 256 hash of subintended data
        keccak_256_hash hash;
        // Pointer to parent node (nullptr for root)
        tree_node *parent;
        // Data specific to different node types
        tree_node *child[2];
        // Helper for traversal algorithms
        uint64_t mark;
    };

    // Sparse map from virtual page index to the
    // corresponding page node in the Merkle tree
    std::unordered_map<
        uint64_t,
        tree_node *
    > m_page_node_map;

    // Root of the Merkle tree
    tree_node m_root_storage;
    tree_node *m_root;

    // Precomputed hashes of spans of zero bytes with
    // increasing power-of-two sizes, from the
    // 2^LOG2_WORD_SIZE all the way up to 2^LOG2_TREE_SIZE bytes
    word_value_proof m_pristine_hashes;

    // Used to mark visited nodes when traversing the tree
    // bottom up in breadth to propagate changes from dirty
    // pages all the way up to the tree root
    uint64_t m_merkle_update_nonce;
    std::deque<std::pair<int, tree_node *>> m_merkle_update_fifo;

    // For statistics
#ifndef NDEBUG
    mutable uint64_t m_num_nodes;
#endif

    const keccak_256_hash &get_proof_hash(const word_value_proof &proof,
        int log2_size) const;

    void set_proof_hash(word_value_proof &proof,
        int log2_size, const keccak_256_hash &hash) const;

	int set_page_node_map(uint64_t page_index, tree_node *node);

    tree_node *create_node(void) const;

    void destroy_node(tree_node *node) const;

    // Create a new page node and insert it into the Merkle tree
    tree_node *new_page_node(uint64_t virtual_page_index);

    void update_page_node_hash(CryptoPP::Keccak_256 &kc,
        const uint8_t *start, int log2_size, keccak_256_hash &hash) const;

    void update_inner_node_hash(CryptoPP::Keccak_256 &kc,
        int log2_size, tree_node *node);

    void print_hash(const uint8_t *hash) const;

    const keccak_256_hash &get_pristine_hash(int log2_size) const;

    const keccak_256_hash &get_inner_child_hash(int child_log2_size,
        const tree_node *node, int bit) const;

    void initialize_pristine_hashes(void);

    void dump_merkle_tree(tree_node *node, int log2_tree_size) const;

    void destroy_merkle_tree(tree_node *node, int log2_size);

    status_code verify_merkle_tree(CryptoPP::Keccak_256 &kc,
        tree_node *node, int log2_size) const;

    void destroy_merkle_tree(void);

    constexpr uint64_t get_page_index(uint64_t address);

	constexpr uint64_t get_offset_in_page(uint64_t address);

    tree_node *get_page_node(uint64_t page_index) const;

    void get_inside_page_word_value_proof(CryptoPP::Keccak_256 &kc,
        uint64_t virtual_address, int parent_diverged, int diverged,
        const uint8_t *physical_address, int log2_size,
        word_value_proof &proof, keccak_256_hash &hash);

    void get_inside_page_word_value_proof(uint64_t virtual_address,
        const uint8_t *physical_address, word_value_proof &proof);

    void dump_merkle_tree(void) const;

    void get_concat_hash(CryptoPP::Keccak_256 &kc,
        const keccak_256_hash &child0, const keccak_256_hash &child1,
        keccak_256_hash &parent) const;

    status_code update_merkle_tree(void);

public:

    status_code verify_merkle_tree(void) const;

    /// \brief Default constructor.
    /// \details Initializes memory to zero.
    merkle_tree_t(void);

    /// \brief Destructor
    /// \details Releases all used memory
    ~merkle_tree_t();

    /// \brief Returns the root hash.
    status_code get_merkle_tree_root_hash(keccak_256_hash &hash);

    /// \brief Returns a proof of pristine value.
    status_code get_pristine_proof(word_value_proof &proof);

    /// \brief Update tree with new data for a page node
    status_code begin_update(CryptoPP::Keccak_256 &kc);
    status_code update_page(CryptoPP::Keccak_256 &kc,
		uint64_t page_address, uint8_t *page_data);
    status_code end_update(CryptoPP::Keccak_256 &kc);

    /// \brief Returns a word value and its proof.
    status_code get_word_value_proof(uint64_t word_address, uint64_t *page_data,
        word_value_proof &proof);

};

#include "merkle-tree.hpp"

using merkle_tree = merkle_tree_t<64,12>;

#endif
