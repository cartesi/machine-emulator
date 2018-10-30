#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

/// \file
/// \brief Merkle tree interface.

#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <iomanip>
#include <type_traits>
#include <deque>
#include <array>
#include <vector>
#include <unordered_map>

#include "keccak-256-hasher.h"

/// \class merkle_tree_t
/// \brief Merkle tree implementation.
///
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
/// The trees corresponding to pages are rebuilt from the
/// original data whenever needed and never stored.
/// Pages are divided into *words* that cover LOG2_WORD_SIZE
/// bits of address space.
/// Tree leaves contain Keccak-256 hashes of individual words.
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
/// \tparam H Hasher class implementing the i_hasher interface.
template <
    int LOG2_TREE_SIZE = 64,
    int LOG2_PAGE_SIZE = 12,
    typename H = keccak_256_hasher
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

    /// \brief Storage for a hash.
    using digest_type = typename H::digest_type;

    using hasher_type = H;

    /// \brief Storage for the proof of a word value.
    /// \details The proof for a word value contains the
    /// hashes for all siblings in the path from the word
    /// node to the root, followed by the hash for the root,
    /// in that order.
    using word_value_proof = std::array<digest_type,
          LOG2_TREE_SIZE-LOG2_WORD_SIZE+1>;

private:
    /// \brief Merkle tree node structure.
    /// \details A node is known to be an inner-node or a page-node implicitly
    /// based on its height in the tree.
    struct tree_node {
        digest_type hash; ///< Hash of subintended data.
        tree_node *parent;    ///< Pointer to parent node (nullptr for root).
        tree_node *child[2];  ///< Children nodes.
        uint64_t mark;        ///< Helper for traversal algorithms.
    };

    // Sparse map from virtual page index to the
    // corresponding page node in the Merkle tree.
    std::unordered_map<
        uint64_t,
        tree_node *
    > m_page_node_map;

    // Root of the Merkle tree.
    tree_node m_root_storage;
    tree_node *m_root;

    // Precomputed hashes of spans of zero bytes with
    // increasing power-of-two sizes, from 2^LOG2_WORD_SIZE
    // to 2^LOG2_TREE_SIZE bytes.
    word_value_proof m_pristine_hashes;

    // Used to mark visited nodes when traversing the tree
    // bottom up in breadth to propagate changes from dirty
    // pages all the way up to the tree root.
    uint64_t m_merkle_update_nonce;
    // FIFO to process pages in bottom-up order.
    std::deque<std::pair<int, tree_node *>> m_merkle_update_fifo;

    // For statistics.
#ifdef MERKLE_DUMP_STATS
    mutable uint64_t m_num_nodes;
#endif

    /// \brief Get hash corresponding to log2_size in proof.
    /// \param proof Input proof.
    /// \param log2_size log<sub>2</sub> of size subintended by hash.
    /// \return Reference to hash inside proof.
    const digest_type &get_proof_hash(const word_value_proof &proof,
        int log2_size) const;

    /// \brief Set hash corresponding to log2_size in proof.
    /// \param proof Proof to modify.
    /// \param log2_size log<sub>2</sub> of size subintended by hash.
    /// \param hash New hash for log2_size in proof.
    void set_proof_hash(word_value_proof &proof,
        int log2_size, const digest_type &hash) const;

    /// \brief Maps a page_index to a node.
    /// \param page_index Page index.
    /// \param node Node subintending page.
    /// \return 1 if succeeded, 0 othewise.
	int set_page_node_map(uint64_t page_index, tree_node *node);

    /// \brief Creates and returns a new tree node.
    /// \return Newly created node or nullptr if out-of-memory.
    tree_node *create_node(void) const;

    /// \brief Deallocates node.
    /// \param node Node to be deallocated.
    void destroy_node(tree_node *node) const;

    /// \brief Creates a new page node and insert it into the Merkle tree.
    /// \param page_index Page index for node.
    /// \return Newly created node.
    /// \details Does *not* check if a node already exists for that page index.
    /// Maps new node to the page index.
    tree_node *new_page_node(uint64_t page_index);

    /// \brief Recursively builds hash for log2_size node
    /// from contiguous memory.
    /// \param h Hasher object.
    /// \param start Start of contiguous memory subintended by node.
    /// \param log2_size log<sub>2</sub> of size subintended by node.
    /// \param hash Receives the hash.
    void update_page_node_hash(H &h, const uint8_t *start, int log2_size, digest_type &hash) const;

    /// \brief Updates an inner node hash from its children.
    /// \param h Hasher object.
    /// \param log2_size log<sub>2</sub> of size subintended by node.
    /// \param node Node to be updated.
    void update_inner_node_hash(H &h, int log2_size, tree_node *node);

    /// \brief Dumps a hash to std::cerr.
    /// \param hash Hash to be dumped.
    void dump_hash(const digest_type &hash) const;

    /// \brief Returns the hash for a log2_size pristine node.
    /// \return Reference to precomputed hash.
    const digest_type &get_pristine_hash(int log2_size) const;

    /// \brief Returns the hash for a child of a given node.
    /// \param child_log2_size log2_size of child node.
    /// \param node Node from which to obtain child.
    /// \param bit Bit corresponding to child_log2_size in child node address.
    /// \return Reference to child hash. If child pointer is null,
    /// returns a pristine hash.
    const digest_type &get_inner_child_hash(int child_log2_size,
        const tree_node *node, int bit) const;

    /// \brief Precomputes hashes for pristine nodes of all sizes.
    void initialize_pristine_hashes(void);

    /// \brief Dumps tree rooted at node to std::cerr.
    /// \param node Root of subtree.
    /// \param  log2_size log<sub>2</sub> of size subintended by \p node.
    void dump_merkle_tree(tree_node *node, int log2_size) const;

    /// \brief Dumps the entire tree rooted to std::cerr.
    void dump_merkle_tree(void) const;

    /// \brief Destroys tree rooted at node.
    /// \param node Root of subtree.
    /// \param  log2_size log<sub>2</sub> of size subintended by \p node.
    void destroy_merkle_tree(tree_node *node, int log2_size);

    /// \brief Destroys entire Merkle tree.
    void destroy_merkle_tree(void);

    /// \brief Verifies tree rooted at node.
    /// \param h Hasher object.
    /// \param node Root of subtree.
    /// \param  log2_size log<sub>2</sub> of size subintended by \p node.
    status_code verify_merkle_tree(H &h, tree_node *node, int log2_size) const;

    /// \brief Computes the page index for a memory address.
    /// \param address Memory address.
    /// \return The page index.
    constexpr uint64_t get_page_index(uint64_t address);

    /// \brief Computes the offset of a memory address within its page.
    /// \param address Memory address.
    /// \return The offset.
	constexpr uint64_t get_offset_in_page(uint64_t address);

    /// \brief Computes the offset of a memory address within its page.
    /// \param page_index Page index associated to node.
    /// \return The node, if found, or nullptr otherwise.
    tree_node *get_page_node(uint64_t page_index) const;

    /// \brief Obtains the proof for target node at \p address and \p log2_size.
    /// \param h Hasher object.
    /// \param address Address of target node.
    /// \param parent_diverged Parent node corresponding to \p node_data
    /// is not not in path from root to target node.
    /// \param diverged Node corresponding to \p node_data is not in
    /// path from root to target node.
    /// \param node_data Pointer to start of contiguous node data.
    /// \param log2_size log<sub>2</sub> of size subintended by target \p node.
    /// \param proof Receives the proof.
    /// \param hash Temporary storage for hashes.
    void get_inside_page_word_value_proof(H &h, uint64_t address, int parent_diverged, int diverged,
        const uint8_t *node_data, int log2_size,
        word_value_proof &proof, digest_type &hash);

    /// \brief Obtains the proof for target node at \p address and \p log2_size.
    /// \param address Address of target node.
    /// \param page_data Pointer to start of contiguous page data.
    /// \param proof Receives the proof.
    void get_inside_page_word_value_proof(uint64_t address,
        const uint8_t *page_data, word_value_proof &proof);

    /// \brief Obtains hash of a \p parent node from the
    /// handles of its children nodes.
    /// \param h Hasher object.
    /// \param child0 Hash of first child.
    /// \param child1 Hash of second child.
    /// \param parent Receives parent hash.
    void get_concat_hash(H &h, const digest_type &child0, const digest_type &child1,
        digest_type &parent) const;

public:

    /// \brief Verifies the entire Merkle tree.
    /// \return status_code::success if tree is consistent,
    /// or status_code::error otherwise.
    status_code verify_merkle_tree(void) const;

    /// \brief Default constructor.
    /// \details Initializes memory to zero.
    merkle_tree_t(void);

    /// \brief Destructor
    /// \details Releases all used memory
    ~merkle_tree_t();

    /// \brief Returns the root hash.
    /// \param hash Receives the hash.
    /// \returns status_code::success.
    status_code get_merkle_tree_root_hash(digest_type &hash);

    /// \brief Returns a pristine proof.
    /// \param proof Receives proof.
    /// \details A pristine proof contains the hashes for
    ///  nodes in all levels of a pristine tree.
    /// \returns status_code::success.
    status_code get_pristine_proof(word_value_proof &proof);

    /// \brief Start tree update.
    /// \param h Hasher object.
    /// \returns status_code::success.
    status_code begin_update(H &h);

    /// \brief Update tree with new data for a page node.
    /// \param h Hasher object.
    /// \param page_address Address of start of page.
    /// \param page_data Pointer to start of contiguous page data.
    /// \returns status_code::success if update completed,
    /// status_code::out_of_memory if it failed.
    status_code update_page(H &h, uint64_t page_address, uint8_t *page_data);

    /// \brief End tree update.
    /// \param h Hasher object.
    /// \returns status_code::success.
    status_code end_update(H &h);

    /// \brief Returns a word value and its proof.
    /// \param word_address Address of aligned word.
    /// \param page_data Pointer to start of contiguous page data where word
    /// resides.
    /// \param proof Receives proof.
    status_code get_word_value_proof(uint64_t word_address, uint64_t *page_data,
        word_value_proof &proof);

};

#include "merkle-tree.hpp"

using merkle_tree = merkle_tree_t<64,12>;

#endif
