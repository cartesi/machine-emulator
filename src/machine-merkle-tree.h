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

#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

/// \file
/// \brief Merkle tree interface.

#include <cstdint>
#include <iosfwd>
#include <type_traits>
#include <deque>
#include <array>
#include <unordered_map>

#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "pristine-merkle-tree.h"

namespace cartesi {

/// \class machine_merkle_tree
/// \brief Merkle tree implementation.
///
/// \details The machine_merkle_tree class implements a Merkle tree
/// covering LOG2_ROOT_SIZE bits of address space.
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
/// machine_merkle_tree#begin_update, machine_merkle_tree#update_page, ...,
/// machine_merkle_tree#update_page, machine_merkle_tree#end_update.
class machine_merkle_tree final {
public:

    using word_type = uint64_t;

    using address_type = uint64_t;

private:
    /// \brief LOG2_ROOT_SIZE Number of bits covered by the address space.
    /// I.e., log<sub>2</sub> of number of bytes subintended by the tree root.
    static constexpr int LOG2_ROOT_SIZE = 64;
    /// \brief LOG2_PAGE_SIZE Number of bits covered by a page.
    /// I.e., log<sub>2</sub> of number of bytes subintended by the
    /// the deepest explicitly represented nodes.
    static constexpr int LOG2_PAGE_SIZE = 12;
    /// \brief LOG2_WORD_SIZE Number of bits covered by a word.
    /// I.e., log<sub>2</sub> of number of bytes subintended by the
    /// the deepest tree nodes.
    static constexpr int LOG2_WORD_SIZE = 3;
    /// \brief DEPTH Depth of Merkle tree.
    static constexpr int DEPTH = LOG2_ROOT_SIZE-LOG2_WORD_SIZE;

    static constexpr size_t m_word_size = size_t(1) << LOG2_WORD_SIZE;

    static constexpr address_type m_page_index_mask =
        ((~UINT64_C(0)) >> (64-LOG2_ROOT_SIZE)) << LOG2_PAGE_SIZE;

    static constexpr address_type m_page_offset_mask = ~m_page_index_mask;

    static constexpr size_t m_page_size = size_t(1) << LOG2_PAGE_SIZE;

public:

    /// \brief Returns the LOG2_ROOT_SIZE parameter.
    static constexpr int get_log2_root_size(void) { return LOG2_ROOT_SIZE; }
    /// \brief Returns the LOG2_PAGE_SIZE parameter.
    static constexpr int get_log2_page_size(void) { return LOG2_PAGE_SIZE; }
    /// \brief Returns the LOG2_WORD_SIZE parameter.
    static constexpr int get_log2_word_size(void) { return LOG2_WORD_SIZE; }
    /// \brief Returns the tree DEPTH.
    static constexpr int get_depth(void) { return DEPTH; }
    /// \brief Returns the page size.
    static constexpr size_t get_page_size(void) { return m_page_size; }
    /// \brief Returns the word size.
    static constexpr size_t get_word_size(void) { return m_word_size; }

    /// \brief Hasher class.
    using hasher_type = keccak_256_hasher;

    /// \brief Storage for a hash.
    using hash_type = hasher_type::hash_type;

    /// \brief Storage for the proof of a word value.
    using proof_type = merkle_tree_proof<hash_type, address_type>;

    /// \brief Storage for the hashes of the siblings of all nodes along
    /// the path from the root to target node.
    using siblings_type = proof_type::sibling_hashes_type;

private:

    /// \brief Merkle tree node structure.
    /// \details A node is known to be an inner-node or a page-node implicitly
    /// based on its height in the tree.
    //??D This is assumed to be a POD type in the implementation
    struct tree_node {
        hash_type hash;       ///< Hash of subintended data.
        tree_node *parent;    ///< Pointer to parent node (nullptr for root).
        tree_node *child[2];  ///< Children nodes.
        uint64_t mark;        ///< Helper for traversal algorithms.
    };

    // Sparse map from virtual page index to the
    // corresponding page node in the Merkle tree.
    std::unordered_map<
        address_type,
        tree_node *
    > m_page_node_map;

    // Root of the Merkle tree.
    tree_node m_root_storage;
    tree_node *m_root;

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

    /// \brief Maps a page_index to a node.
    /// \param page_index Page index.
    /// \param node Node subintending page.
    /// \return 1 if succeeded, 0 othewise.
	int set_page_node_map(address_type page_index, tree_node *node);

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
    tree_node *new_page_node(address_type page_index);

    /// \brief Updates an inner node hash from its children.
    /// \param h Hasher object.
    /// \param log2_size log<sub>2</sub> of size subintended by node.
    /// \param node Node to be updated.
    void update_inner_node_hash(hasher_type &h, int log2_size, tree_node *node);

    /// \brief Dumps a hash to std::cerr.
    /// \param hash Hash to be dumped.
    void dump_hash(const hash_type &hash) const;

    /// \brief Returns the hash for a child of a given node.
    /// \param child_log2_size log2_size of child node.
    /// \param node Node from which to obtain child.
    /// \param bit Bit corresponding to child_log2_size in child node address.
    /// \return Reference to child hash. If child pointer is null,
    /// returns a pristine hash.
    const hash_type &get_child_hash(int child_log2_size,
        const tree_node *node, int bit) const;

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
    /// \returns True if tree is consistent, false otherwise.
    bool verify_tree(hasher_type &h, tree_node *node, int log2_size) const;

    /// \brief Computes the page index for a memory address.
    /// \param address Memory address.
    /// \return The page index.
    constexpr address_type get_page_index(address_type address) const;

    /// \brief Computes the offset of a memory address within its page.
    /// \param address Memory address.
    /// \return The offset.
	constexpr address_type get_offset_in_page(address_type address) const;

    /// \brief Computes the offset of a memory address within its page.
    /// \param page_index Page index associated to node.
    /// \return The node, if found, or nullptr otherwise.
    tree_node *get_page_node(address_type page_index) const;

    /// \brief Recursively builds hash for log2_size node
    /// from contiguous memory.
    /// \param h Hasher object.
    /// \param start Start of contiguous memory subintended by node.
    /// \param log2_size log<sub>2</sub> of size subintended by node.
    /// \param hash Receives the hash.
    void get_page_node_hash(hasher_type &h, const unsigned char *start,
            int log2_size, hash_type &hash) const;

    /// \brief Gets the sibling hashes along the path from
    /// the node currently being visited and a target node.
    /// \param h Hasher object.
    /// \param address Address of target node.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \param hash Receives the target node hash if it is a
    /// subnode of the node currently being visited.
    /// \param curr_data Pointer to contiguous data for node currently
    /// being visited.
    /// \param log2_curr_size log<sub>2</sub> of size subintended by node
    /// currently being visited.
    /// \param curr_hash Receives the hash for node currently being visited.
    /// \param parent_diverged True if parent of node currently being visited
    /// is not in path from root to target node.
    /// \param curr_diverged True if node currently being visited is
    /// itself not in path from root to target node.
    /// \param proof Proof to receive sibling hashes.
    void get_inside_page_sibling_hashes(hasher_type &h,
        address_type address, int log2_size, hash_type &hash,
        const unsigned char *curr_data, int log2_curr_size,
        hash_type &curr_hash, int parent_diverged, int curr_diverged,
        proof_type &proof) const;

    /// \brief Gets the sibling hashes along the path from a
    /// page node towards a target node.
    /// \param address Address of target node.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \param hash Receives target node hash.
    /// \param page_data Pointer to start of contiguous page data.
    /// \param page_hash Receives the hash for the page.
    /// \param proof Proof to receive sibling hashes.
    void get_inside_page_sibling_hashes(
        address_type address, int log2_size, hash_type &hash,
        const unsigned char *page_data, hash_type &page_hash,
        proof_type &proof) const;

    // Precomputed hashes of spans of zero bytes with
    // increasing power-of-two sizes, from 2^LOG2_WORD_SIZE
    // to 2^LOG2_ROOT_SIZE bytes.
    static const pristine_merkle_tree m_pristine_hashes;

public:

    /// \brief Verifies the entire Merkle tree.
    /// \return True if tree is consistent, false otherwise.
    bool verify_tree(void) const;

    /// \brief Default constructor.
    /// \details Initializes memory to zero.
    machine_merkle_tree(void);

    /// \brief No copy constructor
    machine_merkle_tree(const machine_merkle_tree &) = delete;
    /// \brief No copy assignment
    machine_merkle_tree& operator=(const machine_merkle_tree &) = delete;
    /// \brief No move constructor
    machine_merkle_tree(machine_merkle_tree &&) = delete;
    /// \brief No move assignment
    machine_merkle_tree& operator=(machine_merkle_tree &&) = delete;

    /// \brief Destructor
    /// \details Releases all used memory
    ~machine_merkle_tree();

    /// \brief Returns the root hash.
    /// \param hash Receives the hash.
    void get_root_hash(hash_type &hash) const;

    /// \brief Start tree update.
    /// \returns True.
    /// \details This method is not thread safe, so be careful when using
    /// parallelization to compute Merkle trees
    bool begin_update(void);

    /// \brief Update tree with new hash for a page node.
    /// \param page_index Page index for node.
    /// \param hash New hash for node.
    /// \returns True if succeeded, false otherwise.
    /// \details This method is not thread safe, so be careful when using
    /// parallelization to compute Merkle trees
    bool update_page_node_hash(address_type page_index, const hash_type &hash);

    /// \brief End tree update.
    /// \param h Hasher object.
    /// \returns True if succeeded, false otherwise.
    /// \details This method is not thread safe, so be careful when using
    /// parallelization to compute Merkle trees
    bool end_update(hasher_type &h);

    /// \brief Returns the proof for a node in the tree.
    /// \param target_address Address of target node. Must be aligned
    /// to a 2<sup>log2_target_size</sup> boundary.
    /// \param log2_target_size log<sub>2</sub> of size subintended by
    /// target node. Must be between LOG2_WORD_SIZE and LOG2_ROOT_SIZE,
    /// inclusive.
    /// \param page_data When log2_target_size smaller than LOG2_PAGE_SIZE,
    /// \p page_data must point to start of contiguous page containing
    /// the node, or nullptr if the page is pristine (i.e., filled with zeros).
    /// \returns Proof if successful, otherwise throws exception.
    proof_type get_proof(address_type target_address, int log2_target_size,
            const unsigned char *page_data) const;

    /// \brief Recursively builds hash for page node from contiguous memory.
    /// \param h Hasher object.
    /// \param page_data Pointer to start of contiguous page data.
    /// \param hash Receives the hash.
    void get_page_node_hash(hasher_type &h, const unsigned char *page_data,
        hash_type &hash) const;

    /// \brief Gets currently stored hash for page node.
    /// \param page_index Page index for node.
    /// \param hash Receives the hash.
    void get_page_node_hash(address_type page_index, hash_type &hash) const;

    /// \brief Returns the hash for a log2_size pristine node.
    /// \param log2_size log<sub>2</sub> of size subintended by node.
    /// \return Reference to precomputed hash.
    static const hash_type &get_pristine_hash(int log2_size);

};

std::ostream &operator<<(std::ostream &out, const machine_merkle_tree::hash_type &hash);

} // namespace cartesi

#endif
