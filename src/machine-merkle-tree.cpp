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

#include "machine-merkle-tree.h"
#include "i-hasher.h"
#include "pristine-merkle-tree.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <tuple>

/// \file
/// \brief Merkle tree implementation.

namespace cartesi {

// Initialize static pristine hashes
const cartesi::pristine_merkle_tree &machine_merkle_tree::pristine_hashes() {
    static const cartesi::pristine_merkle_tree tree{machine_merkle_tree::get_log2_root_size(),
        machine_merkle_tree::get_log2_word_size()};
    return tree;
}

constexpr machine_merkle_tree::address_type machine_merkle_tree::get_page_index(address_type address) {
    return address & m_page_index_mask;
}

machine_merkle_tree::tree_node *machine_merkle_tree::get_page_node(address_type page_index) const {
    // Look for entry in page map hash table
    auto it = m_page_node_map.find(page_index);
    if (it != m_page_node_map.end()) {
        return it->second;
    }
    return nullptr;
}

constexpr machine_merkle_tree::address_type machine_merkle_tree::get_offset_in_page(address_type address) {
    return address & m_page_offset_mask;
}

int machine_merkle_tree::set_page_node_map(address_type page_index, tree_node *node) {
    m_page_node_map[page_index] = node;
    return 1;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
machine_merkle_tree::tree_node *machine_merkle_tree::create_node() const {
#ifdef MERKLE_DUMP_STATS
    m_num_nodes++;
#endif
    return new tree_node{};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void machine_merkle_tree::destroy_node(tree_node *node) const {
#ifdef MERKLE_DUMP_STATS
    --m_num_nodes;
#endif
    delete node;
}

machine_merkle_tree::tree_node *machine_merkle_tree::new_page_node(address_type page_index) {
    // Start with the first bit in the address space
    address_type bit_mask = UINT64_C(1) << (get_log2_root_size() - 1);
    tree_node *node = m_root;
    // Descend tree until we reach the node at the end of the
    // path determined by the page index,
    // creating the needed nodes along the way
    while (true) {
        const int bit = static_cast<int>((page_index & bit_mask) != 0);
        tree_node *child = node->child[bit];
        if (child == nullptr) {
            child = create_node();
            if (child == nullptr) {
                return nullptr;
            }
            child->parent = node;
            node->child[bit] = child;
        }
        node = child;
        bit_mask >>= 1;
        if ((bit_mask & m_page_index_mask) == 0) {
            break;
        }
    }
    // Finally associate page node to page index
    if (set_page_node_map(page_index, node) == 0) {
        return nullptr;
    }
    // Only if all previous steps succeeded, do we return the node
    return node;
}

void machine_merkle_tree::get_page_node_hash(hasher_type &h, const unsigned char *start, int log2_size,
    hash_type &hash) const {
    if (log2_size > get_log2_word_size()) {
        hash_type child0;
        hash_type child1;
        --log2_size;
        const address_type size = UINT64_C(1) << log2_size;
        get_page_node_hash(h, start, log2_size, child0);
        get_page_node_hash(h, start + size, log2_size, child1);
        get_concat_hash(h, child0, child1, hash);
    } else {
        h.begin();
        h.add_data(start, get_word_size());
        h.end(hash);
    }
}

void machine_merkle_tree::get_page_node_hash(hasher_type &h, const unsigned char *page_data, hash_type &hash) const {
    if (page_data != nullptr) {
        get_page_node_hash(h, page_data, get_log2_page_size(), hash);
    } else {
        hash = get_pristine_hash(get_log2_page_size());
    }
}

void machine_merkle_tree::get_page_node_hash(address_type page_index, hash_type &hash) const {
    assert(page_index == get_page_index(page_index));
    tree_node *node = get_page_node(page_index);
    if (node == nullptr) {
        hash = get_pristine_hash(get_log2_page_size());
    } else {
        hash = node->hash;
    }
}

const machine_merkle_tree::hash_type &machine_merkle_tree::get_child_hash(int child_log2_size, const tree_node *node,
    int bit) {
    const tree_node *child = node->child[bit];
    return (child != nullptr) ? child->hash : get_pristine_hash(child_log2_size);
}

void machine_merkle_tree::update_inner_node_hash(hasher_type &h, int log2_size, tree_node *node) {
    get_concat_hash(h, get_child_hash(log2_size - 1, node, 0), get_child_hash(log2_size - 1, node, 1), node->hash);
}

void machine_merkle_tree::dump_hash(const hash_type &hash) {
    auto f = std::cerr.flags();
    for (const auto &b : hash) {
        std::cerr << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    std::cerr << '\n';
    std::cerr.flags(f);
}

const machine_merkle_tree::hash_type &machine_merkle_tree::get_pristine_hash(int log2_size) {
    return pristine_hashes().get_hash(log2_size);
}

void machine_merkle_tree::dump_merkle_tree(tree_node *node, uint64_t address, int log2_size) const {
    for (int i = 0; i < get_log2_root_size() - log2_size; i++) {
        std::cerr << ' ';
    }
    std::cerr << "0x" << std::setfill('0') << std::setw(16) << std::hex << address << ":" << std::setfill('0')
              << std::setw(2) << std::dec << log2_size << ' ';
    if (node != nullptr) {
        dump_hash(node->hash);
        if (log2_size > get_log2_page_size()) {
            dump_merkle_tree(node->child[0], address, log2_size - 1);
            dump_merkle_tree(node->child[1], address + (UINT64_C(1) << (log2_size - 1)), log2_size - 1);
        }
    } else {
        std::cerr << "nullptr\n";
    }
}

void machine_merkle_tree::destroy_merkle_tree(tree_node *node, int log2_size) {
    if (node != nullptr) {
        // If this is an inner node, invoke recursively
        if (log2_size > get_log2_page_size()) {
            destroy_merkle_tree(node->child[0], log2_size - 1);
            destroy_merkle_tree(node->child[1], log2_size - 1);
        }
        destroy_node(node);
    }
}

void machine_merkle_tree::destroy_merkle_tree() {
    destroy_merkle_tree(m_root_storage.child[0], get_log2_root_size() - 1);
    destroy_merkle_tree(m_root_storage.child[1], get_log2_root_size() - 1);
    memset(&m_root_storage, 0, sizeof(m_root_storage));
}

void machine_merkle_tree::get_inside_page_sibling_hashes(hasher_type &h, address_type address, int log2_size,
    hash_type &hash, const unsigned char *curr_data, int log2_curr_size, hash_type &curr_hash, int parent_diverged,
    int curr_diverged, proof_type &proof) const {
    // If node currently being visited is larger than a
    // word, invoke recursively
    if (log2_curr_size > get_log2_word_size()) {
        const int log2_child_size = log2_curr_size - 1;
        const address_type child_size = UINT64_C(1) << log2_child_size;
        hash_type first_hash;
        hash_type second_hash;
        const int child_bit = static_cast<int>((address & child_size) != 0);
        get_inside_page_sibling_hashes(h, address, log2_size, hash, curr_data, log2_child_size, first_hash,
            static_cast<int>((parent_diverged != 0) || (curr_diverged) != 0), static_cast<int>(child_bit != 0), proof);
        get_inside_page_sibling_hashes(h, address, log2_size, hash, curr_data + child_size, log2_child_size,
            second_hash, static_cast<int>((parent_diverged != 0) || (curr_diverged) != 0),
            static_cast<int>(child_bit != 1), proof);
        // Compute curr_hash from hashes of its children
        get_concat_hash(h, first_hash, second_hash, curr_hash);
        // Otherwise directly compute hash of word
    } else {
        h.begin();
        h.add_data(curr_data, get_word_size());
        h.end(curr_hash);
    }
    if (parent_diverged == 0) {
        // So if the parent belongs to the path, but the node currently being
        // visited doesn't, it is a sibling and we store its hash.
        if ((curr_diverged != 0) && log2_curr_size >= proof.get_log2_target_size()) {
            proof.set_sibling_hash(curr_hash, log2_curr_size);
            // Otherwise, if the node hasn't diverged either and
            // it is has the same size as the target node, then it *is*
            // the target node
        } else if (log2_curr_size == log2_size) {
            hash = curr_hash;
        }
    }
}

void machine_merkle_tree::get_inside_page_sibling_hashes(address_type address, int log2_size, hash_type &hash,
    const unsigned char *page_data, hash_type &page_hash, proof_type &proof) const {
    hasher_type h;
    get_inside_page_sibling_hashes(h, address, log2_size, hash, page_data, get_log2_page_size(), page_hash,
        0 /* parent hasn't diverted */, 0 /* curr node hasn't diverged */, proof);
}

void machine_merkle_tree::dump_merkle_tree() const {
    dump_merkle_tree(m_root, 0, get_log2_root_size());
}

bool machine_merkle_tree::begin_update() {
    m_merkle_update_fifo.clear();
    return true;
}

bool machine_merkle_tree::update_page_node_hash(address_type page_index, const hash_type &hash) {
    assert(get_page_index(page_index) == page_index);
    tree_node *node = get_page_node(page_index);
    // If there is no page node for this page index, allocate a fresh one
    if (node == nullptr) {
        node = new_page_node(page_index);
    }
    // If allocation failed, we fail
    if (node == nullptr) {
        return false;
    }
    // Copy new hash value to node
    node->hash = hash;
    // Add parent to fifo so we propagate changes
    if ((node->parent != nullptr) && node->parent->mark != m_merkle_update_nonce) {
        m_merkle_update_fifo.emplace_back(get_log2_page_size() + 1, node->parent);
        node->parent->mark = m_merkle_update_nonce;
    }
    return true;
}

bool machine_merkle_tree::end_update(hasher_type &h) {
    // Now go over the queue of inner nodes updating their hashes and
    // enqueueing their parents until the queue is empty
    while (!m_merkle_update_fifo.empty()) {
        int log2_size{};
        tree_node *node{};
        std::tie(log2_size, node) = m_merkle_update_fifo.front();
        update_inner_node_hash(h, log2_size, node);
        m_merkle_update_fifo.pop_front();
        if ((node->parent != nullptr) && node->parent->mark != m_merkle_update_nonce) {
            m_merkle_update_fifo.emplace_back(log2_size + 1, node->parent);
            node->parent->mark = m_merkle_update_nonce;
        }
    }
    ++m_merkle_update_nonce;
    return true;
}

machine_merkle_tree::machine_merkle_tree() : m_root_storage{}, m_root{&m_root_storage} {
    m_root->hash = get_pristine_hash(get_log2_root_size());
#ifdef MERKLE_DUMP_STATS
    m_num_nodes = 0;
#endif
}

machine_merkle_tree::~machine_merkle_tree() {
#ifdef MERKLE_DUMP_STATS
    std::cerr << "before destruction\n";
    std::cerr << "  number of tree nodes:     " << m_num_nodes << '\n';
#endif
    destroy_merkle_tree();
#ifdef MERKLE_DUMP_STATS
    std::cerr << "after destruction\n";
    std::cerr << "  number of tree nodes:     " << m_num_nodes << '\n';
#endif
}

void machine_merkle_tree::get_root_hash(hash_type &hash) const {
    hash = m_root->hash;
}

bool machine_merkle_tree::verify_tree() const {
    hasher_type h;
    return verify_tree(h, m_root, get_log2_root_size());
}

bool machine_merkle_tree::verify_tree(hasher_type &h, tree_node *node, int log2_size) const {
    // pristine node is always correct
    if (node == nullptr) {
        return true;
    }
    // verify inner node
    if (log2_size > get_log2_page_size()) {
        const int child_log2_size = log2_size - 1;
        auto first_ok = verify_tree(h, node->child[0], child_log2_size);
        auto second_ok = verify_tree(h, node->child[1], child_log2_size);
        if (!first_ok || !second_ok) {
            return false;
        }
        hash_type hash;
        get_concat_hash(h, get_child_hash(child_log2_size, node, 0), get_child_hash(child_log2_size, node, 1), hash);
        return hash == node->hash;
        // Assume page nodes are correct
    }
    return true;
}

machine_merkle_tree::proof_type machine_merkle_tree::get_proof(address_type target_address, int log2_target_size,
    const unsigned char *page_data) const {
    // Check for valid target node size
    if (log2_target_size > get_log2_root_size() || log2_target_size < get_log2_word_size()) {
        throw std::runtime_error{"log2_target_size is out of bounds"};
    }

    // Check target address alignment
    if ((target_address & ((~UINT64_C(0)) >> (get_log2_root_size() - log2_target_size))) != 0) {
        throw std::runtime_error{"misaligned target address"};
    }

    proof_type proof{get_log2_root_size(), log2_target_size};

    // Copy hashes for nodes larger than or equal to the page size
    const int log2_stop_size = std::max(log2_target_size, get_log2_page_size());
    int log2_node_size = get_log2_root_size();
    const tree_node *node = m_root;
    // Copy non-pristine siblings hashes directly from tree nodes
    while ((node != nullptr) && log2_node_size > log2_stop_size) {
        const int log2_child_size = log2_node_size - 1;
        const int path_bit = static_cast<int>((target_address & (UINT64_C(1) << (log2_child_size))) != 0);
        proof.set_sibling_hash(get_child_hash(log2_child_size, node, static_cast<int>(static_cast<int>(path_bit) == 0)),
            log2_child_size);
        node = node->child[path_bit];
        log2_node_size = log2_child_size;
    }
    // At this point, there are three alternatives
    // Case 1
    // We hit a pristine node along the path to the target node
    if (node == nullptr) {
        if (page_data != nullptr) {
            throw std::runtime_error{"inconsistent merkle tree"};
        }
        // All remaining siblings along the path are pristine
        for (int i = log2_node_size - 1; i >= log2_target_size; --i) {
            proof.set_sibling_hash(get_pristine_hash(i), i);
        }
        // Copy pristine hash into target
        proof.set_target_hash(get_pristine_hash(log2_target_size));
        // Case 2
        // We hit a page node along the path to the target node
    } else if (log2_node_size == get_log2_page_size()) {
        assert(node);
        hash_type page_hash;
        // If target node is smaller than page size
        if (log2_target_size < get_log2_page_size()) {
            // If we were given the page data, compute from it
            if (page_data != nullptr) {
                get_inside_page_sibling_hashes(target_address, log2_target_size, proof.get_target_hash(), page_data,
                    page_hash, proof);
                // Otherwise, if page is pristine
            } else {
                page_hash = get_pristine_hash(get_log2_page_size());
                for (int i = get_log2_page_size() - 1; i >= log2_target_size; --i) {
                    proof.set_sibling_hash(get_pristine_hash(i), i);
                }
                proof.set_target_hash(get_pristine_hash(log2_target_size));
            }
            // Check if hash stored in node matches what we just computed
            if (node->hash != page_hash) {
                // Caller probably forgot to update the Merkle tree
                throw std::runtime_error{"inconsistent merkle tree"};
            }
            // If target node is the page itself
        } else {
            // Simply copy hash
            proof.set_target_hash(node->hash);
        }
        // Case 3
        // We hit the target node itself
    } else {
        assert(node && (log2_node_size == log2_target_size));
        // Copy target node hash and nothing else to do
        proof.set_target_hash(node->hash);
    }
    // Copy remaining proof values
    proof.set_target_address(target_address);
    proof.set_root_hash(m_root->hash); // NOLINT: m_root can't be nullptr
#ifndef NDEBUG
    // Return proof only if it passes verification
    hasher_type h;
    if (!proof.verify(h)) {
        throw std::runtime_error{"proof failed verification"};
    }
#endif
    return proof;
}

machine_merkle_tree::hash_type machine_merkle_tree::get_node_hash(address_type target_address,
    int log2_target_size) const {
    if (log2_target_size > get_log2_root_size() || log2_target_size < get_log2_word_size()) {
        throw std::runtime_error{"log2_target_size is out of bounds"};
    }
    if (log2_target_size < get_log2_page_size()) {
        throw std::runtime_error{"log2_target_size is smaller than page size"};
    }
    if ((target_address & ((static_cast<address_type>(1) << log2_target_size) - 1)) != 0) {
        throw std::invalid_argument{"address is not page-aligned"};
    }
    int log2_node_size = get_log2_root_size();
    const tree_node *node = m_root;
    // walk down the tree until we reach the target node
    while (node != nullptr && log2_node_size > log2_target_size) {
        const int log2_child_size = log2_node_size - 1;
        const int path_bit = static_cast<int>((target_address & (UINT64_C(1) << (log2_child_size))) != 0);
        node = node->child[path_bit];
        log2_node_size = log2_child_size;
    }
    if (node == nullptr) {
        // We hit a pristine node along the path to the target node
        return get_pristine_hash(log2_target_size);
    }
    return node->hash;
}

std::ostream &operator<<(std::ostream &out, const machine_merkle_tree::hash_type &hash) {
    auto f = out.flags();
    for (const unsigned b : hash) {
        out << std::hex << std::setfill('0') << std::setw(2) << b;
    }
    out.flags(f);
    return out;
}

} // namespace cartesi
