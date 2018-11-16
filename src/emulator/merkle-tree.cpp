#include "merkle-tree.h"

#include <iostream>
#include <iomanip>
#include <functional>
#include <cstring>
#include <cinttypes>
#include <cassert>
#include <cstdlib>

/// \file
/// \brief Merkle tree implementation.

constexpr merkle_tree::address_type
merkle_tree::
get_page_index(address_type address) const {
    return address & m_page_index_mask;
}

merkle_tree::tree_node *
merkle_tree::
get_page_node(address_type page_index) const {
    // Look for entry in page map hash table
    auto it = m_page_node_map.find(page_index);
    if (it != m_page_node_map.end()) {
        return it->second;
    } else {
        return nullptr;
    }
}

constexpr merkle_tree::address_type
merkle_tree::
get_offset_in_page(address_type address) const {
    return address & m_page_offset_mask;
}

const merkle_tree::hash_type &
merkle_tree::
get_sibling_hash(const siblings_type &sibling_hashes, int log2_size) {
    int index = get_log2_tree_size()-1-log2_size;
    assert(index >= 0 && index < (int) sibling_hashes.size());
    return sibling_hashes[index];
}

void
merkle_tree::
set_sibling_hash(const hash_type &hash, int log2_size, siblings_type &sibling_hashes) {
    int index = get_log2_tree_size()-1-log2_size;
    assert(index >= 0 && index < (int) sibling_hashes.size());
    sibling_hashes[index] = hash;
}

int
merkle_tree::
set_page_node_map(address_type page_index, tree_node *node) {
    m_page_node_map[page_index] = node;
    return 1;
}

merkle_tree::tree_node *
merkle_tree::
create_node(void) const {
#ifdef MERKLE_DUMP_STATS
    m_num_nodes++;
#endif
    return reinterpret_cast<tree_node *>(calloc(1, sizeof(tree_node)));
}

void
merkle_tree::
destroy_node(tree_node *node) const {
#ifdef MERKLE_DUMP_STATS
    --m_num_nodes;
#endif
    free(node);
}

merkle_tree::tree_node *
merkle_tree::
new_page_node(address_type page_index) {
    // Start with the first bit in the address space
    address_type bit_mask = UINT64_C(1) << (get_log2_tree_size() - 1);
    tree_node *node = m_root;
    // Descend tree until we reach the node at the end of the
    // path determined by the page index,
    // creating the needed nodes along the way
    while (1) {
        int bit = (page_index & bit_mask) != 0;
        tree_node *child = node->child[bit];
        if (!child) {
            child = create_node();
            if (!child)
                return nullptr;
            child->parent = node;
            node->child[bit] = child;
        }
        node = child;
        bit_mask >>= 1;
        if (!(bit_mask & m_page_index_mask))
            break;
    }
    // Finally associate page node to page index
    if (!set_page_node_map(page_index, node)) {
        return nullptr;
    }
    // Only if all previous steps succeeded, do we return the node
    return node;
}

void
merkle_tree::
update_page_node_hash(hasher_type &h, const uint8_t *start, int log2_size, hash_type &hash) const {
    if (log2_size > get_log2_word_size()) {
        hash_type child0, child1;
        --log2_size;
        address_type size = UINT64_C(1) << log2_size;
        update_page_node_hash(h, start, log2_size, child0);
        update_page_node_hash(h, start+size, log2_size, child1);
        get_concat_hash(h, child0, child1, hash);
    } else {
        h.begin();
        h.add_data(start, get_word_size());
        h.end(hash);
    }
}

const merkle_tree::hash_type &
merkle_tree::
get_child_hash(int child_log2_size, const tree_node *node,
    int bit) const {
    const tree_node *child = node->child[bit];
    return child? child->hash: get_pristine_hash(child_log2_size);
}

void
merkle_tree::
update_inner_node_hash(hasher_type &h, int log2_size, tree_node *node) {
    get_concat_hash(h, get_child_hash(log2_size-1, node, 0),
        get_child_hash(log2_size-1, node, 1), node->hash);
}

void
merkle_tree::
dump_hash(const hash_type &hash) const {
    auto f = std::cerr.flags();
    std::cerr << std::hex << std::setfill('0') << std::setw(2);
    for (unsigned i = 0; i < hash.size(); ++i) {
        unsigned b = hash[i];
        std::cerr << b;
    }
    std::cerr << '\n';
    std::cerr.flags(f);
}

const merkle_tree::hash_type &
merkle_tree::
get_pristine_hash(int log2_size) const {
    int index = get_log2_tree_size()-log2_size;
    assert(index >= 0 && index < (int) m_pristine_hashes.size());
    return m_pristine_hashes[index];
}

void
merkle_tree::
set_pristine_hash(const hash_type &hash, int log2_size) {
    int index = get_log2_tree_size()-log2_size;
    assert(index >= 0 && index < (int) m_pristine_hashes.size());
    m_pristine_hashes[index] = hash;
}

void
merkle_tree::
initialize_pristine_hashes(void) {
    hasher_type h;
    word_type zero = 0;
    hash_type hash;
    h.begin();
    h.add_data(reinterpret_cast<uint8_t *>(&zero), sizeof(zero));
    h.end(hash);
    set_pristine_hash(hash, get_log2_word_size());
    for (unsigned i = get_log2_word_size()+1; i <= get_log2_tree_size(); ++i) {
        get_concat_hash(h, hash, hash, hash);
        set_pristine_hash(hash, i);
    }
}

void
merkle_tree::
dump_merkle_tree(tree_node *node, int log2_size) const {
    std::cerr << log2_size << ": ";
    if (node) {
        dump_hash(node->hash);
        if (log2_size > get_log2_page_size()) {
            dump_merkle_tree(node->child[0], log2_size-1);
            dump_merkle_tree(node->child[1], log2_size-1);
        }
    } else {
        std::cerr << "nullptr\n";
    }
}

void
merkle_tree::
destroy_merkle_tree(tree_node *node, int log2_size) {
    if (node) {
        // If this is an inner node, invoke recursively
        if (log2_size > get_log2_page_size()) {
            destroy_merkle_tree(node->child[0], log2_size-1);
            destroy_merkle_tree(node->child[1], log2_size-1);
        }
        destroy_node(node);
    }
}

void
merkle_tree::
destroy_merkle_tree(void) {
    destroy_merkle_tree(m_root_storage.child[0],
        get_log2_tree_size()-1);
    destroy_merkle_tree(m_root_storage.child[1],
        get_log2_tree_size()-1);
    memset(&m_root_storage, 0, sizeof(m_root_storage));
}

void
merkle_tree::
get_inside_page_sibling_hashes(hasher_type &h,
    address_type address, int log2_size, hash_type &hash,
    const uint8_t *curr_data, int log2_curr_size, hash_type &curr_hash,
    int parent_diverged, int curr_diverged,
    siblings_type &sibling_hashes) const {
    // If node currently being visited is larger than a
    // word, invoke recursively
    if (log2_curr_size > get_log2_word_size()) {
        int log2_child_size = log2_curr_size-1;
        address_type child_size = UINT64_C(1) << log2_child_size;
        hash_type first_hash, second_hash;
        int child_bit = (address & child_size) != 0;
        get_inside_page_sibling_hashes(h,
            address, log2_size, hash,
            curr_data, log2_child_size, first_hash,
            parent_diverged || curr_diverged, child_bit != 0, sibling_hashes);
        get_inside_page_sibling_hashes(h,
            address, log2_size, hash,
            curr_data+child_size, log2_child_size, second_hash,
            parent_diverged || curr_diverged, child_bit != 1, sibling_hashes);
        // Compute curr_hash from hashes of its children
        get_concat_hash(h, first_hash, second_hash, curr_hash);
    // Otherwise directly compute hash of word
    } else {
        h.begin();
        h.add_data(curr_data, get_word_size());
        h.end(curr_hash);
    }
    if (!parent_diverged) {
        // So if the parent belongs to the path, but the node currently being
        // visited doesn't, it is a sibling and we store its hash.
        if (curr_diverged) {
            set_sibling_hash(curr_hash, log2_curr_size, sibling_hashes);
        // Otherwise, if the node hasn't diverged either and
        // it is has the same size as the target node, then it *is*
        // the target node
        } else if (log2_curr_size == log2_size) {
            hash = curr_hash;
        }
    }
}

void
merkle_tree::
get_inside_page_sibling_hashes(
    address_type address, int log2_size, hash_type &hash,
    const uint8_t *page_data, hash_type &page_hash,
    siblings_type &sibling_hashes) const {
    hasher_type h;
    get_inside_page_sibling_hashes(h,
        address, log2_size, hash,
        page_data, get_log2_page_size(), page_hash,
        0 /* parent hasn't diverted */ , 0 /* curr node hasn't diverged */,
        sibling_hashes);
}

void
merkle_tree::
dump_merkle_tree(void) const {
    dump_merkle_tree(m_root, get_log2_tree_size());
}

merkle_tree::status_code
merkle_tree::
begin_update(hasher_type &h) {
    (void) h;
    m_merkle_update_fifo.clear();
    return status_code::success;
}


merkle_tree::status_code
merkle_tree::
update_page(hasher_type &h, address_type page_index, const uint8_t *page_data) {
    assert(get_page_index(page_index) == page_index);
    tree_node *node = get_page_node(page_index);
    // If there is no page node for this page index, allocate a fresh one
    if (!node) {
        node = new_page_node(page_index);
        if (!node) {
            return status_code::error_out_of_memory;
        }
    }
    if (page_data) update_page_node_hash(h, page_data, get_log2_page_size(), node->hash);
    else node->hash = get_pristine_hash(get_log2_page_size());
    if (node->parent && node->parent->mark != m_merkle_update_nonce) {
        m_merkle_update_fifo.push_back(
            std::make_pair(get_log2_page_size()+1, node->parent));
        node->parent->mark = m_merkle_update_nonce;
    }
    return status_code::success;
}

merkle_tree::status_code
merkle_tree::
end_update(hasher_type &h) {
    // Now go over the queue of inner nodes updating their hashes and
    // enqueueing their parents until the queue is empty
    while (!m_merkle_update_fifo.empty()) {
        int log2_size;
        tree_node *node;
        std::tie(log2_size, node) = m_merkle_update_fifo.front();
        update_inner_node_hash(h, log2_size, node);
        m_merkle_update_fifo.pop_front();
        if (node->parent && node->parent->mark != m_merkle_update_nonce) {
            m_merkle_update_fifo.push_back(
                std::make_pair(log2_size+1, node->parent));
            node->parent->mark = m_merkle_update_nonce;
        }
    }
    ++m_merkle_update_nonce;
    return status_code::success;
}

merkle_tree::
merkle_tree(void) {
    memset(&m_root_storage, 0, sizeof(m_root_storage));
    m_root = &m_root_storage;
    initialize_pristine_hashes();
    m_root->hash = get_pristine_hash(get_log2_tree_size());
    m_merkle_update_nonce = 1;
#ifdef MERKLE_DUMP_STATS
    m_num_nodes = 0;
#endif
}

merkle_tree::
~merkle_tree() {
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

merkle_tree::status_code
merkle_tree::
get_root_hash(hash_type &hash) const {
    hash = m_root->hash;
    return status_code::success;
}

merkle_tree::status_code
merkle_tree::
verify(void) const {
    hasher_type h;
    return verify(h, m_root, get_log2_tree_size());
}

void
merkle_tree::
get_concat_hash(hasher_type &h, const hash_type &child0,
    const hash_type &child1, hash_type &parent) const {
    h.begin();
    h.add_data(child0.data(), child0.size());
    h.add_data(child1.data(), child1.size());
    h.end(parent);
}

merkle_tree::status_code
merkle_tree::
verify(hasher_type &h, tree_node *node, int log2_size) const {
    // pristine node is always correct
    if (!node) {
        return status_code::success;
    }
    // verify inner node
    if (log2_size > get_log2_page_size()) {
        int child_log2_size = log2_size-1;
        auto first = verify(h, node->child[0], child_log2_size);
        auto second = verify(h, node->child[1], child_log2_size);
        if (is_error(first) || is_error(second)) {
            return status_code::error;
        }
        hash_type hash;
        get_concat_hash(h, get_child_hash(child_log2_size, node, 0),
            get_child_hash(child_log2_size, node, 1), hash);
        if (hash != node->hash) {
            return status_code::error;
        } else {
            return status_code::success;
        }
    // Assume page nodes are correct
    } else {
        return status_code::success;
    }
}

merkle_tree::status_code
merkle_tree::
get_proof(address_type address, int log2_size, const uint8_t *page_data, proof_type &proof) const {
    // Check for valid target node size
    if (log2_size > get_log2_tree_size() || log2_size < get_log2_word_size()) {
        return status_code::error;
    }
    // Check target address alignment
    if (address & ((~UINT64_C(0)) >> (64-log2_size))) {
        return status_code::error;
    }
    // Copy hashes for nodes larger than or equal to the page size
    int log2_stop_size = std::max(log2_size, get_log2_page_size());
    int log2_node_size = get_log2_tree_size();
    const tree_node *node = m_root;
    // Copy non-pristine siblings hashes directly from tree nodes
    while (node && log2_node_size > log2_stop_size) {
        int log2_child_size = log2_node_size-1;
        int path_bit = (address & (UINT64_C(1) << (log2_child_size))) != 0;
        set_sibling_hash(get_child_hash(log2_child_size, node, !path_bit), log2_child_size, proof.sibling_hashes);
        node = node->child[path_bit];
        log2_node_size = log2_child_size;
    }
    // At this point, there are three alternatives
    // Case 1
    // We hit a pristine node along the path to the target node
    if (!node) {
        if (page_data) {
            return status_code::error;
        }
        // All remaining siblings along the path are pristine
        for (int i = log2_node_size-1; i >= log2_size; --i) {
            set_sibling_hash(get_pristine_hash(i), i, proof.sibling_hashes);
        }
        // Copy pristine hash into target
        proof.target_hash = get_pristine_hash(log2_size);
    // Case 2
    // We hit a page node along the path to the target node
    } else if (log2_node_size == get_log2_page_size()) {
        assert(node);
        hash_type page_hash;
        // If we have the page data, compute from it
        if (page_data) {
            get_inside_page_sibling_hashes(address, log2_size, proof.target_hash,
                page_data, page_hash, proof.sibling_hashes);
        // Otherwise the page is pristine
        } else {
            page_hash = get_pristine_hash(get_log2_page_size());
            for (int i = get_log2_page_size()-1; i >= log2_size; --i) {
                set_sibling_hash(get_pristine_hash(i), i, proof.sibling_hashes);
            }
            proof.target_hash = get_pristine_hash(log2_size);
        }
        // Check if hash stored in node matches what we just computed
        if (node->hash != page_hash) {
            // Caller probably forgot to update the Merkle tree
            return status_code::error;
        }
    // Case 3
    // We hit the target node itself
    } else {
        assert(node && log2_node_size == log2_size);
        // Copy target node hash and nothing else to do
        proof.target_hash = node->hash;
    }
    // Clear unecesassary sibling hashes, if any
    hash_type zero;
    zero.fill(0);
    for (int i = log2_size-1; i >= get_log2_word_size(); --i) {
        set_sibling_hash(zero, i, proof.sibling_hashes);
    }
    // Copy remaining proof values
    proof.address = address;
    proof.log2_size = log2_size;
    proof.root_hash = m_root->hash;
    return status_code::success;
}

std::ostream &operator<<(std::ostream &out, const merkle_tree::hash_type &hash) {
    auto f = out.flags();
    for (unsigned b: hash) {
        out << std::hex << std::setfill('0') << std::setw(2) << b;
    }
    out.flags(f);
    return out;
}
