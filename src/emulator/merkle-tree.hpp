/// \file
/// \brief Merkle tree implementation.

template <int T, int P, typename H>
constexpr uint64_t
merkle_tree_t<T,P,H>::
get_page_index(uint64_t address) {
    return address & m_page_index_mask;
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::tree_node *
merkle_tree_t<T,P,H>::
get_page_node(uint64_t page_index) const {
    // Look for entry in page map hash table
    auto it = m_page_node_map.find(page_index);
    if (it != m_page_node_map.end()) {
        return it->second;
    } else {
        return nullptr;
    }
}

template <int T, int P, typename H>
constexpr uint64_t
merkle_tree_t<T,P,H>::
get_offset_in_page(uint64_t address) {
    return address & m_page_offset_mask;
}

template <int T, int P, typename H>
const typename merkle_tree_t<T,P,H>::digest_type &
merkle_tree_t<T,P,H>::
get_proof_hash(const word_value_proof &proof, int log2_size) const {
    log2_size -= get_log2_word_size();
    return proof[log2_size];
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
set_proof_hash(word_value_proof &proof, int log2_size,
    const digest_type &hash) const {
    log2_size -= get_log2_word_size();
    proof[log2_size] = hash;
}

template <int T, int P, typename H>
int
merkle_tree_t<T,P,H>::
set_page_node_map(uint64_t page_index, tree_node *node) {
    m_page_node_map[page_index] = node;
    return 1;
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::tree_node *
merkle_tree_t<T,P,H>::
create_node(void) const {
#ifdef MERKLE_DUMP_STATS
    m_num_nodes++;
#endif
    return reinterpret_cast<tree_node *>(calloc(1, sizeof(tree_node)));
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
destroy_node(tree_node *node) const {
#ifdef MERKLE_DUMP_STATS
    --m_num_nodes;
#endif
    free(node);
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::tree_node *
merkle_tree_t<T,P,H>::
new_page_node(uint64_t page_index) {
    // Start with the first bit in the address space
    uint64_t bit_mask = 1ull << (get_log2_tree_size() - 1);
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

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
update_page_node_hash(H &h, const uint8_t *start, int log2_size, digest_type &hash) const {
    if (log2_size > get_log2_word_size()) {
        digest_type child0, child1;
        --log2_size;
        uint64_t size = 1ull << log2_size;
        update_page_node_hash(h, start, log2_size, child0);
        update_page_node_hash(h, start+size, log2_size, child1);
        get_concat_hash(h, child0, child1, hash);
    } else {
        h.begin();
        h.add_data(start, get_word_size());
        h.end(hash);
    }
}

template <int T, int P, typename H>
const typename merkle_tree_t<T,P,H>::digest_type &
merkle_tree_t<T,P,H>::
get_inner_child_hash(int child_log2_size, const tree_node *node,
    int bit) const {
    const tree_node *child = node->child[bit];
    return child? child->hash: get_pristine_hash(child_log2_size);
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
update_inner_node_hash(H &h, int log2_size, tree_node *node) {
    get_concat_hash(h, get_inner_child_hash(log2_size-1, node, 0),
        get_inner_child_hash(log2_size-1, node, 1), node->hash);
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
dump_hash(const digest_type &hash) const {
    auto f = std::cerr.flags();
    std::cerr << std::hex << std::setfill('0') << std::setw(2);
    for (unsigned i = 0; i < hash.size(); ++i) {
        unsigned b = hash[i];
        std::cerr << b;
    }
    std::cerr << '\n';
    std::cerr.flags(f);
}

template <int T, int P, typename H>
const typename merkle_tree_t<T,P,H>::digest_type &
merkle_tree_t<T,P,H>::
get_pristine_hash(int log2_size) const {
    return get_proof_hash(m_pristine_hashes, log2_size);
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
initialize_pristine_hashes(void) {
    H h;
    //??D change this to the crazy EVM hash
    constexpr int nzeros = 32;
    uint8_t zeros[nzeros];
    memset(zeros, 0, nzeros);
    h.begin();
    int todo = m_word_size;
    while (todo > 0) {
        int now = std::min(nzeros, todo);
        h.add_data(zeros, now);
        todo -= now;
    }
    h.end(m_pristine_hashes[0]);
    for (unsigned i = 1; i < m_pristine_hashes.size(); ++i) {
        get_concat_hash(h, m_pristine_hashes[i-1],
            m_pristine_hashes[i-1], m_pristine_hashes[i]);
    }
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
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

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
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

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
destroy_merkle_tree(void) {
    destroy_merkle_tree(m_root_storage.child[0],
        get_log2_tree_size()-1);
    destroy_merkle_tree(m_root_storage.child[1],
        get_log2_tree_size()-1);
    memset(&m_root_storage, 0, sizeof(m_root_storage));
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
get_inside_page_word_value_proof(H &h, uint64_t address, int parent_diverged,
    int diverged, const uint8_t *node_data, int log2_size,
    word_value_proof &proof, digest_type &hash) const {
    if (log2_size > get_log2_word_size()) {
        int log2_child_size = log2_size-1;
        uint64_t child_size = 1ull << log2_child_size;
        digest_type first, second;
        int bit = (address & child_size) != 0;
        get_inside_page_word_value_proof(h, address,
            parent_diverged || diverged, bit != 0,
            node_data, log2_child_size, proof, first);
        get_inside_page_word_value_proof(h, address,
            parent_diverged || diverged, bit != 1,
            node_data+child_size, log2_child_size, proof, second);
        get_concat_hash(h, first, second, hash);
    } else {
        h.begin();
        h.add_data(node_data, get_word_size());
        h.end(hash);
    }
    // We only store siblings of nodes along the path. So if
    // the parent belongs to the path, but the node doesn't,
    // we store it.
    if (!parent_diverged && diverged) {
        set_proof_hash(proof, log2_size, hash);
    }
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
get_inside_page_word_value_proof(uint64_t address,
    const uint8_t *page_data, word_value_proof &proof,
    digest_type &page_hash) const {
    H h;
    get_inside_page_word_value_proof(h, address, 0, 0,
        page_data, get_log2_page_size(), proof, page_hash);
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
dump_merkle_tree(void) const {
    dump_merkle_tree(m_root, get_log2_tree_size());
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
begin_update(H &h) {
    (void) h;
    m_merkle_update_fifo.clear();
    return status_code::success;
}


template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
update_page(H &h, uint64_t page_index, const uint8_t *page_data) {
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

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
end_update(H &h) {
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

template <int T, int P, typename H>
merkle_tree_t<T,P,H>::
merkle_tree_t(void) {
    memset(&m_root_storage, 0, sizeof(m_root_storage));
    m_root = &m_root_storage;
    initialize_pristine_hashes();
    m_root->hash = get_pristine_hash(get_log2_tree_size());
    m_merkle_update_nonce = 1;
#ifdef MERKLE_DUMP_STATS
    m_num_nodes = 0;
#endif
}

template <int T, int P, typename H>
merkle_tree_t<T,P,H>::
~merkle_tree_t() {
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

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
get_merkle_tree_root_hash(digest_type &hash) {
    hash = m_root->hash;
    return status_code::success;
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
get_pristine_proof(word_value_proof &proof) {
    proof = m_pristine_hashes;
    return status_code::success;
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
verify_merkle_tree(void) const {
    return verify_merkle_tree(H(), m_root, get_log2_tree_size());
}

template <int T, int P, typename H>
void
merkle_tree_t<T,P,H>::
get_concat_hash(H &h, const digest_type &child0,
    const digest_type &child1, digest_type &parent) const {
    h.begin();
    h.add_data(child0.data(), child0.size());
    h.add_data(child1.data(), child1.size());
    h.end(parent);
}

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
verify_merkle_tree(H &h, tree_node *node, int log2_size) const {
    // pristine node is always correct
    if (!node) {
        return status_code::success;
    }
    // verify inner node
    if (log2_size > get_log2_page_size()) {
        int child_log2_size = log2_size-1;
        auto first = verify_merkle_tree(h, node->child[0],
            child_log2_size);
        auto second = verify_merkle_tree(h, node->child[1],
            child_log2_size);
        if (is_error(first) || is_error(second)) {
            return status_code::error;
        }
        digest_type hash;
        get_concat_hash(h, get_inner_child_hash(child_log2_size, node, 0),
            get_inner_child_hash(child_log2_size, node, 1), hash);
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

template <int T, int P, typename H>
typename merkle_tree_t<T,P,H>::status_code
merkle_tree_t<T,P,H>::
get_word_value_proof(uint64_t address, const uint8_t *page_data, word_value_proof &proof) const {
    // Descend on the tree until we either hit a pristine subtree or a page
    tree_node *node = m_root;
    int child_log2_size = get_log2_tree_size()-1;
    while (1) {
        if (child_log2_size < get_log2_page_size()) break;
        int bit = (address & (1ull << child_log2_size)) != 0;
        tree_node *child = node->child[bit];
        if (!child) break;
        node = child;
        --child_log2_size;
    }
    int log2_size = child_log2_size+1;
    // If we hit a non-pristine page, compute hashes inside page
    // (page_data = nullptr means a pristine page)
    if (log2_size == get_log2_page_size() && page_data) {
        digest_type page_hash;
        // Get inside-page hashes by computing them directly from the page
        get_inside_page_word_value_proof(address, page_data, proof, page_hash);
        // Check that, indeed, the newly computed hash for the page matches
        // the hash we have stored in the tree
        if (page_hash != node->hash) {
            // Caller probably forgot to update the Merkle tree
            return status_code::error;
        }
    // Otherwise, everything is pristine up to the current child_log2_size
    } else {
        // Copy pristine hashes
        for (int i = get_log2_word_size(); i < log2_size; ++i) {
            set_proof_hash(proof, i, get_pristine_hash(i));
        }
    }
    // Continue from our node up to the tree root, storing the uncles
    // of every node
    for (int i = log2_size; i < get_log2_tree_size(); ++i) {
        assert(node->parent);
        int bit = (address & (1ull << i)) != 0;
        assert(node->parent->child[bit] == node);
        set_proof_hash(proof, i, get_inner_child_hash(i, node->parent, !bit));
        node = node->parent;
    }
    // Copy root hash
    set_proof_hash(proof, get_log2_tree_size(), m_root->hash);

    if (log2_size < get_log2_tree_size()) {
        return status_code::error_should_not_happen;
    } else {
        return status_code::success;
    }
    return status_code::success;
}
