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

#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

/// \file
/// \brief Circular buffer container

#include <concepts>
#include <cstddef>
#include <iterator>
#include <limits>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include <boost/container/static_vector.hpp>
#include <boost/iterator/iterator_adaptor.hpp>

#include "concepts.h"
#include "meta.h"

namespace cartesi {

/// \brief Circular buffer container.
/// \tparam T type of entry in container.
/// \tparam N maximum number of entries container can hold.
/// \details The circular buffer container with a fixed number of entries.
/// The container that be statically allocated, when \p N is passed as a template argument at compile time.
/// It can be dynamically allocated, with the size is chosen in the constructor at runtime.
/// \p T does not need to be default-constructible.
template <typename T, size_t N = std::dynamic_extent>
class circular_buffer {
    using base = circular_buffer<T, N>;
    using container_dynamic = std::vector<T>;
    using container_static = boost::container::static_vector<T, N + 1>;
    using container_base = std::conditional_t<N == std::dynamic_extent, container_dynamic, container_static>;

public:
    using value_type = typename container_base::value_type;
    using size_type = typename container_base::size_type;
    using difference_type = typename container_base::difference_type;
    using reference = typename container_base::reference;
    using const_reference = typename container_base::const_reference;
    using pointer = typename container_base::pointer;
    using const_pointer = typename container_base::const_pointer;

    static constexpr auto max_size = std::numeric_limits<difference_type>::max() - 1;

    /// \brief Constructor for statically allocated container
    constexpr circular_buffer() noexcept
        requires(N > 0 && N < max_size && N != std::dynamic_extent)
        : m_uninitialized_entries{modulus()} {}

    /// \brief Constructor for dynamically allocated container
    /// \param n maximum number of entries container can hold
    explicit circular_buffer(size_type n)
        requires(N == std::dynamic_extent)
        : m_uninitialized_entries{static_cast<difference_type>(n + 1)}, m_modulus{static_cast<difference_type>(n + 1)} {
        if (n == 0) {
            throw std::invalid_argument{"capacity must be > 0"};
        }
        if (n > max_size) {
            throw std::invalid_argument{"capacity is too large"};
        }
        m_storage.reserve(n + 1); // Allocate once and for all
    }

    // Default move and copy constructors
    circular_buffer(const circular_buffer &) = default;
    circular_buffer(circular_buffer &&) noexcept = default;
    circular_buffer &operator=(const circular_buffer &) = default;
    circular_buffer &operator=(circular_buffer &&) noexcept = default;
    ~circular_buffer() = default;

    /// \brief Returns number of entries currently in container
    /// \returns Number of entries currently in container
    [[nodiscard]] size_type size() const noexcept {
        auto n = m_end - m_begin;
        if (n < 0) {
            n += modulus();
        }
        return static_cast<size_type>(n);
    }

    /// \brief Returns maximum number of entries container can hold
    /// \returns Maximum number of entries container can hold
    [[nodiscard]] constexpr size_type capacity() const noexcept {
        if constexpr (N == std::dynamic_extent) {
            return m_modulus - 1;
        } else {
            return N;
        }
    }

    /// \brief Returns modulus to use for modular arithmetic
    /// \returns Modulus to use for modular arithmetic
    [[nodiscard]] constexpr difference_type modulus() const noexcept {
        if constexpr (N == std::dynamic_extent) {
            return m_modulus;
        } else {
            return static_cast<difference_type>(N + 1);
        }
    }

    /// \brief Tells if container is empty
    /// \returns True if empty, false otherwise
    [[nodiscard]] bool empty() const noexcept {
        return m_begin == m_end;
    }

    /// \brief Tells if container is full
    /// \returns True if true, false otherwise
    [[nodiscard]] bool full() const noexcept {
        return size() == capacity();
    }

    /// \brief Adds new entry to back of container
    /// \tparam U Type for universal reference to value
    /// \param value Value to insert. L-value references are copied, r-value references are moved.
    template <typename U>
        requires std::constructible_from<T, U &&>
    void push_back(U &&value) noexcept {
        // If we still have uninitialized entries, push_back into storage
        if (m_uninitialized_entries != 0) {
            --m_uninitialized_entries;
            m_storage.push_back(std::forward<U>(value));
            // Otherwise, simply copy/move construct over initialized entries
        } else {
            dereference_offset(m_end) = std::forward<U>(value);
        }
        increment_offset(m_end);
        if (m_end == m_begin) {
            increment_offset(m_begin);
        }
    }

    /// \brief Construct entry at back of container
    /// \tparam Args... Types of entry constructor arguments
    /// \param ...args Arguments to entry constructor
    template <typename... Args>
        requires std::constructible_from<T, Args...>
    void emplace_back(Args &&...args) {
        if (m_uninitialized_entries != 0) {
            --m_uninitialized_entries;
            m_storage.emplace_back(std::forward<Args>(args)...);
        } else {
            dereference_offset(m_end) = T(std::forward<Args>(args)...);
        }
        increment_offset(m_end);
        if (m_end == m_begin) {
            increment_offset(m_begin);
        }
    }

    /// \brief Adds new entry to back of container, if not already there
    /// \tparam U Type for universal reference to value
    /// \param value Value to insert. L-value references are copied, r-value references are moved.
    /// \details The container must not be full.
    template <typename U>
        requires std::constructible_from<T, U &&> && std::equality_comparable_with<T, U>
    void try_push_back(U &&value) noexcept {
        if (empty() || back() != value) {
            assert(!full() && "circular buffer container is full");
            push_back(std::forward<U>(value));
        }
    }

    /// \brief Removes entry at back of container, if any
    void pop_back() noexcept {
        if (!empty()) {
            decrement_offset(m_end);
        }
    }

    /// \brief Removes entry at the front of container, if any
    void pop_front() noexcept {
        if (!empty()) {
            increment_offset(m_begin);
        }
    }

    /// \brief Returns entry at front of container
    /// \detail If container is empty, returns garbage
    reference front() noexcept {
        return dereference_offset(m_begin);
    }

    /// \brief Returns entry at front of container
    /// \detail If container is empty, returns garbage
    const_reference front() const noexcept {
        return dereference_offset(m_begin);
    }

    /// \brief Returns entry at back of container
    /// \detail If container is empty, returns garbage
    reference back() noexcept {
        auto b = m_end;
        decrement_offset(b);
        return dereference_offset(b);
    }

    /// \brief Returns entry at back of container
    /// \detail If container is empty, returns garbage
    const_reference back() const noexcept {
        auto b = m_end;
        decrement_offset(b);
        return dereference_offset(b);
    }

    /// \brief Removes all entries from container
    void clear() noexcept {
        m_storage.clear();
        m_storage.reserve(modulus());
        m_begin = m_end = 0;
        m_uninitialized_entries = modulus();
    }

    /// \brief Base class for all iterators
    /// \tparam CB class of container (so it works with const and non-const)
    /// \tparam Value class of container entry (so it works with const and non-const)
    template <typename CB, typename Value>
    class iterator_base :
        public boost::iterator_facade<iterator_base<CB, Value>, Value, std::random_access_iterator_tag, Value &,
            difference_type> {
        CB *m_cb;
        difference_type m_offset;

    public:
        iterator_base() noexcept : iterator_base::iterator_facade_{}, m_cb{}, m_offset{0} {}

        iterator_base(CB *cb, difference_type offset) noexcept :
            iterator_base::iterator_facade_{},
            m_cb{cb},
            m_offset{offset} {}

    private:
        friend class boost::iterator_core_access;

        void increment() {
            m_cb->increment_offset(m_offset);
        }

        void decrement() {
            m_cb->decrement_offset(m_offset);
        }

        template <typename CB_Other, typename ValueOther>

        bool equal(const iterator_base<CB_Other, ValueOther> &other) const
            requires SameAsNoCVRef<CB, CB_Other> && SameAsNoCVRef<Value, ValueOther>
        {
            if (m_cb != other.m_cb) {
                return false;
            }
            return m_cb->equal_offset(m_offset, other.m_offset);
        }

        Value &dereference() const {
            return m_cb->dereference_offset(m_offset);
        }
    };

    // Friend declaration so iterators can use private methods in container
    template <typename CB, typename Value>
    friend class iterator_base;

    // Iterator types
    using iterator = iterator_base<base, value_type>;
    using const_iterator = iterator_base<const base, const value_type>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using reverse_iterator = std::reverse_iterator<iterator>;

    /// \brief Returns iterator to first entry in container
    /// \returns Iterator to first entry in container
    auto begin() noexcept {
        return iterator{this, m_begin};
    }

    /// \brief Returns iterator to one past last entry in container
    /// \returns Iterator to one past last entry in container
    auto end() noexcept {
        return iterator{this, m_end};
    }

    /// \brief Returns iterator to first entry in container
    /// \returns Iterator to first entry in container
    auto begin() const noexcept {
        return const_iterator{this, m_begin};
    }

    /// \brief Returns iterator to one past last entry in container
    /// \returns Iterator to one past last entry in container
    auto end() const noexcept {
        return const_iterator{this, m_end};
    }

    /// \brief Returns constant iterator to first entry in container
    /// \returns Constant iterator to first entry in container
    auto cbegin() const noexcept {
        return const_iterator{this, m_begin};
    }

    /// \brief Returns constant iterator to one past last entry in container
    /// \returns Constant iterator to one past last entry in container
    auto cend() const noexcept {
        return const_iterator{this, m_end};
    }

    /// \brief Returns iterator to first entry in reversed container
    /// \returns Iterator to first entry in reversed container
    auto rbegin() noexcept {
        return reverse_iterator{end()};
    }

    /// \brief Returns iterator to one past last entry in revesed container
    /// \returns Iterator to one past last entry in revesed container
    auto rend() noexcept {
        return reverse_iterator{begin()};
    }

    /// \brief Returns iterator to first entry in reversed container
    /// \returns Iterator to first entry in reversed container
    auto rbegin() const noexcept {
        return const_reverse_iterator{end()};
    }

    /// \brief Returns iterator to one past last entry in revesed container
    /// \returns Iterator to one past last entry in revesed container
    auto rend() const noexcept {
        return const_reverse_iterator{begin()};
    }

    /// \brief Returns constant iterator to first entry in reversed container
    /// \returns Constant iterator to first entry in reversed container
    auto crbegin() const noexcept {
        return const_reverse_iterator{end()};
    }

    /// \brief Returns constant iterator to one past last entry in revesed container
    /// \returns Constant iterator to one past last entry in revesed container
    auto crend() const noexcept {
        return const_reverse_iterator{begin()};
    }

private:
    /// \brief Increment offset using modular arithmetic
    /// \details Assumes offset is in {0, ..., modulus()-1}
    void increment_offset(difference_type &offset) noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        ++offset;
        if (offset >= modulus()) {
            offset -= modulus();
        }
    }

    /// \brief Decrements offset using modular arithmetic
    /// \details Assumes offset is in {0, ..., modulus()-1}
    void decrement_offset(difference_type &offset) noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        --offset;
        if (offset < 0) {
            offset += modulus();
        }
    }

    /// \brief Returns reference to entry at offset
    /// \details Assumes offset is in {0, ..., modulus()-1}
    reference dereference_offset(difference_type offset) noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        return *(m_storage.data() + offset);
    }

    /// \brief Returns constant reference to entry at offset
    /// \details Assumes offset is in {0, ..., modulus()-1}
    const_reference dereference_offset(difference_type offset) const noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        return *(m_storage.data() + offset);
    }

    /// \brief Checks if offsets refer to same entry
    /// \details Assumes offset is in {0, ..., modulus()-1}
    static bool equal_offset(difference_type a, difference_type b) noexcept {
        return a == b;
    }

    container_base m_storage; // Storage for all entries. Starts empty (but already allocated).
    // m_begin and m_end use modular arithmetic and are always in {0, modulus()-1}
    difference_type m_begin{0};              // First entry
    difference_type m_end{0};                // One past past last entry
    difference_type m_uninitialized_entries; // Number of entries not yet initialized
    [[no_unique_address]] std::conditional_t<N == std::dynamic_extent, difference_type, std::monostate> m_modulus;
};

} // namespace cartesi

#endif // CIRCULAR_BUFFER_H
