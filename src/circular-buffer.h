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
#include <span>
#include <utility>

#include <boost/container/static_vector.hpp>
#include <boost/iterator/iterator_adaptor.hpp>

#include "meta.h"

namespace cartesi {

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
    template <typename CB, typename Value>
    class iterator_base;

    constexpr circular_buffer() noexcept
        requires(N != std::dynamic_extent)
        : m_open_slots{modulus()} {}

    explicit circular_buffer(size_type n)
        requires(N == std::dynamic_extent)
        : m_open_slots{static_cast<difference_type>(n + 1)}, m_modulus{static_cast<difference_type>(n + 1)} {
        m_storage.reserve(n + 1); // Allocate once and for all
    }

    circular_buffer(const circular_buffer &) = default;
    circular_buffer(circular_buffer &&) noexcept = default;
    circular_buffer &operator=(const circular_buffer &) = default;
    circular_buffer &operator=(circular_buffer &&) noexcept = default;

    size_type size() const noexcept {
        auto n = m_tail - m_head;
        if (n < 0) {
            n += modulus();
        }
        return n;
    }

    size_t capacity() const noexcept
        requires(N == std::dynamic_extent)
    {
        return modulus() - 1;
    }

    constexpr size_t capacity() const noexcept
        requires(N != std::dynamic_extent)
    {
        return modulus() - 1;
    }

    auto modulus() const noexcept
        requires(N == std::dynamic_extent)
    {
        return m_modulus;
    }

    constexpr auto modulus() const noexcept
        requires(N != std::dynamic_extent)
    {
        return static_cast<difference_type>(N + 1);
    }

    bool empty() const noexcept {
        return m_head == m_tail;
    }

    bool full() const noexcept {
        return size() == capacity();
    }

    const_reference operator[](difference_type n) const noexcept {
        auto offset = m_head;
        advance_offset(offset, n);
        return dereference_offset(offset);
    }

    reference operator[](difference_type n) noexcept {
        auto offset = m_head;
        advance_offset(offset, n);
        return dereference_offset(offset);
    }

    template <typename U>
    void push_back(U &&value) noexcept
        requires std::is_nothrow_convertible_v<std::remove_cvref_t<U> *, T *>
    {
        if (m_open_slots != 0) {
            --m_open_slots;
            m_storage.push_back(std::forward<U>(value));
        } else {
            dereference_offset(m_tail) = std::forward<U>(value);
        }
        increment_offset(m_tail);
        if (m_tail == m_head) {
            increment_offset(m_head);
        }
    }

    template <typename U>
    void try_push_back(U &&value) noexcept
        requires std::is_nothrow_convertible_v<std::remove_cvref_t<U> *, T *>
    {
        if (empty() || back() != value) {
            push_back(std::forward<U>(value));
        }
    }

    template <typename... Args>
        requires std::constructible_from<T, Args...>
    void emplace_back(Args &&...args) {
        if (m_open_slots != 0) {
            --m_open_slots;
            m_storage.emplace_back(std::forward<Args>(args)...);
        } else {
            dereference_offset(m_tail) = T(std::forward<Args>(args)...);
        }
        increment_offset(m_tail);
        if (m_tail == m_head) {
            increment_offset(m_head);
        }
    }

    void pop_back() noexcept {
        if (!empty()) {
            decrement_offset(m_tail);
        }
    }

    void pop_front() noexcept {
        if (!empty()) {
            increment_offset(m_head);
        }
    }

    reference front() noexcept {
        return dereference_offset(m_head);
    }

    const_reference front() const noexcept {
        return dereference_offset(m_head);
    }

    reference back() noexcept {
        auto b = m_tail;
        decrement_offset(b);
        return dereference_offset(b);
    }

    const_reference back() const noexcept {
        auto b = m_tail;
        decrement_offset(b);
        return dereference_offset(b);
    }

    void clear() noexcept {
        m_storage.clear();
        m_storage.reserve(modulus());
        m_head = m_tail = 0;
        m_open_slots = modulus();
    }

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
            requires std::is_nothrow_convertible_v<std::remove_const_t<CB> *, std::remove_const_t<CB_Other> *> &&
            std::is_nothrow_convertible_v<std::remove_const_t<Value> *, std::remove_const_t<ValueOther> *>
        {
            if (m_cb != other.m_cb) {
                return false;
            }
            return m_cb->equal_offset(m_offset, other.m_offset);
        }

        Value &dereference() const {
            return m_cb->dereference_offset(m_offset);
        }

        template <typename CB_Other, typename ValueOther>
        difference_type distance_to(const iterator_base<CB_Other, ValueOther> &other) const
            requires std::is_nothrow_convertible_v<std::remove_const_t<CB> *, std::remove_const_t<CB_Other> *> &&
            std::is_nothrow_convertible_v<std::remove_const_t<Value> *, std::remove_const_t<ValueOther> *>
        {
            if (m_cb != other.m_cb) {
                return {};
            }
            return m_cb->distance_to_offset(m_offset, other.m_offset);
        }

        void advance(difference_type n) {
            m_cb->advance_offset(m_offset, n);
        }
    };

    template <typename CB, typename Value>
    friend class iterator_base;

    using iterator = iterator_base<base, value_type>;
    using const_iterator = iterator_base<const base, const value_type>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;
    using reverse_iterator = std::reverse_iterator<iterator>;

    auto begin() noexcept {
        return iterator{this, m_head};
    }

    auto end() noexcept {
        return iterator{this, m_tail};
    }

    auto begin() const noexcept {
        return const_iterator{this, m_head};
    }

    auto end() const noexcept {
        return const_iterator{this, m_tail};
    }

    auto cbegin() const noexcept {
        return const_iterator{this, m_head};
    }

    auto cend() const noexcept {
        return const_iterator{this, m_tail};
    }

    auto rbegin() noexcept {
        return reverse_iterator{end()};
    }

    auto rend() noexcept {
        return reverse_iterator{begin()};
    }

    auto rbegin() const noexcept {
        return const_reverse_iterator{end()};
    }

    auto rend() const noexcept {
        return const_reverse_iterator{begin()};
    }

    auto crbegin() const noexcept {
        return const_reverse_iterator{end()};
    }

    auto crend() const noexcept {
        return const_reverse_iterator{begin()};
    }

private:
    template <typename A, typename V>
    static decltype(auto) value_category_as(V &&v) {
        if constexpr (std::is_lvalue_reference_v<A>) {
            return static_cast<std::remove_reference_t<V> &>(v);
        } else {
            return static_cast<std::remove_reference_t<V> &&>(v);
        }
    }

    void increment_offset(difference_type &offset) noexcept {
        ++offset;
        if (offset >= modulus()) {
            offset -= modulus();
        }
    }

    void decrement_offset(difference_type &offset) noexcept {
        --offset;
        if (offset < 0) {
            offset += modulus();
        }
    }

    void advance_offset(difference_type &offset, difference_type n) noexcept {
        offset = (offset + n) % modulus();
        if (offset < 0) {
            offset += modulus();
        }
    }

    reference dereference_offset(difference_type offset) noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        return *(m_storage.data() + offset);
    }

    const_reference dereference_offset(difference_type offset) const noexcept {
        assert(offset >= 0 && offset < modulus() && "offset is out of range");
        return *(m_storage.data() + offset);
    }

    difference_type distance_to_offset(difference_type a, difference_type b) const noexcept {
        auto na = a % modulus();
        if (na < 0) {
            na += modulus();
        }
        if (na < m_head) {
            na += modulus();
        }
        auto nb = b % modulus();
        if (nb < 0) {
            nb += modulus();
        }
        if (nb < m_head) {
            nb += modulus();
        }
        return nb - na;
    }

    static bool equal_offset(difference_type a, difference_type b) noexcept {
        return a == b;
    }

    container_base m_storage;
    difference_type m_head{0};
    difference_type m_tail{0};
    difference_type m_open_slots;
    [[no_unique_address]] std::conditional_t<N == std::dynamic_extent, difference_type, std::monostate> m_modulus;
};

} // namespace cartesi

#endif // CIRCULAR_BUFFER_H
