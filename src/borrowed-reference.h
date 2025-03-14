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

#ifndef BORROWED_REFERENCE_H
#define BORROWED_REFERENCE_H

#include <functional>
#include <utility>

/// \file
/// \brief Circular buffer container

namespace cartesi {

template <typename T>
class borrowed_reference {
public:
    explicit borrowed_reference(T &ref) : m_ptr(&ref) {}

    borrowed_reference(const borrowed_reference &) = delete;
    borrowed_reference &operator=(const borrowed_reference &) = delete;

    borrowed_reference(borrowed_reference &&other) noexcept : m_ptr(other.m_ptr) {
        other.invalidate();
    }

    borrowed_reference &operator=(borrowed_reference &&other) noexcept {
        if (this != &other) {
            m_ptr = other.m_ptr;
            other.invalidate();
        }
        return *this;
    }

    constexpr operator T &() const noexcept {
        return *m_ptr;
    }

    constexpr T &get() const noexcept {
        return *m_ptr;
    }

private:
    T *m_ptr;

    void invalidate() {
        m_ptr = nullptr;
    }
};

template <typename T>
static inline auto make_borrowed_reference(T &ref) {
    return borrowed_reference<T>(ref);
}

} // namespace cartesi

#endif // BORROWED_REFERENCE_H
