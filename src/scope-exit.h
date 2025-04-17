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

#ifndef SCOPE_EXIT_H
#define SCOPE_EXIT_H

//??E An official scoped_exit utility is supposed to become part of C++ in the future,
//    when that happens, we could potentially replace this implementation.

#include <exception>
#include <utility>

namespace cartesi {

template <typename F>
class scope_exit {
public:
    explicit scope_exit(F &&f) noexcept : m_func(std::move(f)) {}

    /// \brief Calls the exit function when the scope is exited when active, then destroys the scope_exit.
    ~scope_exit() {
        exit();
    }

    scope_exit(const scope_exit &) = delete;
    scope_exit &operator=(const scope_exit &) = delete;
    scope_exit(scope_exit &&) = delete;
    scope_exit &operator=(scope_exit &&) = delete;

    /// \brief Invokes the exit function if active and then becomes inactive.
    void exit() {
        if (m_active) {
            m_active = false;
            m_func();
        }
    }

    /// \brief Makes the scope_exit inactive.
    void release() noexcept {
        m_active = false;
    }

private:
    F m_func;
    bool m_active{true};
};

template <typename F>
scope_exit<F> make_scope_exit(F &&f) {
    return scope_exit<F>(std::forward<F>(f));
}

template <typename F>
class scope_fail {
public:
    explicit scope_fail(F &&f) noexcept : m_func(std::move(f)), m_uncaught_on_entry(std::uncaught_exceptions()) {}

    /// \brief Calls the fail function when the scope is exited after an exception is thrown while active,
    /// then destroys the scope_fail.
    ~scope_fail() noexcept {
        if (m_active && std::uncaught_exceptions() > m_uncaught_on_entry) {
            m_func();
        }
    }

    scope_fail(const scope_fail &) = delete;
    scope_fail &operator=(const scope_fail &) = delete;
    scope_fail(scope_fail &&) = delete;
    scope_fail &operator=(scope_fail &&) = delete;

    /// \brief Makes the scope_fail inactive
    void release() noexcept {
        m_active = false;
    }

private:
    F m_func;
    int m_uncaught_on_entry;
    bool m_active{true};
};

template <typename F>
scope_fail<F> make_scope_fail(F &&f) {
    return scope_fail<F>(std::forward<F>(f));
}

}; // namespace cartesi

#endif
