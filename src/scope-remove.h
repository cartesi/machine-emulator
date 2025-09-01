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

#ifndef SCOPE_REMOVE_H
#define SCOPE_REMOVE_H

#include <ranges>
#include <string>
#include <vector>

#include "os-filesystem.h"

namespace cartesi {

/// \brief A class that manages the removal of files and directories when it goes out of scope.
class scope_remove {
public:
    /// \brief Calls the exit function when the scope is exited when active, then destroys the scope_remove.
    ~scope_remove() {
        remove_all();
    }

    scope_remove() = default;
    scope_remove(const scope_remove &) = delete;
    scope_remove &operator=(const scope_remove &) = delete;
    scope_remove(scope_remove &&) = delete;
    scope_remove &operator=(scope_remove &&) = delete;

    /// \brief Adds a file to be removed by the scope_remove.
    /// \param filename The name of the file to add.
    void add_file(const std::string &filename) {
        m_filenames.emplace_back(filename);
    }

    /// \brief Adds a directory to be removed by the scope_remove.
    /// \param dirname The name of the directory to add.
    void add_directory(const std::string &dirname) {
        m_dirnames.emplace_back(dirname);
    }

    /// \brief Removes all files and directories added to the scope_remove.
    void remove_all() noexcept {
        // Remove files in reverse order
        for (const auto &filename : m_filenames | std::views::reverse) {
            try {
                os::remove_file(filename);
            } catch (...) { // NOLINT(bugprone-empty-catch)
                // Silent ignore cleanup errors
            }
        }
        m_filenames.clear();

        // Remove directories in reverse order to avoid issues with nested directories
        for (const auto &dirname : m_dirnames | std::views::reverse) {
            try {
                os::remove_directory(dirname);
            } catch (...) { // NOLINT(bugprone-empty-catch)
                // Silent ignore cleanup errors
            }
        }
        m_dirnames.clear();
    }

    /// \brief Retain all files and directories added to the scope_remove, keeping them stored.
    void retain_all() noexcept {
        m_filenames.clear();
        m_dirnames.clear();
    }

private:
    std::vector<std::string> m_filenames; ///< List of files to be removed
    std::vector<std::string> m_dirnames;  ///< List of directories to be removed
};

} // namespace cartesi

#endif
