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

#ifndef JSONRPC_MG_MGR_H
#define JSONRPC_MG_MGR_H

#include <boost/container/static_vector.hpp>
#include <mongoose.h>
#include <string>

namespace cartesi {

class jsonrpc_mg_mgr final {

    boost::container::static_vector<std::string, 2> m_address{};
    struct mg_mgr m_mgr {}; // unnecessary initialization to silince clang-tidy

public:
    explicit jsonrpc_mg_mgr(std::string remote_address);
    jsonrpc_mg_mgr(const jsonrpc_mg_mgr &other) = delete;
    jsonrpc_mg_mgr(jsonrpc_mg_mgr &&other) noexcept = delete;
    jsonrpc_mg_mgr &operator=(const jsonrpc_mg_mgr &other) = delete;
    jsonrpc_mg_mgr &operator=(jsonrpc_mg_mgr &&other) noexcept = delete;
    ~jsonrpc_mg_mgr();
    bool is_forked(void) const;
    bool is_shutdown(void) const;
    struct mg_mgr &get_mgr(void);
    const struct mg_mgr &get_mgr(void) const;
    const std::string &get_remote_address(void) const;
    const std::string &get_remote_parent_address(void) const;
    void snapshot(void);
    void commit(void);
    void rollback(void);
    void shutdown(void);
};

} // namespace cartesi

#endif
