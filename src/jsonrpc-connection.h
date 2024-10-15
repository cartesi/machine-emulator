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

#ifndef JSONRPC_CONNECTION_H
#define JSONRPC_CONNECTION_H

#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "asio-config.h" // must be included before any ASIO header
#include <boost/asio/io_context.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/container/static_vector.hpp>
#pragma GCC diagnostic pop

#include "semantic-version.h"

namespace cartesi {

/// Result of a fork
struct fork_result final {
    std::string address;
    uint32_t pid{};
};

class jsonrpc_connection final {
public:
    jsonrpc_connection(std::string remote_address, bool detach_server);
    jsonrpc_connection(const jsonrpc_connection &other) = delete;
    jsonrpc_connection(jsonrpc_connection &&other) noexcept = delete;
    jsonrpc_connection &operator=(const jsonrpc_connection &other) = delete;
    jsonrpc_connection &operator=(jsonrpc_connection &&other) noexcept = delete;
    ~jsonrpc_connection();

    bool is_snapshot() const;
    bool is_shutdown() const;
    boost::beast::tcp_stream &get_stream();
    const boost::beast::tcp_stream &get_stream() const;
    const std::string &get_remote_address() const;
    const std::string &get_remote_parent_address() const;
    void snapshot();
    void commit();
    void rollback();

    void shutdown_server();
    fork_result fork_server();
    std::string rebind_server(const std::string &address);
    semantic_version get_server_version();

    boost::asio::io_context m_ioc{1};         // The io_context is required for all I/O
    boost::beast::tcp_stream m_stream{m_ioc}; // TCP stream for keep alive connections
    boost::container::static_vector<std::string, 2> m_address;
    bool m_detach_server{};
};

} // namespace cartesi

#endif
