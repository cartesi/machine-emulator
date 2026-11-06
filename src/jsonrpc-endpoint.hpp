// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef JSONRPC_ENDPOINT_HPP
#define JSONRPC_ENDPOINT_HPP

#include <charconv>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace cartesi {

/// \brief Converts an address of the form <ipv4-address>:<port> or [<ipv6-address>]:<port> to an endpoint
/// \details Port 0 is accepted, so a server can ask for an ephemeral port.
inline boost::asio::ip::tcp::endpoint address_to_endpoint(const std::string &address) {
    const auto invalid = [&address](const std::string &reason) {
        return std::invalid_argument{"invalid endpoint address \"" + address + "\" (" + reason + ")"};
    };
    const auto port_separator = address.rfind(':');
    if (port_separator == std::string::npos || address.ends_with(']')) {
        throw invalid("missing port");
    }
    std::string_view host{address.data(), port_separator};
    if (host.starts_with('[') && host.ends_with(']')) {
        host = host.substr(1, host.size() - 2);
    } else if (host.contains(':')) {
        throw invalid("IPv6 address must be in brackets");
    }
    const auto *const port_begin = address.c_str() + port_separator + 1;
    const auto *const port_end = address.c_str() + address.size();
    uint16_t port = 0;
    const auto [parsed_end, error] = std::from_chars(port_begin, port_end, port);
    if (port_begin == port_end || error != std::errc{} || parsed_end != port_end) {
        throw invalid("invalid port");
    }
    boost::system::error_code ec;
    const auto ip = boost::asio::ip::make_address(std::string{host}, ec);
    if (ec) {
        throw invalid("invalid IP address");
    }
    return {ip, port};
}

/// \brief Converts an endpoint to an address that address_to_endpoint() accepts
inline std::string endpoint_to_string(const boost::asio::ip::tcp::endpoint &endpoint) {
    std::ostringstream ss;
    ss << endpoint;
    return ss.str();
}

} // namespace cartesi

#endif // JSONRPC_ENDPOINT_HPP
