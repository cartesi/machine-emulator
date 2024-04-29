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

#include "jsonrpc-virtual-machine.h"

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "asio-config.h" // must be included before any ASIO header
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#pragma GCC diagnostic pop

#include <boost/type_index.hpp>

#include "base64.h"
#include "htif.h"
#include "json-util.h"
#include "jsonrpc-mgr.h"

using namespace std::string_literals;
using json = nlohmann::json;
using hash_type = cartesi::machine_merkle_tree::hash_type;

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
using tcp = asio::ip::tcp;      // from <boost/asio/ip/tcp.hpp>

template <typename... Ts, size_t... Is>
std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params, std::index_sequence<Is...>) {
    json array = json::array();
    ((array.push_back(json(std::get<Is>(params)))), ...);
    const json j = {{"jsonrpc", "2.0"}, {"method", method}, {"id", 0}, {"params", std::move(array)}};
    return j.dump();
}

template <typename... Ts>
std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params) {
    return jsonrpc_post_data(method, params, std::make_index_sequence<sizeof...(Ts)>{});
}

// Parses an endpoint from an address string in the format "<ip>:<port>"
static asio::ip::tcp::endpoint parse_endpoint(const std::string &address) {
    try {
        const auto colon_pos = address.find_first_of(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("missing port number"s);
        }
        const std::string host = address.substr(0, colon_pos);
        const int port = std::stoi(address.substr(colon_pos + 1));
        if (port <= 0 || port >= 65536) {
            throw std::runtime_error("invalid port number"s);
        }
        return {asio::ip::address::from_string(host), static_cast<uint16_t>(port)};
    } catch (std::exception &e) {
        throw std::runtime_error("failed to parse endpoint from address \""s + address + "\": "s + e.what());
    }
}

static std::string json_post(beast::tcp_stream &stream, const std::string &remote_address, const std::string &post_data,
    bool keep_alive) {
    // Determine remote endpoint from remote address
    const asio::ip::tcp::endpoint remote_endpoint = parse_endpoint(remote_address);

    // Close current stream socket when the remote endpoint is different
    if (stream.socket().is_open()) {
        beast::error_code ec;
        const auto socket_remote_endpoint = stream.socket().remote_endpoint(ec);
        if (ec || socket_remote_endpoint != remote_endpoint) {
            // We can silently ignore socket shutdown/close errors from previous connections
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            stream.socket().close(ec);
        }
    }

    // Try to reuse an alive connection to the same endpoint, otherwise connect it
    if (!stream.socket().is_open()) {
        // Connect
        while (true) {
            beast::error_code ec;
            stream.connect(remote_endpoint, ec);
            if (!ec) { // Success
                break;
            } else if (ec == asio::error::interrupted) {
                // Retry the operation during interrupts (SIGINT/SIGTERM),
                // otherwise we may leave dead zombies processes during fork requests.
            } else { // Unexpected error
                throw beast::system_error(ec);
            }
        }

        // Disable Nagle's algorithm to minimize TCP connection latency
        const boost::asio::ip::tcp::no_delay no_delay_option(true);
        stream.socket().set_option(no_delay_option);

        // Minimize socket close time by setting the linger time to 0.
        // On MacOS, it avoids accumulating socket in TIME_WAIT state, after rapid successive requests,
        // which can consume all available ports.
        // It is safe to do this because it is the client who decides to close the connection,
        // after all data is received.
        const boost::asio::socket_base::linger linger_option(true, 0);
        stream.socket().set_option(linger_option);

        // Enable keep alive TCP option for keep alive HTTP connection
        if (keep_alive) {
            const boost::asio::socket_base::keep_alive keep_alive_option(true);
            stream.socket().set_option(keep_alive_option);
        }
    }

    try {
        // Set up a HTTP request message
        http::request<http::string_body> req;
        req.method(http::verb::post); // POST
        req.version(11);              // Only HTTP 1.1 support keep alive connections
        req.target("/");
        req.keep_alive(keep_alive);
        req.set(http::field::host, remote_endpoint.address().to_string());
        req.set(http::field::content_type, "application/json");
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.body() = post_data;
        req.prepare_payload();

        // Send the HTTP request
        while (true) {
            beast::error_code ec;
            http::write(stream, req, ec);
            if (!ec) { // Success
                break;
            } else if (ec == asio::error::interrupted) {
                // Retry the operation during interrupts (SIGINT/SIGTERM),
                // otherwise we may leave dead zombies processes during fork requests.
            } else { // Unexpected error
                throw beast::system_error(ec);
            }
        }

        // Set up HTTP response parser
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> res_parser;
        res_parser.eager(true);
        res_parser.body_limit(16777216U); // can receive up to 16MB

        // Receive the HTTP response
        while (true) {
            beast::error_code ec;
            http::read(stream, buffer, res_parser, ec);
            if (!ec) { // Success
                break;
            } else if (ec == asio::error::interrupted) {
                // Retry the operation during interrupts (SIGINT/SIGTERM),
                // otherwise we may leave dead zombies processes during fork requests.
            } else { // Unexpected error
                throw beast::system_error(ec);
            }
        }

        http::response<http::string_body> res = res_parser.release();
        if (res.result() != http::status::ok) {
            throw std::runtime_error("http error: reason  "s + std::string(res.reason()) + " (code "s +
                std::to_string(res.result_int()) + ")"s);
        }

        // Gracefully close the socket
        if (!keep_alive || !res.keep_alive()) {
            beast::error_code ec;
            // The response was received so we can silently ignore socket shutdown/close errors
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            stream.socket().close(ec);
        }

        // Return response body
        return std::move(res.body().data());
    } catch (...) {
        // Close stream socket on errors
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        stream.socket().close(ec);
        // Re-throw exception
        throw;
    }
}

template <typename R, typename... Ts>
void jsonrpc_request(beast::tcp_stream &stream, const std::string &remote_address, const std::string &method,
    const std::tuple<Ts...> &tp, R &result, bool keep_alive = true) {
    auto request = jsonrpc_post_data(method, tp);
    json response;
    try {
        response = json::parse(json_post(stream, remote_address, request, keep_alive));
    } catch (std::exception &x) {
        throw std::runtime_error("jsonrpc server error: invalid response ("s + x.what() + ")"s);
    }
    if (!response.contains("jsonrpc")) {
        throw std::runtime_error(R"(jsonrpc server error: missing field "jsonrpc")"s);
    }
    if (!response["jsonrpc"].is_string() || response["jsonrpc"] != "2.0") {
        throw std::runtime_error(R"(jsonrpc server error: invalid field "jsonrpc" (expected "2.0"))"s);
    }
    if (!response.contains("id")) {
        throw std::runtime_error(R"(jsonrpc server error: missing field "id")"s);
    }
    if (!response["id"].is_number() || response["id"] != 0) {
        throw std::runtime_error(R"(jsonrpc server error: invalid field "id" (expected 0))"s);
    }
    if (response.contains("error") && response.contains("result")) {
        throw std::runtime_error(R"(jsonrpc server error: response contains both "error" and "result" fields)"s);
    }
    if (!response.contains("error") && !response.contains("result")) {
        throw std::runtime_error(R"(jsonrpc server error: response contain no "error" or "result" fields)"s);
    }
    if (response.contains("error")) {
        const auto &jerror = response["error"];
        if (!jerror.is_object()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error" field (expected object))"s);
        }
        if (!jerror.contains("code") || !jerror["code"].is_number_integer()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error/code" field (expected integer))"s);
        }
        auto code = jerror["code"].template get<int>();
        if (!jerror.contains("message") || !jerror["message"].is_string()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error/message" field (expected string))"s);
        }
        auto message = jerror["message"].template get<std::string>();
        throw std::runtime_error("jsonrpc error: "s + message + " (code "s + std::to_string(code) + ")"s);
    }
    try {
        cartesi::ju_get_field(response, "result"s, result, ""s);
    } catch (std::exception &x) {
        throw std::runtime_error("jsonrpc server error: "s + x.what());
    }
}

namespace cartesi {

jsonrpc_mgr::jsonrpc_mgr(std::string remote_address) {
    m_address.push_back(std::move(remote_address));
    // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
    struct sigaction sa {};
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, nullptr);
}

jsonrpc_mgr::~jsonrpc_mgr() {
    // Gracefully close any established keep alive connection
    if (m_stream.socket().is_open()) {
        beast::error_code ec;
        m_stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        m_stream.socket().close(ec);
    }
}

beast::tcp_stream &jsonrpc_mgr::get_stream(void) {
    return m_stream;
}

const beast::tcp_stream &jsonrpc_mgr::get_stream(void) const {
    return m_stream;
}

const std::string &jsonrpc_mgr::get_remote_address(void) const {
    if (is_shutdown()) {
        throw std::out_of_range("remote server is shutdown");
    }
    return m_address.back();
}

const std::string &jsonrpc_mgr::get_remote_parent_address(void) const {
    if (!is_forked()) {
        throw std::out_of_range("remote server is not forked");
    }
    return m_address[0];
}

void jsonrpc_mgr::snapshot(void) {
    // If we are forked, discard the pending snapshot
    if (is_forked()) {
        commit();
    }

    // To create a snapshot, we fork a new server as the child and get its remote address
    std::string child_address;
    jsonrpc_request(get_stream(), get_remote_address(), "fork", std::tie(), child_address, false);
    m_address.push_back(std::move(child_address));
}

void jsonrpc_mgr::commit() {
    // If we are not forked, there is no pending snapshot to discard, therefore we are already committed
    if (!is_forked()) {
        return;
    }

    // To commit, we kill the parent server and replace its address with the child's
    try {
        bool result = false;
        jsonrpc_request(get_stream(), get_remote_parent_address(), "shutdown", std::tie(), result, false);
    } catch (std::exception &e) {
        // It's possible that the remote server was killed before the shutdown (e.g SIGTERM was sent),
        // so we silently ignore errors here.
        // If the server still up, the next rebind request will fail anyway with port already in use.
    }

    // Rebind the remote server to continue listening in the original port
    bool result = false;
    jsonrpc_request(get_stream(), get_remote_address(), "rebind", std::tie(m_address[0]), result, false);
    m_address.pop_back();
}

void jsonrpc_mgr::rollback() {
    // If we are not forked, there is no snapshot to rollback to
    if (!is_forked()) {
        throw std::out_of_range("remote server has no pending snapshot to rollback to");
    }

    // To rollback, we kill the child and expose the parent server
    bool result = false;
    jsonrpc_request(get_stream(), get_remote_address(), "shutdown", std::tie(), result, false);
    m_address.pop_back();
}

bool jsonrpc_mgr::is_forked(void) const {
    return m_address.size() > 1;
}

void jsonrpc_mgr::shutdown(void) {
    bool result = false;
    if (is_forked()) {
        jsonrpc_request(get_stream(), get_remote_parent_address(), "shutdown", std::tie(), result, false);
    }
    jsonrpc_request(get_stream(), get_remote_address(), "shutdown", std::tie(), result, false);
    m_address.clear();
}

bool jsonrpc_mgr::is_shutdown(void) const {
    return m_address.empty();
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr) : m_mgr(std::move(mgr)) {}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr, const std::string &directory,
    const machine_runtime_config &runtime) :
    m_mgr(std::move(mgr)) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.machine.directory",
        std::tie(directory, runtime), result);
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr, const machine_config &config,
    const machine_runtime_config &runtime) :
    m_mgr(std::move(mgr)) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.machine.config",
        std::tie(config, runtime), result);
}

jsonrpc_virtual_machine::~jsonrpc_virtual_machine(void) = default;

machine_config jsonrpc_virtual_machine::do_get_initial_config(void) const {
    machine_config result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.get_initial_config", std::tie(), result);
    return result;
}

machine_config jsonrpc_virtual_machine::get_default_config(const jsonrpc_mgr_ptr &mgr) {
    machine_config result;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.get_default_config", std::tie(), result);
    return result;
}

semantic_version jsonrpc_virtual_machine::get_version(const jsonrpc_mgr_ptr &mgr) {
    semantic_version result;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "get_version", std::tie(), result);
    return result;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

void jsonrpc_virtual_machine::shutdown(const jsonrpc_mgr_ptr &mgr) {
    mgr->shutdown();
}

void jsonrpc_virtual_machine::verify_uarch_step_log(const jsonrpc_mgr_ptr &mgr, const access_log &log,
    const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_uarch_step_log",
        std::tie(log, runtime, one_based), result);
}

void jsonrpc_virtual_machine::verify_uarch_step_state_transition(const jsonrpc_mgr_ptr &mgr,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after,
    const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_uarch_step_state_transition",
        std::tie(b64_root_hash_before, log, b64_root_hash_after, runtime, one_based), result);
}

void jsonrpc_virtual_machine::verify_uarch_reset_log(const jsonrpc_mgr_ptr &mgr, const access_log &log,
    const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_uarch_reset_log",
        std::tie(log, runtime, one_based), result);
}

void jsonrpc_virtual_machine::verify_uarch_reset_state_transition(const jsonrpc_mgr_ptr &mgr,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after,
    const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_uarch_reset_state_transition",
        std::tie(b64_root_hash_before, log, b64_root_hash_after, runtime, one_based), result);
}

interpreter_break_reason jsonrpc_virtual_machine::do_run(uint64_t mcycle_end) {
    interpreter_break_reason result = interpreter_break_reason::failed;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.run", std::tie(mcycle_end), result);
    return result;
}

void jsonrpc_virtual_machine::do_store(const std::string &directory) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.store", std::tie(directory), result);
}

uint64_t jsonrpc_virtual_machine::do_read_csr(csr r) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_csr", std::tie(r), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_csr(csr w, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_csr", std::tie(w, val), result);
}

uint64_t jsonrpc_virtual_machine::get_csr_address(const jsonrpc_mgr_ptr &mgr, csr w) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.get_csr_address", std::tie(w), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_x(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_x", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_x(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_x", std::tie(i, val), result);
}

uint64_t jsonrpc_virtual_machine::get_x_address(const jsonrpc_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.get_x_address", std::tie(i), result);
    return result;
}

std::string jsonrpc_virtual_machine::fork(const jsonrpc_mgr_ptr &mgr) {
    std::string result;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "fork", std::tie(), result, false);
    return result;
}

void jsonrpc_virtual_machine::rebind(const jsonrpc_mgr_ptr &mgr, const std::string &address) {
    bool result = false;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "rebind", std::tie(address), result, false);
}

uint64_t jsonrpc_virtual_machine::do_read_f(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_f", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_f(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_f", std::tie(i, val), result);
}

uint64_t jsonrpc_virtual_machine::get_f_address(const jsonrpc_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.get_f_address", std::tie(i), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::get_uarch_x_address(const jsonrpc_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.get_uarch_x_address", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_memory", std::tie(address, length),
        result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, size_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_memory", std::tie(address, b64),
        result);
}

void jsonrpc_virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_virtual_memory",
        std::tie(address, length), result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_virtual_memory",
        std::tie(address, b64), result);
}

uint64_t jsonrpc_virtual_machine::do_translate_virtual_address(uint64_t vaddr) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.translate_virtual_address",
        std::tie(vaddr), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_pc(void) const {
    return read_csr(csr::pc);
}

void jsonrpc_virtual_machine::do_write_pc(uint64_t val) {
    write_csr(csr::pc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_fcsr(void) const {
    return read_csr(csr::fcsr);
}

void jsonrpc_virtual_machine::do_write_fcsr(uint64_t val) {
    write_csr(csr::fcsr, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mvendorid(void) const {
    return read_csr(csr::mvendorid);
}

uint64_t jsonrpc_virtual_machine::do_read_marchid(void) const {
    return read_csr(csr::marchid);
}

uint64_t jsonrpc_virtual_machine::do_read_mimpid(void) const {
    return read_csr(csr::mimpid);
}

uint64_t jsonrpc_virtual_machine::do_read_mcycle(void) const {
    return read_csr(csr::mcycle);
}

void jsonrpc_virtual_machine::do_write_mcycle(uint64_t val) {
    write_csr(csr::mcycle, val);
}

uint64_t jsonrpc_virtual_machine::do_read_icycleinstret(void) const {
    return read_csr(csr::icycleinstret);
}

void jsonrpc_virtual_machine::do_write_icycleinstret(uint64_t val) {
    write_csr(csr::icycleinstret, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mstatus(void) const {
    return read_csr(csr::mstatus);
}

void jsonrpc_virtual_machine::do_write_mstatus(uint64_t val) {
    write_csr(csr::mstatus, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mtvec(void) const {
    return read_csr(csr::mtvec);
}

void jsonrpc_virtual_machine::do_write_mtvec(uint64_t val) {
    write_csr(csr::mtvec, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mscratch(void) const {
    return read_csr(csr::mscratch);
}

void jsonrpc_virtual_machine::do_write_mscratch(uint64_t val) {
    write_csr(csr::mscratch, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mepc(void) const {
    return read_csr(csr::mepc);
}

void jsonrpc_virtual_machine::do_write_mepc(uint64_t val) {
    write_csr(csr::mepc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mcause(void) const {
    return read_csr(csr::mcause);
}

void jsonrpc_virtual_machine::do_write_mcause(uint64_t val) {
    write_csr(csr::mcause, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mtval(void) const {
    return read_csr(csr::mtval);
}

void jsonrpc_virtual_machine::do_write_mtval(uint64_t val) {
    write_csr(csr::mtval, val);
}

uint64_t jsonrpc_virtual_machine::do_read_misa(void) const {
    return read_csr(csr::misa);
}

void jsonrpc_virtual_machine::do_write_misa(uint64_t val) {
    write_csr(csr::misa, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mie(void) const {
    return read_csr(csr::mie);
}

void jsonrpc_virtual_machine::do_write_mie(uint64_t val) {
    write_csr(csr::mie, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mip(void) const {
    return read_csr(csr::mip);
}

void jsonrpc_virtual_machine::do_write_mip(uint64_t val) {
    write_csr(csr::mip, val);
}

uint64_t jsonrpc_virtual_machine::do_read_medeleg(void) const {
    return read_csr(csr::medeleg);
}

void jsonrpc_virtual_machine::do_write_medeleg(uint64_t val) {
    write_csr(csr::medeleg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mideleg(void) const {
    return read_csr(csr::mideleg);
}

void jsonrpc_virtual_machine::do_write_mideleg(uint64_t val) {
    write_csr(csr::mideleg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_mcounteren(void) const {
    return read_csr(csr::mcounteren);
}

void jsonrpc_virtual_machine::do_write_mcounteren(uint64_t val) {
    write_csr(csr::mcounteren, val);
}

uint64_t jsonrpc_virtual_machine::do_read_menvcfg(void) const {
    return read_csr(csr::menvcfg);
}

void jsonrpc_virtual_machine::do_write_menvcfg(uint64_t val) {
    write_csr(csr::menvcfg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_stvec(void) const {
    return read_csr(csr::stvec);
}

void jsonrpc_virtual_machine::do_write_stvec(uint64_t val) {
    write_csr(csr::stvec, val);
}

uint64_t jsonrpc_virtual_machine::do_read_sscratch(void) const {
    return read_csr(csr::sscratch);
}

void jsonrpc_virtual_machine::do_write_sscratch(uint64_t val) {
    write_csr(csr::sscratch, val);
}

uint64_t jsonrpc_virtual_machine::do_read_sepc(void) const {
    return read_csr(csr::sepc);
}

void jsonrpc_virtual_machine::do_write_sepc(uint64_t val) {
    write_csr(csr::sepc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_scause(void) const {
    return read_csr(csr::scause);
}

void jsonrpc_virtual_machine::do_write_scause(uint64_t val) {
    write_csr(csr::scause, val);
}

uint64_t jsonrpc_virtual_machine::do_read_stval(void) const {
    return read_csr(csr::stval);
}

void jsonrpc_virtual_machine::do_write_stval(uint64_t val) {
    write_csr(csr::stval, val);
}

uint64_t jsonrpc_virtual_machine::do_read_satp(void) const {
    return read_csr(csr::satp);
}

void jsonrpc_virtual_machine::do_write_satp(uint64_t val) {
    write_csr(csr::satp, val);
}

uint64_t jsonrpc_virtual_machine::do_read_scounteren(void) const {
    return read_csr(csr::scounteren);
}

void jsonrpc_virtual_machine::do_write_scounteren(uint64_t val) {
    write_csr(csr::scounteren, val);
}

uint64_t jsonrpc_virtual_machine::do_read_senvcfg(void) const {
    return read_csr(csr::senvcfg);
}

void jsonrpc_virtual_machine::do_write_senvcfg(uint64_t val) {
    write_csr(csr::senvcfg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_ilrsc(void) const {
    return read_csr(csr::ilrsc);
}

void jsonrpc_virtual_machine::do_write_ilrsc(uint64_t val) {
    write_csr(csr::ilrsc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_iflags(void) const {
    return read_csr(csr::iflags);
}

bool jsonrpc_virtual_machine::do_read_iflags_H(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_iflags_H", std::tie(), result);
    return result;
}

bool jsonrpc_virtual_machine::do_read_iflags_Y(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_iflags_Y", std::tie(), result);
    return result;
}

bool jsonrpc_virtual_machine::do_read_iflags_X(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_iflags_X", std::tie(), result);
    return result;
}

void jsonrpc_virtual_machine::do_set_iflags_H(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.set_iflags_H", std::tie(), result);
}

void jsonrpc_virtual_machine::do_set_iflags_Y(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.set_iflags_Y", std::tie(), result);
}

void jsonrpc_virtual_machine::do_set_iflags_X(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.set_iflags_X", std::tie(), result);
}

void jsonrpc_virtual_machine::do_reset_iflags_Y(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.reset_iflags_Y", std::tie(), result);
}

void jsonrpc_virtual_machine::do_reset_iflags_X(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.reset_iflags_X", std::tie(), result);
}

uint64_t jsonrpc_virtual_machine::do_read_iunrep(void) const {
    return read_csr(csr::iunrep);
}

void jsonrpc_virtual_machine::do_write_iunrep(uint64_t val) {
    write_csr(csr::iunrep, val);
}

bool jsonrpc_virtual_machine::do_read_uarch_halt_flag(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_uarch_halt_flag", std::tie(),
        result);
    return result;
}

void jsonrpc_virtual_machine::do_set_uarch_halt_flag(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.set_uarch_halt_flag", std::tie(),
        result);
}

void jsonrpc_virtual_machine::do_reset_uarch(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.reset_uarch", std::tie(), result);
}

access_log jsonrpc_virtual_machine::do_log_uarch_reset(const access_log::type &log_type, bool one_based) {
    not_default_constructible<access_log> result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.log_uarch_reset",
        std::tie(log_type, one_based), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_write_iflags(uint64_t val) {
    write_csr(csr::iflags, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htif_tohost(void) const {
    return read_csr(csr::htif_tohost);
}

uint64_t jsonrpc_virtual_machine::do_read_htif_tohost_dev(void) const {
    return HTIF_DEV_FIELD(read_htif_tohost());
}

uint64_t jsonrpc_virtual_machine::do_read_htif_tohost_cmd(void) const {
    return HTIF_CMD_FIELD(read_htif_tohost());
}

uint64_t jsonrpc_virtual_machine::do_read_htif_tohost_data(void) const {
    return HTIF_DATA_FIELD(read_htif_tohost());
}

void jsonrpc_virtual_machine::do_write_htif_tohost(uint64_t val) {
    write_csr(csr::htif_tohost, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htif_fromhost(void) const {
    return read_csr(csr::htif_fromhost);
}

void jsonrpc_virtual_machine::do_write_htif_fromhost(uint64_t val) {
    write_csr(csr::htif_fromhost, val);
}

void jsonrpc_virtual_machine::do_write_htif_fromhost_data(uint64_t val) {
    write_htif_fromhost(HTIF_REPLACE_DATA(read_htif_fromhost(), val));
}

uint64_t jsonrpc_virtual_machine::do_read_htif_ihalt(void) const {
    return read_csr(csr::htif_ihalt);
}

void jsonrpc_virtual_machine::do_write_htif_ihalt(uint64_t val) {
    write_csr(csr::htif_ihalt, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htif_iconsole(void) const {
    return read_csr(csr::htif_iconsole);
}

void jsonrpc_virtual_machine::do_write_htif_iconsole(uint64_t val) {
    write_csr(csr::htif_iconsole, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htif_iyield(void) const {
    return read_csr(csr::htif_iyield);
}

void jsonrpc_virtual_machine::do_write_htif_iyield(uint64_t val) {
    write_csr(csr::htif_iyield, val);
}

uint64_t jsonrpc_virtual_machine::do_read_clint_mtimecmp(void) const {
    return read_csr(csr::clint_mtimecmp);
}

void jsonrpc_virtual_machine::do_write_clint_mtimecmp(uint64_t val) {
    write_csr(csr::clint_mtimecmp, val);
}

uint64_t jsonrpc_virtual_machine::do_read_plic_girqpend(void) const {
    return read_csr(csr::plic_girqpend);
}

void jsonrpc_virtual_machine::do_write_plic_girqpend(uint64_t val) {
    write_csr(csr::plic_girqpend, val);
}

uint64_t jsonrpc_virtual_machine::do_read_plic_girqsrvd(void) const {
    return read_csr(csr::plic_girqsrvd);
}

void jsonrpc_virtual_machine::do_write_plic_girqsrvd(uint64_t val) {
    write_csr(csr::plic_girqsrvd, val);
}

void jsonrpc_virtual_machine::do_get_root_hash(hash_type &hash) const {
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.get_root_hash", std::tie(), hash);
}

machine_merkle_tree::proof_type jsonrpc_virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    not_default_constructible<machine_merkle_tree::proof_type> result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.get_proof", std::tie(address, log2_size),
        result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.replace_memory_range",
        std::tie(new_range), result);
}

access_log jsonrpc_virtual_machine::do_log_uarch_step(const access_log::type &log_type, bool one_based) {
    not_default_constructible<access_log> result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.log_uarch_step",
        std::tie(log_type, one_based), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_destroy() {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.destroy", std::tie(), result, false);
}

bool jsonrpc_virtual_machine::do_verify_dirty_page_maps(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.verify_dirty_page_maps", std::tie(),
        result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_word(uint64_t address) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_word", std::tie(address), result);
    return result;
}

bool jsonrpc_virtual_machine::do_verify_merkle_tree(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.verify_merkle_tree", std::tie(), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_uarch_x(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.read_uarch_x", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_uarch_x(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.write_uarch_x", std::tie(i, val),
        result);
}

uint64_t jsonrpc_virtual_machine::do_read_uarch_pc(void) const {
    return read_csr(csr::uarch_pc);
}

void jsonrpc_virtual_machine::do_write_uarch_pc(uint64_t val) {
    write_csr(csr::uarch_pc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_uarch_cycle(void) const {
    return read_csr(csr::uarch_cycle);
}

void jsonrpc_virtual_machine::do_write_uarch_cycle(uint64_t val) {
    write_csr(csr::uarch_cycle, val);
}

void jsonrpc_virtual_machine::do_snapshot(void) {
    m_mgr->snapshot();
}

void jsonrpc_virtual_machine::do_commit(void) {
    m_mgr->commit();
}

void jsonrpc_virtual_machine::do_rollback(void) {
    m_mgr->rollback();
}

uarch_interpreter_break_reason jsonrpc_virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    uarch_interpreter_break_reason result = uarch_interpreter_break_reason::reached_target_cycle;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.run_uarch", std::tie(uarch_cycle_end),
        result);
    return result;
}

machine_memory_range_descrs jsonrpc_virtual_machine::do_get_memory_ranges(void) const {
    machine_memory_range_descrs result;
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.get_memory_ranges", std::tie(), result);
    return result;
}

void jsonrpc_virtual_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.send_cmio_response",
        std::tie(reason, b64), result);
}

access_log jsonrpc_virtual_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length,
    const access_log::type &log_type, bool one_based) {
    not_default_constructible<access_log> result;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_mgr->get_stream(), m_mgr->get_remote_address(), "machine.log_send_cmio_response",
        std::tie(reason, b64, log_type, one_based), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::verify_send_cmio_response_log(const jsonrpc_mgr_ptr &mgr, uint16_t reason,
    const unsigned char *data, size_t length, const access_log &log, const machine_runtime_config &runtime,
    bool one_based) {
    bool result = false;
    std::string b64_data = cartesi::encode_base64(data, length);
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_send_cmio_response_log",
        std::tie(reason, b64_data, log, runtime, one_based), result);
}

void jsonrpc_virtual_machine::verify_send_cmio_response_state_transition(const jsonrpc_mgr_ptr &mgr, uint16_t reason,
    const unsigned char *data, size_t length, const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after, const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    std::string b64_data = cartesi::encode_base64(data, length);
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(mgr->get_stream(), mgr->get_remote_address(), "machine.verify_send_cmio_response_state_transition",
        std::tie(reason, b64_data, b64_root_hash_before, log, b64_root_hash_after, runtime, one_based), result);
}

#pragma GCC diagnostic pop

} // namespace cartesi
