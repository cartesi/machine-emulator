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

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <string>

#include <mongoose.h>
#include <nlohmann/json.hpp>

#include "jsonrpc-mg-mgr.h"
#include "jsonrpc-virtual-machine.h"

#include "base64.h"
#include "json-util.h"

using namespace std::string_literals;
using json = nlohmann::json;

using hash_type = cartesi::machine_merkle_tree::hash_type;

#include <boost/type_index.hpp>

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

struct http_request_data {
    const std::string &url;
    const std::string &post_data;
    std::string status_code;
    std::string reason_phrase;
    std::string entity_body;
    bool done;
};

// Print HTTP response and signal that we're done
static void json_post_fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    http_request_data *data = static_cast<http_request_data *>(fn_data);
    if (ev == MG_EV_CONNECT) {
        const struct mg_str host = mg_url_host(data->url.c_str());
        mg_printf(c,
            "POST %s HTTP/1.0\r\n"
            "Host: %.*s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            mg_url_uri(data->url.c_str()), static_cast<int>(host.len), host.ptr, data->post_data.size());
        mg_send(c, data->post_data.data(), data->post_data.size());
    } else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = static_cast<struct mg_http_message *>(ev_data);
        data->entity_body = std::string_view(hm->body.ptr, hm->body.len);
        data->status_code = std::string_view(hm->uri.ptr, hm->uri.len);
        data->reason_phrase = std::string_view(hm->proto.ptr, hm->proto.len);
        c->is_closing = 1;
        data->done = true;
    } else if (ev == MG_EV_ERROR) {
        data->entity_body.clear();
        data->status_code = "503";
        data->reason_phrase = static_cast<char *>(ev_data);
        data->done = true;
    } else if (ev == MG_EV_CLOSE && !data->done) {
        data->entity_body.clear();
        data->status_code.clear();
        data->reason_phrase = "connection closed";
        data->done = true;
    }
}

static std::string json_post(struct mg_mgr &mgr, const std::string &url, const std::string &post_data) {
    http_request_data data{url, post_data, "", "", "", false};
    if (!mg_http_connect(&mgr, url.c_str(), json_post_fn, &data)) {
        throw std::runtime_error("connection to '"s + url + "' failed"s);
    }
    while (!data.done) {
        mg_mgr_poll(&mgr, 1000);
    }
    if (data.status_code.empty()) {
        throw std::runtime_error("http error: "s + data.reason_phrase);
    }
    if (data.status_code != "200") {
        throw std::runtime_error("http error: "s + data.reason_phrase + " (code "s + data.status_code + ")"s);
    }
    return std::move(data.entity_body);
}

template <typename R, typename... Ts>
void jsonrpc_request(struct mg_mgr &mgr, const std::string &url, const std::string &method, const std::tuple<Ts...> &tp,
    R &result) {
    auto request = jsonrpc_post_data(method, tp);
    json response;
    try {
        response = json::parse(json_post(mgr, url, request));
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
        throw std::runtime_error(R"(jsonrpc server error: reponse contains both "error" and "result" fields)"s);
    }
    if (!response.contains("error") && !response.contains("result")) {
        throw std::runtime_error(R"(jsonrpc server error: reponse contain no "error" or "result" fields)"s);
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

jsonrpc_mg_mgr::jsonrpc_mg_mgr(std::string remote_address) {
    memset(&m_mgr, 0, sizeof(m_mgr));
    mg_mgr_init(&m_mgr);
    m_address.push_back(std::move(remote_address));
    // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
    struct sigaction sa {};
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, nullptr);
}

jsonrpc_mg_mgr::~jsonrpc_mg_mgr() {
    mg_mgr_free(&m_mgr);
}

struct mg_mgr &jsonrpc_mg_mgr::get_mgr(void) {
    return m_mgr;
}

const struct mg_mgr &jsonrpc_mg_mgr::get_mgr(void) const {
    return m_mgr;
}

const std::string &jsonrpc_mg_mgr::get_remote_address(void) const {
    if (is_shutdown()) {
        throw std::out_of_range("remote server is shutdown");
    }
    return m_address.back();
}

const std::string &jsonrpc_mg_mgr::get_remote_parent_address(void) const {
    if (!is_forked()) {
        throw std::out_of_range("remote server is not forked");
    }
    return m_address[0];
}

void jsonrpc_mg_mgr::snapshot(void) {
    // Simulate the snapshot operation as in the gRPC server
    // If we are forked, we kill the parent server and replace its address with the child's,
    // then we behave as if we were not forked
    if (is_forked()) {
        bool result = false;
        jsonrpc_request(get_mgr(), get_remote_parent_address(), "shutdown", std::tie(), result);
        std::swap(m_address[0], m_address[1]);
        m_address.pop_back();
    }
    // If we are not forked, we fork a new server as the child and get its remote address
    std::string child_address;
    jsonrpc_request(get_mgr(), get_remote_address(), "fork", std::tie(), child_address);
    m_address.push_back(std::move(child_address));
}

void jsonrpc_mg_mgr::rollback() {
    // Simulate the rollback operation as in the gRPC server
    // If we are not forked, we throw an exception
    if (!is_forked()) {
        throw std::out_of_range("remote server is not forked");
    }
    // If we are forked, we kill the child and expose the parent server
    bool result = false;
    jsonrpc_request(get_mgr(), get_remote_address(), "shutdown", std::tie(), result);
    m_address.pop_back();
}

bool jsonrpc_mg_mgr::is_forked(void) const {
    return m_address.size() > 1;
}

void jsonrpc_mg_mgr::shutdown(void) {
    bool result = false;
    if (is_forked()) {
        jsonrpc_request(get_mgr(), get_remote_parent_address(), "shutdown", std::tie(), result);
    }
    jsonrpc_request(get_mgr(), get_remote_address(), "shutdown", std::tie(), result);
    m_address.clear();
}

bool jsonrpc_mg_mgr::is_shutdown(void) const {
    return m_address.empty();
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mg_mgr_ptr mgr) : m_mgr(std::move(mgr)) {}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mg_mgr_ptr mgr, const std::string &directory,
    const machine_runtime_config &runtime) :
    m_mgr(std::move(mgr)) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.machine.directory",
        std::tie(directory, runtime), result);
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(jsonrpc_mg_mgr_ptr mgr, const machine_config &config,
    const machine_runtime_config &runtime) :
    m_mgr(std::move(mgr)) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.machine.config", std::tie(config, runtime),
        result);
}

jsonrpc_virtual_machine::~jsonrpc_virtual_machine(void) = default;

machine_config jsonrpc_virtual_machine::do_get_initial_config(void) const {
    machine_config result;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.get_initial_config", std::tie(), result);
    return result;
}

machine_config jsonrpc_virtual_machine::get_default_config(const jsonrpc_mg_mgr_ptr &mgr) {
    machine_config result;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.get_default_config", std::tie(), result);
    return result;
}

semantic_version jsonrpc_virtual_machine::get_version(const jsonrpc_mg_mgr_ptr &mgr) {
    semantic_version result;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "get_version", std::tie(), result);
    return result;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

void jsonrpc_virtual_machine::shutdown(const jsonrpc_mg_mgr_ptr &mgr) {
    mgr->shutdown();
}

void jsonrpc_virtual_machine::verify_access_log(const jsonrpc_mg_mgr_ptr &mgr, const access_log &log,
    const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.verify_access_log",
        std::tie(log, runtime, one_based), result);
}

void jsonrpc_virtual_machine::verify_state_transition(const jsonrpc_mg_mgr_ptr &mgr, const hash_type &root_hash_before,
    const access_log &log, const hash_type &root_hash_after, const machine_runtime_config &runtime, bool one_based) {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.verify_state_transition",
        std::tie(b64_root_hash_before, log, b64_root_hash_after, runtime, one_based), result);
}

interpreter_break_reason jsonrpc_virtual_machine::do_run(uint64_t mcycle_end) {
    interpreter_break_reason result = interpreter_break_reason::failed;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.run", std::tie(mcycle_end), result);
    return result;
}

void jsonrpc_virtual_machine::do_store(const std::string &directory) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.store", std::tie(directory), result);
}

uint64_t jsonrpc_virtual_machine::do_read_csr(csr r) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_csr", std::tie(r), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_csr(csr w, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_csr", std::tie(w, val), result);
}

uint64_t jsonrpc_virtual_machine::get_csr_address(const jsonrpc_mg_mgr_ptr &mgr, csr w) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.get_csr_address", std::tie(w), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_x(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_x", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_x(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_x", std::tie(i, val), result);
}

uint64_t jsonrpc_virtual_machine::get_x_address(const jsonrpc_mg_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.get_x_address", std::tie(i), result);
    return result;
}

std::string jsonrpc_virtual_machine::fork(const jsonrpc_mg_mgr_ptr &mgr) {
    std::string result;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "fork", std::tie(), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_f(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_f", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_f(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_f", std::tie(i, val), result);
}

uint64_t jsonrpc_virtual_machine::get_f_address(const jsonrpc_mg_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.get_f_address", std::tie(i), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::get_uarch_x_address(const jsonrpc_mg_mgr_ptr &mgr, int i) {
    uint64_t result = 0;
    jsonrpc_request(mgr->get_mgr(), mgr->get_remote_address(), "machine.get_uarch_x_address", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_memory", std::tie(address, length),
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
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_memory", std::tie(address, b64),
        result);
}

void jsonrpc_virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_virtual_memory",
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
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_virtual_memory",
        std::tie(address, b64), result);
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

uint64_t jsonrpc_virtual_machine::do_read_hstatus(void) const {
    return read_csr(csr::hstatus);
}

void jsonrpc_virtual_machine::do_write_hstatus(uint64_t val) {
    write_csr(csr::hstatus, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hideleg(void) const {
    return read_csr(csr::hideleg);
}

void jsonrpc_virtual_machine::do_write_hideleg(uint64_t val) {
    write_csr(csr::hideleg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hedeleg(void) const {
    return read_csr(csr::hedeleg);
}

void jsonrpc_virtual_machine::do_write_hedeleg(uint64_t val) {
    write_csr(csr::hedeleg, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hip(void) const {
    return read_csr(csr::hip);
}

void jsonrpc_virtual_machine::do_write_hip(uint64_t val) {
    write_csr(csr::hip, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hvip(void) const {
    return read_csr(csr::hvip);
}

void jsonrpc_virtual_machine::do_write_hvip(uint64_t val) {
    write_csr(csr::hvip, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hie(void) const {
    return read_csr(csr::hie);
}

void jsonrpc_virtual_machine::do_write_hie(uint64_t val) {
    write_csr(csr::hie, val);
}

uint64_t jsonrpc_virtual_machine::do_read_hgatp(void) const {
    return read_csr(csr::hgatp);
}

void jsonrpc_virtual_machine::do_write_hgatp(uint64_t val) {
    write_csr(csr::hgatp, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htimedelta(void) const {
    return read_csr(csr::htimedelta);
}

void jsonrpc_virtual_machine::do_write_htimedelta(uint64_t val) {
    write_csr(csr::htimedelta, val);
}

uint64_t jsonrpc_virtual_machine::do_read_htval(void) const {
    return read_csr(csr::htval);
}

void jsonrpc_virtual_machine::do_write_htval(uint64_t val) {
    write_csr(csr::htval, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsepc(void) const {
    return read_csr(csr::vsepc);
}

void jsonrpc_virtual_machine::do_write_vsepc(uint64_t val) {
    write_csr(csr::vsepc, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsstatus(void) const {
    return read_csr(csr::vsstatus);
}

void jsonrpc_virtual_machine::do_write_vsstatus(uint64_t val) {
    write_csr(csr::vsstatus, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vscause(void) const {
    return read_csr(csr::vscause);
}

void jsonrpc_virtual_machine::do_write_vscause(uint64_t val) {
    write_csr(csr::vscause, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vstval(void) const {
    return read_csr(csr::vstval);
}

void jsonrpc_virtual_machine::do_write_vstval(uint64_t val) {
    write_csr(csr::vstval, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vstvec(void) const {
    return read_csr(csr::vstvec);
}

void jsonrpc_virtual_machine::do_write_vstvec(uint64_t val) {
    write_csr(csr::vstvec, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsscratch(void) const {
    return read_csr(csr::vsscratch);
}

void jsonrpc_virtual_machine::do_write_vsscratch(uint64_t val) {
    write_csr(csr::vsscratch, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsatp(void) const {
    return read_csr(csr::vsatp);
}

void jsonrpc_virtual_machine::do_write_vsatp(uint64_t val) {
    write_csr(csr::vsatp, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsip(void) const {
    return read_csr(csr::vsip);
}

void jsonrpc_virtual_machine::do_write_vsip(uint64_t val) {
    write_csr(csr::vsip, val);
}

uint64_t jsonrpc_virtual_machine::do_read_vsie(void) const {
    return read_csr(csr::vsie);
}

void jsonrpc_virtual_machine::do_write_vsie(uint64_t val) {
    write_csr(csr::vsie, val);
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
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_iflags_H", std::tie(), result);
    return result;
}

bool jsonrpc_virtual_machine::do_read_iflags_Y(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_iflags_Y", std::tie(), result);
    return result;
}

bool jsonrpc_virtual_machine::do_read_iflags_X(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_iflags_X", std::tie(), result);
    return result;
}

void jsonrpc_virtual_machine::do_set_iflags_H(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.set_iflags_H", std::tie(), result);
}

void jsonrpc_virtual_machine::do_set_iflags_Y(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.set_iflags_Y", std::tie(), result);
}

void jsonrpc_virtual_machine::do_set_iflags_X(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.set_iflags_X", std::tie(), result);
}

void jsonrpc_virtual_machine::do_reset_iflags_Y(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.reset_iflags_Y", std::tie(), result);
}

void jsonrpc_virtual_machine::do_reset_iflags_X(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.reset_iflags_X", std::tie(), result);
}

bool jsonrpc_virtual_machine::do_read_uarch_halt_flag(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_uarch_halt_flag", std::tie(), result);
    return result;
}

void jsonrpc_virtual_machine::do_set_uarch_halt_flag(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.set_uarch_halt_flag", std::tie(), result);
}

void jsonrpc_virtual_machine::do_reset_uarch_state(void) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.reset_uarch_state", std::tie(), result);
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

void jsonrpc_virtual_machine::do_get_root_hash(hash_type &hash) const {
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.get_root_hash", std::tie(), hash);
}

machine_merkle_tree::proof_type jsonrpc_virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    not_default_constructible<machine_merkle_tree::proof_type> result;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.get_proof", std::tie(address, log2_size),
        result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.replace_memory_range", std::tie(new_range),
        result);
}

access_log jsonrpc_virtual_machine::do_step_uarch(const access_log::type &log_type, bool one_based) {
    not_default_constructible<access_log> result;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.step_uarch", std::tie(log_type, one_based),
        result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_destroy() {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.destroy", std::tie(), result);
}

bool jsonrpc_virtual_machine::do_verify_dirty_page_maps(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.verify_dirty_page_maps", std::tie(),
        result);
    return result;
}

void jsonrpc_virtual_machine::do_dump_pmas(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.dump_pmas", std::tie(), result);
}

uint64_t jsonrpc_virtual_machine::do_read_word(uint64_t address) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_word", std::tie(address), result);
    return result;
}

bool jsonrpc_virtual_machine::do_verify_merkle_tree(void) const {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.verify_merkle_tree", std::tie(), result);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_uarch_x(int i) const {
    uint64_t result = 0;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.read_uarch_x", std::tie(i), result);
    return result;
}

void jsonrpc_virtual_machine::do_write_uarch_x(int i, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.write_uarch_x", std::tie(i, val), result);
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

void jsonrpc_virtual_machine::do_rollback(void) {
    m_mgr->rollback();
}

uint64_t jsonrpc_virtual_machine::do_read_uarch_ram_length(void) const {
    return read_csr(csr::uarch_ram_length);
}

uarch_interpreter_break_reason jsonrpc_virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    uarch_interpreter_break_reason result = uarch_interpreter_break_reason::reached_target_cycle;
    jsonrpc_request(m_mgr->get_mgr(), m_mgr->get_remote_address(), "machine.run_uarch", std::tie(uarch_cycle_end),
        result);
    return result;
}

#pragma GCC diagnostic pop

} // namespace cartesi
