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

#if defined(__clang__) && defined(__APPLE__)
#if !defined(__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#define __ENVIRONMENT_OS_VERSION_MIN_REQUIRED__ __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#endif
#endif

#define BOOST_TEST_MODULE Machine JSONRPC C API test // NOLINT(cppcoreguidelines-macro-usage)
#define BOOST_TEST_NO_OLD_TOOLS

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/test/included/unit_test.hpp>
#pragma GCC diagnostic pop

#define JSON_HAS_FILESYSTEM 0
#include <json.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <cm-jsonrpc.h>
#include <cm.h>
#include <scope-exit.hpp>

// NOLINTBEGIN(cppcoreguidelines-avoid-do-while,cppcoreguidelines-non-private-member-variables-in-classes)

#ifdef __clang__
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif

// NOLINTNEXTLINE
#define BOOST_AUTO_TEST_CASE_NOLINT(...) BOOST_AUTO_TEST_CASE(__VA_ARGS__)
// NOLINTNEXTLINE
#define BOOST_FIXTURE_TEST_CASE_NOLINT(...) BOOST_FIXTURE_TEST_CASE(__VA_ARGS__)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Returns a minimal machine config JSON string (1 MB RAM, no ROM image).
static std::string minimal_machine_config() {
    const char *cfg{};
    cm_get_default_config(nullptr, &cfg);
    auto j = nlohmann::json::parse(cfg);
    j["ram"]["length"] = 1 << 20;
    return j.dump();
}

// Sends an HTTP request to address ("host:port") and returns {status_code, response_body}.
// Uses HTTP/1.0 so the server closes the connection after the response.
static std::pair<int, std::string> http_raw(const std::string &address, const std::string &method,
    const std::string &uri, const std::string &body) {
    auto colon = address.rfind(':');
    std::string host = address.substr(0, colon);
    int port = std::stoi(address.substr(colon + 1));

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    BOOST_REQUIRE_GE(fd, 0);

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    ::inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    BOOST_REQUIRE_EQUAL(::connect(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)), 0); // NOLINT

    std::ostringstream req;
    req << method << " " << uri << " HTTP/1.0\r\n";
    req << "Host: " << address << "\r\n";
    if (!body.empty()) {
        req << "Content-Type: application/json\r\n";
        req << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;
    auto req_str = req.str();
    ::send(fd, req_str.c_str(), req_str.size(), 0);

    std::string response;
    std::array<char, 4096> buf{};
    ssize_t n = 0;
    while ((n = ::recv(fd, buf.data(), buf.size(), 0)) > 0) {
        response.append(buf.data(), static_cast<size_t>(n));
    }
    ::close(fd);

    // Parse "HTTP/1.0 NNN ..."
    int status = 0;
    if (response.size() >= 12) {
        status = std::stoi(response.substr(9, 3));
    }
    auto sep = response.find("\r\n\r\n");
    std::string resp_body;
    if (sep != std::string::npos) {
        resp_body = response.substr(sep + 4);
    }
    return {status, resp_body};
}

// Convenience: POST JSON-RPC body and return the parsed response JSON.
static nlohmann::json jsonrpc_post(const std::string &address, const std::string &body) {
    auto [status, resp] = http_raw(address, "POST", "/", body);
    BOOST_REQUIRE_EQUAL(status, 200);
    return nlohmann::json::parse(resp);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Spawns a JSON-RPC server bound to an ephemeral port. Shuts it down on destruction.
// Requires CARTESI_JSONRPC_MACHINE to point at the server binary.
// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
struct spawned_server_fixture {
    spawned_server_fixture() {
        const char *addr{};
        cm_error err = cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, &addr, &pid);
        BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
        BOOST_REQUIRE(m != nullptr);
        bound_address = addr ? addr : "";
    }
    ~spawned_server_fixture() {
        if (m != nullptr) {
            cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
            cm_delete(m);
        }
    }
    cm_machine *m{};
    std::string bound_address;
    uint32_t pid{};
};

using machine_ptr = std::unique_ptr<cm_machine, decltype(&cm_delete)>;

// Keep the servers alive until the caller has finished loading its snapshots.
// Report errors after joining: Boost.Test assertions must stay on the test thread.
static void spawn_servers(std::stop_token stop, std::vector<machine_ptr> &servers, std::string &error) {
    try {
        for (int i = 0; i < 16 && !stop.stop_requested(); ++i) {
            cm_machine *server{};
            const auto err = cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &server, nullptr, nullptr);
            machine_ptr owner{server, cm_delete};
            if (err != CM_ERROR_OK) {
                error = cm_get_last_error_message();
                return;
            }
            servers.push_back(std::move(owner));
        }
    } catch (const std::exception &e) {
        error = e.what();
    }
}

// What: spawning a server must not keep a completed local store's file locks alive.
// How:  repeatedly store and reload a machine while another thread spawns servers.
//       Keep all servers alive through the reloads, including their startup fork descendants.
BOOST_AUTO_TEST_CASE_NOLINT(spawn_during_store_test) {
    auto base = (std::filesystem::temp_directory_path() / "cartesi-spawn-store-XXXXXX").string();
    BOOST_REQUIRE(mkdtemp(base.data()) != nullptr);
    const auto cleanup = cartesi::scope_exit([&base] { std::filesystem::remove_all(base); });
    const auto dir = base + "/machine";

    cm_machine *machine{};
    const auto err = cm_create_new(R"({"ram":{"length":134217728}})", nullptr, nullptr, &machine);
    const machine_ptr owner{machine, cm_delete};
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);

    std::vector<machine_ptr> servers;
    std::string spawn_error;
    std::jthread spawner{spawn_servers, std::ref(servers), std::ref(spawn_error)};
    for (int i = 0; i < 10; ++i) {
        BOOST_REQUIRE_EQUAL(cm_store(machine, dir.c_str(), CM_SHARING_ALL), CM_ERROR_OK);
        cm_machine *loaded{};
        const auto load_err = cm_load_new(dir.c_str(), nullptr, CM_SHARING_ALL, &loaded);
        machine_ptr loaded_owner{loaded, cm_delete};
        BOOST_REQUIRE_MESSAGE(load_err == CM_ERROR_OK, cm_get_last_error_message());
        // Close the loaded machine before removing its backing files.
        loaded_owner.reset();
        std::filesystem::remove_all(dir);
    }
    spawner.request_stop();
    spawner.join();
    BOOST_CHECK_MESSAGE(spawn_error.empty(), spawn_error);
    BOOST_CHECK(!servers.empty());
}

// ---------------------------------------------------------------------------
// Group A: argument-validation errors (no running server required)
// ---------------------------------------------------------------------------

// What: cm_jsonrpc_connect_server rejects a null address pointer.
// How:  call with address=nullptr and expect a non-OK error plus a null output handle.
BOOST_AUTO_TEST_CASE_NOLINT(connect_null_address_test) {
    cm_machine *out{};
    cm_error err = cm_jsonrpc_connect_server(nullptr, -1, &out);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(out == nullptr);
}

// What: cm_jsonrpc_connect_server rejects a null output pointer.
// How:  call with out_machine=nullptr and expect a non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(connect_null_output_test) {
    cm_error err = cm_jsonrpc_connect_server("127.0.0.1:0", -1, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
}

// What: cm_jsonrpc_connect_server fails cleanly when nothing is listening.
// How:  point at 127.0.0.1:1 (a port that will refuse/time out quickly) with a
//       short timeout and expect a non-OK error without leaking a handle.
BOOST_AUTO_TEST_CASE_NOLINT(connect_unreachable_address_test) {
    cm_machine *out{};
    cm_error err = cm_jsonrpc_connect_server("127.0.0.1:1", 50, &out);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(out == nullptr);
}

// What: cm_jsonrpc_spawn_server rejects a null address pointer.
// How:  call with address=nullptr and expect a non-OK error with all output
//       parameters left untouched (no machine, no bound address, zero pid).
BOOST_AUTO_TEST_CASE_NOLINT(spawn_null_address_test) {
    cm_machine *out{};
    const char *addr{};
    uint32_t pid{};
    cm_error err = cm_jsonrpc_spawn_server(nullptr, -1, &out, &addr, &pid);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(out == nullptr);
    BOOST_CHECK(addr == nullptr);
    BOOST_CHECK_EQUAL(pid, 0U);
}

// What: cm_jsonrpc_spawn_server rejects a null machine output pointer.
// How:  call with out_machine=nullptr and expect a non-OK error; verify the
//       other outputs (bound address, pid) are not populated either.
BOOST_AUTO_TEST_CASE_NOLINT(spawn_null_machine_output_test) {
    const char *addr{};
    uint32_t pid{};
    cm_error err = cm_jsonrpc_spawn_server("127.0.0.1:0", -1, nullptr, &addr, &pid);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(addr == nullptr);
    BOOST_CHECK_EQUAL(pid, 0U);
}

// ---------------------------------------------------------------------------
// Group B: wrong handle -- nullptr and local-machine handle errors
// ---------------------------------------------------------------------------

// What: cm_jsonrpc_fork_server rejects a null machine handle.
// How:  call with machine=nullptr and expect a non-OK error with all outputs
//       left untouched.
BOOST_AUTO_TEST_CASE_NOLINT(fork_null_machine_test) {
    cm_machine *forked{};
    const char *addr{};
    uint32_t pid{};
    cm_error err = cm_jsonrpc_fork_server(nullptr, &forked, &addr, &pid);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(forked == nullptr);
    BOOST_CHECK(addr == nullptr);
    BOOST_CHECK_EQUAL(pid, 0U);
}

// What: cm_jsonrpc_fork_server rejects a null forked-machine output pointer.
// How:  spawn a real server so convert_from_c accepts the handle, then call
//       fork with forked=nullptr and expect a non-OK error with no side effects.
BOOST_AUTO_TEST_CASE_NOLINT(fork_null_forked_output_test) {
    cm_machine *m{};
    const char *bound{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, &bound, nullptr);
    BOOST_REQUIRE(m != nullptr);

    const char *addr{};
    cm_error err = cm_jsonrpc_fork_server(m, nullptr, &addr, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(addr == nullptr);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: cm_jsonrpc_fork_server rejects a null address output pointer.
// How:  spawn a real server, then call fork with address=nullptr and expect a
//       non-OK error and a null forked handle.
BOOST_AUTO_TEST_CASE_NOLINT(fork_null_address_output_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_machine *forked{};
    cm_error err = cm_jsonrpc_fork_server(m, &forked, nullptr, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(forked == nullptr);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: cm_jsonrpc_get_server_version rejects a null output pointer.
// How:  spawn a real server, call the getter with out=nullptr and expect a
//       non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(get_version_null_output_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_error err = cm_jsonrpc_get_server_version(m, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: cm_jsonrpc_get_timeout rejects a null output pointer.
// How:  spawn a real server, call the getter with out=nullptr and expect a
//       non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(get_timeout_null_output_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_error err = cm_jsonrpc_get_timeout(m, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: cm_jsonrpc_get_cleanup_call rejects a null output pointer.
// How:  spawn a real server, call the getter with out=nullptr and expect a
//       non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(get_cleanup_call_null_output_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_error err = cm_jsonrpc_get_cleanup_call(m, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: cm_jsonrpc_get_server_address rejects a null output pointer.
// How:  spawn a real server, call the getter with out=nullptr and expect a
//       non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(get_server_address_null_output_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_error err = cm_jsonrpc_get_server_address(m, nullptr);
    BOOST_CHECK_NE(err, CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// What: every cm_jsonrpc_* wrapper rejects a handle that is not a remote
//       machine (exercises the "not a JSONRPC remote machine" branch in
//       convert_from_c).
// How:  create a local machine with cm_create_new, then call every wrapper
//       that accepts cm_machine* on it and assert each returns a non-OK error.
BOOST_AUTO_TEST_CASE_NOLINT(local_handle_rejected_test) {
    cm_machine *local{};
    std::string cfg = minimal_machine_config();
    cm_create_new(cfg.c_str(), nullptr, nullptr, &local);
    BOOST_REQUIRE(local != nullptr);

    // Every cm_jsonrpc_* function that accepts cm_machine* should reject a local handle.
    BOOST_CHECK_NE(cm_jsonrpc_shutdown_server(local), CM_ERROR_OK);
    BOOST_CHECK_NE(cm_jsonrpc_emancipate_server(local), CM_ERROR_OK);
    BOOST_CHECK_NE(cm_jsonrpc_delay_next_request(local, 0), CM_ERROR_OK);

    int64_t ms{};
    BOOST_CHECK_NE(cm_jsonrpc_get_timeout(local, &ms), CM_ERROR_OK);
    BOOST_CHECK_NE(cm_jsonrpc_set_timeout(local, 0), CM_ERROR_OK);

    cm_jsonrpc_cleanup_call call{};
    BOOST_CHECK_NE(cm_jsonrpc_get_cleanup_call(local, &call), CM_ERROR_OK);
    BOOST_CHECK_NE(cm_jsonrpc_set_cleanup_call(local, CM_JSONRPC_NOTHING), CM_ERROR_OK);

    const char *addr{};
    BOOST_CHECK_NE(cm_jsonrpc_get_server_address(local, &addr), CM_ERROR_OK);

    const char *ver{};
    BOOST_CHECK_NE(cm_jsonrpc_get_server_version(local, &ver), CM_ERROR_OK);

    const char *bound{};
    BOOST_CHECK_NE(cm_jsonrpc_rebind_server(local, "127.0.0.1:0", &bound), CM_ERROR_OK);

    cm_machine *forked{};
    BOOST_CHECK_NE(cm_jsonrpc_fork_server(local, &forked, &addr, nullptr), CM_ERROR_OK);

    cm_delete(local);
}

// What: cm_jsonrpc_set_cleanup_call rejects an out-of-range enum value.
// How:  cast the integer 42 to cm_jsonrpc_cleanup_call and pass it to the
//       setter; the unknown case triggers the default throw in convert_from_c.
BOOST_AUTO_TEST_CASE_NOLINT(set_cleanup_call_invalid_enum_test) {
    cm_machine *m{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, nullptr, nullptr);
    BOOST_REQUIRE(m != nullptr);

    cm_error err = cm_jsonrpc_set_cleanup_call(m, static_cast<cm_jsonrpc_cleanup_call>(42));
    BOOST_CHECK_NE(err, CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m);
}

// ---------------------------------------------------------------------------
// Group C: happy paths (all three cleanup values + standard wrappers)
// ---------------------------------------------------------------------------

// What: cm_jsonrpc_get_server_address returns the server's bound address.
// How:  ask the spawned server for its address and compare it against the
//       address reported by cm_jsonrpc_spawn_server when the fixture started it.
BOOST_FIXTURE_TEST_CASE_NOLINT(get_server_address_test, spawned_server_fixture) {
    const char *addr{};
    cm_error err = cm_jsonrpc_get_server_address(m, &addr);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(std::string(addr), bound_address);
}

// What: cm_jsonrpc_get_server_version returns a well-formed version JSON.
// How:  call the wrapper, parse the returned string as JSON, and check that
//       the standard semver fields (major, minor, patch) are present.
BOOST_FIXTURE_TEST_CASE_NOLINT(get_server_version_test, spawned_server_fixture) {
    const char *ver{};
    cm_error err = cm_jsonrpc_get_server_version(m, &ver);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_REQUIRE(ver != nullptr);
    auto j = nlohmann::json::parse(ver);
    BOOST_CHECK(j.contains("major"));
    BOOST_CHECK(j.contains("minor"));
    BOOST_CHECK(j.contains("patch"));
}

// What: cm_jsonrpc_set_timeout and cm_jsonrpc_get_timeout are symmetric.
// How:  set the timeout to 1234 ms, read it back, and compare.
BOOST_FIXTURE_TEST_CASE_NOLINT(set_get_timeout_test, spawned_server_fixture) {
    cm_error err = cm_jsonrpc_set_timeout(m, 1234);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);

    int64_t ms{};
    err = cm_jsonrpc_get_timeout(m, &ms);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_CHECK_EQUAL(ms, 1234);
}

// What: set/get_cleanup_call round-trips every enum value, exercising all
//       cases of convert_from_c / convert_to_c for cm_jsonrpc_cleanup_call.
// How:  set DESTROY, SHUTDOWN, and NOTHING in turn and read each back.
BOOST_FIXTURE_TEST_CASE_NOLINT(set_get_cleanup_call_all_values_test, spawned_server_fixture) {
    BOOST_REQUIRE_EQUAL(cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_DESTROY), CM_ERROR_OK);
    cm_jsonrpc_cleanup_call call{};
    BOOST_REQUIRE_EQUAL(cm_jsonrpc_get_cleanup_call(m, &call), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(call, CM_JSONRPC_DESTROY);

    BOOST_REQUIRE_EQUAL(cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN), CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cm_jsonrpc_get_cleanup_call(m, &call), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(call, CM_JSONRPC_SHUTDOWN);

    BOOST_REQUIRE_EQUAL(cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_NOTHING), CM_ERROR_OK);
    BOOST_REQUIRE_EQUAL(cm_jsonrpc_get_cleanup_call(m, &call), CM_ERROR_OK);
    BOOST_CHECK_EQUAL(call, CM_JSONRPC_NOTHING);
}

// What: cm_jsonrpc_rebind_server moves the server to a new address and
//       subsequent requests still reach it.
// How:  rebind to an ephemeral port on 127.0.0.1, then call get_server_version
//       through the same client handle to confirm it routes to the new address.
BOOST_FIXTURE_TEST_CASE_NOLINT(rebind_server_test, spawned_server_fixture) {
    const char *new_addr{};
    cm_error err = cm_jsonrpc_rebind_server(m, "127.0.0.1:0", &new_addr);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_REQUIRE(new_addr != nullptr);
    const char *ver{};
    BOOST_CHECK_EQUAL(cm_jsonrpc_get_server_version(m, &ver), CM_ERROR_OK);
}

// What: cm_jsonrpc_emancipate_server returns OK on a freshly spawned server.
// How:  call the wrapper once against the fixture server and expect success.
BOOST_FIXTURE_TEST_CASE_NOLINT(emancipate_server_test, spawned_server_fixture) {
    cm_error err = cm_jsonrpc_emancipate_server(m);
    BOOST_CHECK_EQUAL(err, CM_ERROR_OK);
}

// What: cm_jsonrpc_delay_next_request really delays the next server request.
// How:  schedule a 100 ms delay, issue get_server_version and measure the
//       wall-clock elapsed time; it must be at least the requested delay.
BOOST_FIXTURE_TEST_CASE_NOLINT(delay_next_request_test, spawned_server_fixture) {
    constexpr uint64_t DELAY_MS = 100;
    BOOST_REQUIRE_EQUAL(cm_jsonrpc_delay_next_request(m, DELAY_MS), CM_ERROR_OK);

    auto t0 = std::chrono::steady_clock::now();
    const char *ver{};
    cm_jsonrpc_get_server_version(m, &ver);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    BOOST_CHECK_GE(elapsed.count(), static_cast<long>(DELAY_MS));
}

// What: cm_jsonrpc_fork_server spawns a child server that is independently
//       reachable.
// How:  fork from the fixture server, confirm the new address and pid are
//       populated, and make a get_server_version call through the forked
//       handle.
BOOST_FIXTURE_TEST_CASE_NOLINT(fork_server_test, spawned_server_fixture) {
    cm_machine *forked{};
    const char *fork_addr{};
    uint32_t fork_pid{};
    cm_error err = cm_jsonrpc_fork_server(m, &forked, &fork_addr, &fork_pid);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_REQUIRE(forked != nullptr);
    BOOST_REQUIRE(fork_addr != nullptr);
    BOOST_CHECK_NE(fork_pid, 0U);

    const char *ver{};
    BOOST_CHECK_EQUAL(cm_jsonrpc_get_server_version(forked, &ver), CM_ERROR_OK);

    cm_jsonrpc_set_cleanup_call(forked, CM_JSONRPC_SHUTDOWN);
    cm_delete(forked);
}

// What: the CM_JSONRPC_SHUTDOWN cleanup mode shuts the server down when the
//       client handle is deleted.
// How:  spawn a server, set cleanup to SHUTDOWN, cm_delete the handle, then
//       try to reconnect with a short timeout; the connect must fail because
//       the server process has terminated.
BOOST_AUTO_TEST_CASE_NOLINT(cleanup_shutdown_test) {
    cm_machine *m{};
    const char *addr_cstr{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, &addr_cstr, nullptr);
    BOOST_REQUIRE(m != nullptr);
    std::string addr = addr_cstr;

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_SHUTDOWN);
    cm_delete(m); // implicitly shuts down the server process

    // Server is gone; connecting with a short timeout must fail.
    cm_machine *reconnect{};
    cm_error err = cm_jsonrpc_connect_server(addr.c_str(), 100, &reconnect);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
    BOOST_CHECK(reconnect == nullptr);
}

// What: the CM_JSONRPC_DESTROY cleanup mode destroys the machine on cm_delete
//       but leaves the server process alive.
// How:  spawn a server, create a machine, set cleanup to DESTROY, cm_delete
//       the handle, then reconnect to the same address and confirm the server
//       is still reachable.
BOOST_AUTO_TEST_CASE_NOLINT(cleanup_destroy_test) {
    cm_machine *m{};
    const char *addr_cstr{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, &addr_cstr, nullptr);
    BOOST_REQUIRE(m != nullptr);
    std::string addr = addr_cstr;

    // Create a machine so that destroy has something to do.
    std::string cfg = minimal_machine_config();
    cm_create(m, cfg.c_str(), nullptr, nullptr);

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_DESTROY);
    cm_delete(m); // implicitly destroys the machine but leaves server alive

    // Server should still be reachable.
    cm_machine *reconnect{};
    cm_error err = cm_jsonrpc_connect_server(addr.c_str(), 1000, &reconnect);
    BOOST_CHECK_EQUAL(err, CM_ERROR_OK);
    if (reconnect != nullptr) {
        cm_jsonrpc_set_cleanup_call(reconnect, CM_JSONRPC_SHUTDOWN);
        cm_delete(reconnect);
    }
}

// What: the CM_JSONRPC_NOTHING cleanup mode leaves the server untouched on
//       cm_delete, requiring an explicit shutdown later.
// How:  spawn a server, set cleanup to NOTHING, cm_delete the handle, then
//       reconnect to the same address, call cm_jsonrpc_shutdown_server
//       explicitly and expect success.
BOOST_AUTO_TEST_CASE_NOLINT(cleanup_nothing_test) {
    cm_machine *m{};
    const char *addr_cstr{};
    cm_jsonrpc_spawn_server("127.0.0.1:0", 5000, &m, &addr_cstr, nullptr);
    BOOST_REQUIRE(m != nullptr);
    std::string addr = addr_cstr;

    cm_jsonrpc_set_cleanup_call(m, CM_JSONRPC_NOTHING);
    cm_delete(m); // server stays alive; no memory leak from the handle

    // Reconnect and shut down explicitly.
    cm_machine *reconnect{};
    cm_error err = cm_jsonrpc_connect_server(addr.c_str(), 1000, &reconnect);
    BOOST_REQUIRE_EQUAL(err, CM_ERROR_OK);
    BOOST_REQUIRE(reconnect != nullptr);

    BOOST_CHECK_EQUAL(cm_jsonrpc_shutdown_server(reconnect), CM_ERROR_OK);
    cm_delete(reconnect);
}

// ---------------------------------------------------------------------------
// Group D: "no machine" server-side errors via C API (machine methods before
// cm_create_new is called).  This hits the "no machine" guard in each handler
// in jsonrpc-remote-machine.cpp.
// ---------------------------------------------------------------------------

// What: cm_read_reg returns an error when no machine has been created on the
//       remote server yet (hits the "no machine" guard in the handler).
// How:  against the bare fixture server (no cm_create_new), call cm_read_reg
//       for CM_REG_PC and expect a non-OK error.
BOOST_FIXTURE_TEST_CASE_NOLINT(read_reg_before_create_test, spawned_server_fixture) {
    uint64_t val{};
    cm_error err = cm_read_reg(m, CM_REG_PC, &val);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
}

// What: cm_run returns an error when no machine has been created yet.
// How:  against the bare fixture server, call cm_run and expect a non-OK error.
BOOST_FIXTURE_TEST_CASE_NOLINT(run_before_create_test, spawned_server_fixture) {
    cm_break_reason reason{};
    cm_error err = cm_run(m, 1, &reason);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
}

// What: cm_get_root_hash returns an error when no machine has been created yet.
// How:  against the bare fixture server, call cm_get_root_hash and expect a
//       non-OK error.
BOOST_FIXTURE_TEST_CASE_NOLINT(get_root_hash_before_create_test, spawned_server_fixture) {
    cm_hash hash{};
    cm_error err = cm_get_root_hash(m, &hash);
    BOOST_CHECK_NE(err, CM_ERROR_OK);
}

// ---------------------------------------------------------------------------
// Group E: raw HTTP/JSON-RPC error branches in jsonrpc-remote-machine.cpp
// ---------------------------------------------------------------------------

// What: a non-POST HTTP verb on the JSON-RPC endpoint yields 405 Method Not Allowed.
// How:  open a raw socket to the fixture server, send "GET / HTTP/1.0" and
//       assert the status line reports 405.
BOOST_FIXTURE_TEST_CASE_NOLINT(http_non_post_rejected_test, spawned_server_fixture) {
    auto [status, body] = http_raw(bound_address, "GET", "/", "");
    BOOST_CHECK_EQUAL(status, 405);
}

// What: POSTing to any URI other than "/" yields 404 Not Found.
// How:  send a POST to "/bad-path" with a valid-ish body and assert 404.
BOOST_FIXTURE_TEST_CASE_NOLINT(http_wrong_uri_rejected_test, spawned_server_fixture) {
    auto [status, body] = http_raw(bound_address, "POST", "/bad-path", "{}");
    BOOST_CHECK_EQUAL(status, 404);
}

// What: a body that is not valid JSON yields JSON-RPC parse_error (-32700).
// How:  POST a clearly broken body ("{not valid json") and assert the reply
//       contains an "error" with code -32700.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_parse_error_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, "{not valid json");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32700);
}

// What: an empty batch array yields invalid_request (-32600).
// How:  POST "[]" and assert the reply contains an "error" with code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_empty_batch_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, "[]");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32600);
}

// What: a request with no "jsonrpc" field yields invalid_request (-32600).
// How:  POST a request missing the "jsonrpc" key and assert code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_missing_version_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"method":"version","id":1})");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32600);
}

// What: a request with "jsonrpc" set to something other than "2.0" yields
//       invalid_request (-32600).
// How:  POST a request with "jsonrpc":"1.0" and assert code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_wrong_version_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"jsonrpc":"1.0","method":"version","id":1})");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32600);
}

// What: a request with no "method" field yields invalid_request (-32600).
// How:  POST a request missing the "method" key and assert code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_missing_method_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"jsonrpc":"2.0","id":1})");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32600);
}

// What: a request with an empty "method" string yields invalid_request (-32600).
// How:  POST a request with "method":"" and assert code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_empty_method_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"jsonrpc":"2.0","method":"","id":1})");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32600);
}

// What: an unrecognized method name yields method_not_found (-32601).
// How:  POST a well-formed request with method "does.not.exist" and assert
//       the reply carries code -32601.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_unknown_method_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"jsonrpc":"2.0","method":"does.not.exist","id":1})");
    BOOST_REQUIRE(j.contains("error"));
    BOOST_CHECK_EQUAL(j["error"]["code"].get<int>(), -32601);
}

// What: a well-formed notification (no "id") receives no JSON response body.
// How:  POST a request for "get_version" with no "id" field and assert the
//       HTTP status is 200 and the response body is empty.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_notification_no_response_test, spawned_server_fixture) {
    auto [status, body] = http_raw(bound_address, "POST", "/", R"({"jsonrpc":"2.0","method":"get_version"})");
    BOOST_CHECK_EQUAL(status, 200);
    BOOST_CHECK(body.empty());
}

// What: a batch of two valid requests returns a two-element array of results.
// How:  POST a batch with two "get_version" requests and assert the reply is
//       a JSON array of size 2 where every element has a "result" field.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_batch_request_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address,
        R"([{"jsonrpc":"2.0","method":"get_version","id":1},{"jsonrpc":"2.0","method":"get_version","id":2}])");
    BOOST_REQUIRE(j.is_array());
    BOOST_CHECK_EQUAL(j.size(), 2U);
    for (const auto &resp : j) {
        BOOST_CHECK(resp.contains("result"));
    }
}

// What: a batch where an element is not a JSON object produces an individual
//       invalid_request error for that element.
// How:  POST "[42]" and assert the reply is a one-element array whose only
//       entry has error code -32600.
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_batch_non_object_element_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"([42])");
    BOOST_REQUIRE(j.is_array());
    BOOST_REQUIRE_EQUAL(j.size(), 1U);
    BOOST_CHECK_EQUAL(j[0]["error"]["code"].get<int>(), -32600);
}

// What: a request whose "id" is not a string/number/null is still answered,
//       exercising the id-type validation branch in the dispatcher.
// How:  POST a request with "id":[1,2] and assert the reply is a well-formed
//       JSON object (the branch runs; the test does not pin down the exact
//       payload shape since it is non-obvious).
BOOST_FIXTURE_TEST_CASE_NOLINT(jsonrpc_invalid_id_type_test, spawned_server_fixture) {
    auto j = jsonrpc_post(bound_address, R"({"jsonrpc":"2.0","method":"version","id":[1,2]})");
    BOOST_CHECK(j.is_object());
}

// NOLINTEND(cppcoreguidelines-avoid-do-while,cppcoreguidelines-non-private-member-variables-in-classes)
