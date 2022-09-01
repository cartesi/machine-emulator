// Copyright 2021 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include <google/protobuf/util/json_util.h>
#include <grpc++/grpc++.h>

#include "cartesi-machine-checkin.grpc.pb.h"
#include "health.grpc.pb.h"
#include "protobuf-util.h"
#include "server-manager.grpc.pb.h"
#pragma GCC diagnostic pop

#include "back-merkle-tree.h"
#include "complete-merkle-tree.h"
#include "machine.h"

using CartesiMachine::Void;
using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

// NOLINTNEXTLINE(misc-unused-using-decls)
using std::chrono_literals::operator""s;

using namespace std::filesystem;
using namespace CartesiServerManager;
using namespace cartesi;
using namespace grpc::health::v1;

constexpr static const int LOG2_ROOT_SIZE = 37;
constexpr static const int LOG2_KECCAK_SIZE = 5;
constexpr static const int LOG2_WORD_SIZE = 3;
constexpr static const uint64_t MEMORY_REGION_LENGTH = 2 << 20;
static const path MANAGER_ROOT_DIR = "/tmp/server-manager-root"; // NOLINT: ignore static initialization warning

class ServerManagerClient {

public:
    ServerManagerClient(const std::string &address) : m_test_id("not-defined") {
        m_stub = ServerManager::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        m_health_stub = Health::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    }

    Status get_version(Versioning::GetVersionResponse &response) {
        ClientContext context;
        Void request;
        init_client_context(context);
        return m_stub->GetVersion(&context, request, &response);
    }

    Status start_session(const StartSessionRequest &request, StartSessionResponse &response) {
        ClientContext context;
        init_client_context(context);
        return m_stub->StartSession(&context, request, &response);
    }

    Status advance_state(const AdvanceStateRequest &request) {
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->AdvanceState(&context, request, &response);
    }

    Status get_status(GetStatusResponse &response) {
        ClientContext context;
        Void request;
        init_client_context(context);
        return m_stub->GetStatus(&context, request, &response);
    }

    Status get_session_status(const GetSessionStatusRequest &request, GetSessionStatusResponse &response) {
        ClientContext context;
        init_client_context(context);
        return m_stub->GetSessionStatus(&context, request, &response);
    }

    Status get_epoch_status(const GetEpochStatusRequest &request, GetEpochStatusResponse &response) {
        ClientContext context;
        init_client_context(context);
        return m_stub->GetEpochStatus(&context, request, &response);
    }

    Status inspect_state(const InspectStateRequest &request, InspectStateResponse &response) {
        ClientContext context;
        init_client_context(context);
        return m_stub->InspectState(&context, request, &response);
    }

    Status finish_epoch(const FinishEpochRequest &request) {
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->FinishEpoch(&context, request, &response);
    }

    Status end_session(const EndSessionRequest &request) {
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->EndSession(&context, request, &response);
    }

    Status health_check(const HealthCheckRequest &request, HealthCheckResponse &response) {
        ClientContext context;
        init_client_context(context);
        return m_health_stub->Check(&context, request, &response);
    }

    void set_test_id(std::string test_id) {
        m_test_id = std::move(test_id);
    }

    std::string test_id() {
        return m_test_id;
    }

private:
    std::unique_ptr<ServerManager::Stub> m_stub;
    std::unique_ptr<Health::Stub> m_health_stub;
    std::string m_test_id;

    void init_client_context(ClientContext &context) {
        context.set_wait_for_ready(true);
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(90));
        context.AddMetadata("test-id", test_id());
        context.AddMetadata("request-id", request_id());
    }

    static std::string request_id() {
        uint64_t request_id =
            static_cast<uint64_t>(std::time(nullptr)) << 32 | (std::rand() & 0xFFFFFFFF); // NOLINT: rand is ok for this
        return std::to_string(request_id);
    }
};

using config_function = void (*)(machine_config &);
using test_function = void (*)(ServerManagerClient &);
using test_setup = void (*)(const std::function<void(const std::string &, test_function)> &);

class test_suite final {
public:
    test_suite(ServerManagerClient &manager) : m_manager{manager}, m_suite{}, m_total_tests{0} {}

    void add_test_set(const std::string &title, test_setup setup) {
        m_suite.emplace_back(title, std::vector<std::pair<std::string, test_function>>());
        auto &tests = m_suite.back().second;
        setup([&tests, this](const std::string &title, test_function f) {
            tests.emplace_back(title, f);
            ++m_total_tests;
        });
    }

    int run() {
        int total = 0;
        int total_failed = 0;
        std::cerr << "\nRunning tests:\n\n";
        for (const auto &[test, cases] : m_suite) {
            int failed = 0;
            std::cerr << test << ": ";
            for (const auto &[c, f] : cases) {
                try {
                    std::cerr << ".";
                    m_manager.set_test_id(std::to_string(total));
                    (*f)(m_manager);
                } catch (std::exception &e) {
                    if (failed == 0) {
                        std::cerr << " FAILED";
                    }
                    std::cerr << "\n  - [" << std::to_string(total) + "] '" << c << "' expected result failed:\n\t"
                              << e.what() << std::endl;
                    failed++;
                }
                total++;
            }
            if (failed == 0) {
                std::cerr << " OK";
            }
            std::cerr << std::endl;
            total_failed += failed;
        }
        std::cerr << m_total_tests - total_failed << " of " << m_total_tests << " tests passed" << std::endl;
        return total_failed;
    }

private:
    ServerManagerClient &m_manager;
    std::vector<std::pair<std::string, std::vector<std::pair<std::string, test_function>>>> m_suite;
    unsigned int m_total_tests;
};

static void get_word_hash(cryptopp_keccak_256_hasher &h, const unsigned char *word, int log2_word_size,
    cryptopp_keccak_256_hasher::hash_type &hash) {
    h.begin();
    h.add_data(word, 1 << log2_word_size);
    h.end(hash);
}

static cryptopp_keccak_256_hasher::hash_type get_leaf_hash(cryptopp_keccak_256_hasher &h,
    const unsigned char *leaf_data, int log2_leaf_size, int log2_word_size) {
    assert(log2_leaf_size >= log2_word_size);
    if (log2_leaf_size > log2_word_size) {
        cryptopp_keccak_256_hasher::hash_type left = get_leaf_hash(h, leaf_data, log2_leaf_size - 1, log2_word_size);
        cryptopp_keccak_256_hasher::hash_type right =
            get_leaf_hash(h, leaf_data + (1 << (log2_leaf_size - 1)), log2_leaf_size - 1, log2_word_size);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        cryptopp_keccak_256_hasher::hash_type leaf;
        get_word_hash(h, leaf_data, log2_word_size, leaf);
        return leaf;
    }
}

#if 0
static void get_hash(const unsigned char *data, size_t size,
    cryptopp_keccak_256_hasher::hash_type &hash) {
    cryptopp_keccak_256_hasher h;
    h.begin();
    h.add_data(data, size);
    h.end(hash);
}

static void print_hash(const cryptopp_keccak_256_hasher::hash_type &hash, FILE *f) {
    for (auto b: hash) {
        (void) fprintf(f, "%02x", static_cast<int>(b));
    }
    (void) fprintf(f, "\n");
}

static void print_json_message(const google::protobuf::Message &msg, bool pretty = false) {
    std::string json_msg;
    google::protobuf::util::JsonOptions json_opts;
    json_opts.add_whitespace = pretty;
    google::protobuf::util::Status s = MessageToJsonString(msg, &json_msg, json_opts);
    if (s.ok()) {
        std::cerr << std::endl << json_msg << std::endl ;
    }
}
#endif

static uint64_t new_session_id() {
    static uint64_t session_id = 1;
    return session_id++;
}

static uint64_t flash_start_address(uint8_t position) {
    return (1ULL << 63) + (position * (1ULL << 60));
}

static path get_machine_directory(const std::string &storage_path, const std::string &machine) {
    return MANAGER_ROOT_DIR / storage_path / machine;
}

static bool delete_storage_directory(const std::string &storage_path) {
    if (storage_path.empty()) {
        return false;
    }
    return remove_all(MANAGER_ROOT_DIR / storage_path) > 0;
}

static bool create_storage_directory(const std::string &storage_path, bool rebuild = true) {
    if (storage_path.empty()) {
        return false;
    }
    path root_path = MANAGER_ROOT_DIR / storage_path;
    if (exists(root_path)) {
        if (!rebuild) {
            return true;
        }
        if (!delete_storage_directory(storage_path)) {
            return false;
        }
    }
    return create_directories(root_path) > 0;
}

static bool change_storage_directory_permissions(const std::string &storage_path, bool writable) {
    if (storage_path.empty()) {
        return false;
    }
    auto new_perms = writable ? (perms::owner_all) : (perms::owner_read | perms::owner_exec);
    std::error_code ec;
    permissions(MANAGER_ROOT_DIR / storage_path, new_perms, ec);
    return ec.value() == 0;
}

static void create_machine(const std::string &name, const std::string &command,
    const config_function custom_config = nullptr) {
    std::cerr << "- Creating " << name << ": ";
    // Check if machine already exists
    path machine_directory = get_machine_directory("tests", name);
    if (exists(machine_directory)) {
        std::cerr << "Already exists." << std::endl;
        return;
    }

    const char *env_images_path = std::getenv("CARTESI_IMAGES_PATH");
    path images_path = (env_images_path == nullptr) ? current_path() : env_images_path;

    // Machine config
    machine_config config;

    // Enable machine yield manual and yield automatic
    config.htif.yield_manual = true;
    config.htif.yield_automatic = true;

    // Setup rollup device
    rollup_config rollup;
    rollup.rx_buffer.start = 0x60000000;
    rollup.rx_buffer.length = 2 << 20;
    rollup.tx_buffer.start = 0x60200000;
    rollup.tx_buffer.length = 2 << 20;
    rollup.input_metadata.start = 0x60400000;
    rollup.input_metadata.length = 4096;
    rollup.voucher_hashes.start = 0x60600000;
    rollup.voucher_hashes.length = 2 << 20;
    rollup.notice_hashes.start = 0x60800000;
    rollup.notice_hashes.length = 2 << 20;
    config.rollup = rollup;

    // Flash Drives
    path rootfs = images_path / "rootfs.ext2";
    config.flash_drive.push_back({flash_start_address(0), file_size(rootfs), false, rootfs.string()});

    // ROM
    config.rom.image_filename = (images_path / "rom.bin").string();
    config.rom.bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet "
                          "mtdparts=flash.0:-(root) ";

    if (!command.empty()) {
        config.rom.bootargs += command;
    }

    // RAM
    config.ram.image_filename = (images_path / "linux.bin").string();
    config.ram.length = 64 << 20;

    if (custom_config != nullptr) {
        custom_config(config);
    }

    // Create machine instance, run it until yield and store it
    machine machine_instance(config);
    machine_instance.run(UINT64_MAX);
    machine_instance.store(machine_directory);
}

static void initialize_machines(bool rebuild, bool http_api) {
    std::cerr << "Initializing machines:\n";
    if (!create_storage_directory("tests", rebuild)) {
        throw std::runtime_error("Could not create storage directory tests " __FILE__ ":" + std::to_string(__LINE__));
    }
    if (http_api) {
        create_machine("advance-state-machine",
            "-- rollup-init echo-dapp --vouchers=2 --notices=2 --reports=2 --verbose");
        create_machine("inspect-state-machine", "-- rollup-init echo-dapp --reports=2 --verbose");
        create_machine("one-notice-machine", "-- rollup-init echo-dapp --vouchers=0 --notices=1 --reports=0 --verbose");
        create_machine("one-report-machine", "-- rollup-init echo-dapp --vouchers=0 --notices=0 --reports=1 --verbose");
        create_machine("one-voucher-machine",
            "-- rollup-init echo-dapp --vouchers=1 --notices=0 --reports=0 --verbose");
        create_machine("advance-rejecting-machine", "-- rollup-init echo-dapp --reject=0 --verbose");
        create_machine("inspect-rejecting-machine", "-- rollup-init echo-dapp --reports=0 --reject-inspects --verbose");
    } else {
        create_machine("advance-state-machine", "-- ioctl-echo-loop --vouchers=2 --notices=2 --reports=2 --verbose=1");
        create_machine("inspect-state-machine", "-- ioctl-echo-loop --reports=2 --verbose=1");
        create_machine("one-notice-machine", "-- ioctl-echo-loop --vouchers=0 --notices=1 --reports=0 --verbose=1");
        create_machine("one-report-machine", "-- ioctl-echo-loop --vouchers=0 --notices=0 --reports=1 --verbose=1");
        create_machine("one-voucher-machine", "-- ioctl-echo-loop --vouchers=1 --notices=0 --reports=0 --verbose=1");
        create_machine("advance-rejecting-machine", "-- ioctl-echo-loop --reject=0 --verbose=1");
        create_machine("inspect-rejecting-machine", "-- ioctl-echo-loop --reports=0 --reject-inspects --verbose=1");
    }

    create_machine("no-output-machine", "-- while true; do rollup accept; done");
    create_machine("halting-machine", "-- rollup accept");

    create_machine("init-exception-machine", R"(-- echo {\"payload\": \"test payload\"} | rollup exception)");
    create_machine("exception-machine", R"(-- rollup accept; echo {\"payload\": \"test payload\"} | rollup exception)");
    create_machine("fatal-error-machine",
        R"(-- echo 'import requests; requests.post("http://127.0.0.1:5004/finish", json={"status": ""accept"}); exit(2);' > s.py; rollup-init python3 s.py)");
    create_machine("http-server-error-machine",
        R"(-- echo 'import requests; import os; requests.post("http://127.0.0.1:5004/finish", json={"status": ""accept"}); os.system("killall rollup-http-server");' > s.py; rollup-init python3 s.py)");
    create_machine("voucher-on-inspect-machine",
        R"(-- rollup accept; echo {\"address\": \"fafafafafafafafafafafafafafafafafafafafa\", \"payload\": \"test payload\"} | rollup voucher; rollup accept)");
    create_machine("notice-on-inspect-machine",
        R"(-- rollup accept; echo {\"payload\": \"test payload\"} | rollup notice; rollup accept)");

    create_machine("no-manual-yield-machine", "-- yield automatic rx-accepted 0",
        [](machine_config &config) { config.htif.yield_manual = false; });
    create_machine("no-automatic-yield-machine", "-- rollup accept",
        [](machine_config &config) { config.htif.yield_automatic = false; });
    create_machine("console-getchar-machine", "-- rollup accept",
        [](machine_config &config) { config.htif.console_getchar = true; });
    create_machine("no-rollup-machine", "-- yield manual rx-accepted 0",
        [](machine_config &config) { config.rollup.reset(); });

    // shared buffers
    create_machine("shared-rx-buffer-machine", "-- rollup accept",
        [](machine_config &config) { config.rollup->rx_buffer.shared = true; });
    create_machine("shared-tx-buffer-machine", "-- rollup accept",
        [](machine_config &config) { config.rollup->tx_buffer.shared = true; });
    create_machine("shared-input-metadata-machine", "-- rollup accept",
        [](machine_config &config) { config.rollup->input_metadata.shared = true; });
    create_machine("shared-voucher-hashes-machine", "-- rollup accept",
        [](machine_config &config) { config.rollup->voucher_hashes.shared = true; });
    create_machine("shared-notice-hashes-machine", "-- rollup accept",
        [](machine_config &config) { config.rollup->notice_hashes.shared = true; });
}

static StartSessionRequest create_valid_start_session_request(const std::string &name = "advance-state-machine") {
    // Convert to proto message
    StartSessionRequest session_request;
    std::string *machine_directory = session_request.mutable_machine_directory();
    *machine_directory = get_machine_directory("tests", name);

    session_request.set_session_id("test_session_request_id:" + std::to_string(new_session_id()));
    session_request.set_active_epoch_index(0);

    CyclesConfig *server_cycles = session_request.mutable_server_cycles();
    server_cycles->set_max_advance_state(UINT64_MAX >> 2);
    server_cycles->set_advance_state_increment(1 << 22);
    server_cycles->set_max_inspect_state(UINT64_MAX >> 2);
    server_cycles->set_inspect_state_increment(1 << 22);

    // Set server_deadline
    auto *server_deadline = session_request.mutable_server_deadline();
    server_deadline->set_checkin(1000ULL * 5);
    server_deadline->set_advance_state(1000ULL * 60 * 3);
    server_deadline->set_advance_state_increment(1000ULL * 10);
    server_deadline->set_inspect_state(1000ULL * 60 * 3);
    server_deadline->set_inspect_state_increment(1000ULL * 10);
    server_deadline->set_machine(1000ULL * 60);
    server_deadline->set_store(1000ULL * 60 * 3);
    server_deadline->set_fast(1000ULL * 5);

    return session_request;
}

// NOLINTNEXTLINE: ignore static initialization warning
static const std::string INPUT_ADDRESS_1 = "fafafafafafafafafafafafafafafafafafafafa";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_ADDRESS_1 = "000000000000000000000000fafafafafafafafafafafafafafafafafafafafa";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_OFFSET_1 = "0000000000000000000000000000000000000000000000000000000000000040";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_LENGTH_1 = "0000000000000000000000000000000000000000000000000000000000000080";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_PAYLOAD_1 = "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765720000";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_KECCAK_1 = "028c8a06ce878fcd02522f0ca3174f9e6fe7c9267750a0c45844e597e7cbab03";

// NOLINTNEXTLINE: ignore static initialization warning
static const std::string INPUT_ADDRESS_2 = "babababababababababababababababababababa";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_ADDRESS_2 = "000000000000000000000000babababababababababababababababababababa";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_OFFSET_2 = "0000000000000000000000000000000000000000000000000000000000000040";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_LENGTH_2 = "0000000000000000000000000000000000000000000000000000000000000020";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_PAYLOAD_2 = "4c6f72656d20697073756d20646f6c6f722073697420616d657420637261732e";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string VOUCHER_KECCAK_2 = "4af9ac1565a66632741c1cf848847920ae4ef6e7e96ef9fd5bae9fa316f5cb33";

// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_OFFSET_1 = "0000000000000000000000000000000000000000000000000000000000000020";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_LENGTH_1 = VOUCHER_LENGTH_1;
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_PAYLOAD_1 = VOUCHER_PAYLOAD_1;
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_KECCAK_1 = "253f38cb583d6aba613e7f75bde205c74280bd321be826b93eb41a5404c1f508";

// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_OFFSET_2 = "0000000000000000000000000000000000000000000000000000000000000020";
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_LENGTH_2 = VOUCHER_LENGTH_2;
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_PAYLOAD_2 = VOUCHER_PAYLOAD_2;
// NOLINTNEXTLINE: ignore static initialization warning
static const std::string NOTICE_KECCAK_2 = "8c35a8e6f7e96bf5b0f9200e6cf35db282e9de960e9e958c5d52b14a66af6c47";

static void hex_string_to_binary(const std::string &input, std::string &dest) {
#ifndef __clang_analyzer__
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(dest))); // NOLINT: suppress cryptopp warnings
#else
    (void) input;
    (void) dest;
#endif
}

static std::string get_voucher_keccak(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? VOUCHER_KECCAK_2 : VOUCHER_KECCAK_1, value);
    return value;
}

static std::string get_voucher_address(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? INPUT_ADDRESS_2 : INPUT_ADDRESS_1, value);
    return value;
}

static std::string get_voucher_payload(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? VOUCHER_PAYLOAD_2 : VOUCHER_PAYLOAD_1, value);
    return value;
}

static std::string get_notice_keccak(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? NOTICE_KECCAK_2 : NOTICE_KECCAK_1, value);
    return value;
}

static std::string get_notice_payload(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? VOUCHER_PAYLOAD_2 : VOUCHER_PAYLOAD_1, value);
    return value;
}

static std::string get_report_payload(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? VOUCHER_PAYLOAD_2 : VOUCHER_PAYLOAD_1, value);
    return value;
}

static inline int ilog2(uint64_t v) {
    return 63 - __builtin_clzll(v);
}

static cryptopp_keccak_256_hasher::hash_type get_data_hash(cryptopp_keccak_256_hasher &h, int log2_root_size,
    const std::string &data) {
    cartesi::complete_merkle_tree tree{log2_root_size, LOG2_WORD_SIZE, LOG2_WORD_SIZE};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data_c_str = reinterpret_cast<const unsigned char *>(data.c_str());
    uint64_t leaf_size = UINT64_C(1) << LOG2_WORD_SIZE;
    for (uint64_t i = 0; i < data.size(); i += leaf_size) {
        // Compute leaf hash
        auto leaf_hash = get_leaf_hash(h, data_c_str + i, 3, 3);
        // Add leaf to the tree
        tree.push_back(leaf_hash);
    }
    return tree.get_root_hash();
}

static cryptopp_keccak_256_hasher::hash_type get_voucher_keccak_hash(cryptopp_keccak_256_hasher &h, uint64_t index) {
    std::string keccak = get_voucher_keccak(index);
    return get_data_hash(h, LOG2_KECCAK_SIZE, keccak);
}

static cryptopp_keccak_256_hasher::hash_type get_notice_keccak_hash(cryptopp_keccak_256_hasher &h, uint64_t index) {
    std::string keccak = get_notice_keccak(index);
    return get_data_hash(h, LOG2_KECCAK_SIZE, keccak);
}

static cryptopp_keccak_256_hasher::hash_type get_voucher_root_hash(cryptopp_keccak_256_hasher &h, uint64_t index,
    uint64_t count) {
    std::string metadata_content;
    for (uint64_t i = 0; i < count; i++) {
        metadata_content += get_voucher_keccak(index);
    }
    return get_data_hash(h, ilog2(MEMORY_REGION_LENGTH), metadata_content);
}

static cryptopp_keccak_256_hasher::hash_type get_notice_root_hash(cryptopp_keccak_256_hasher &h, uint64_t index,
    uint64_t count) {
    std::string metadata_content;
    for (uint64_t i = 0; i < count; i++) {
        metadata_content += get_notice_keccak(index);
    }
    return get_data_hash(h, ilog2(MEMORY_REGION_LENGTH), metadata_content);
}

static void init_valid_advance_state_request(AdvanceStateRequest &request, const std::string &session_id,
    uint64_t epoch, uint64_t input_index) {
    request.set_session_id(session_id);
    request.set_active_epoch_index(epoch);
    request.set_current_input_index(input_index);

    static uint64_t block_number = 1;
    auto *input_metadata = request.mutable_input_metadata();
    auto *address = input_metadata->mutable_msg_sender()->mutable_data();
    *address = get_voucher_address(input_index);
    input_metadata->set_block_number(block_number);
    input_metadata->set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    input_metadata->set_epoch_index(epoch);
    input_metadata->set_input_index(input_index);

    auto *input_payload = request.mutable_input_payload();
    *input_payload = get_voucher_payload(input_index); // NOLINT: suppres crytopp warnings
}

static void init_valid_inspect_state_request(InspectStateRequest &request, const std::string &session_id,
    uint64_t input) {
    request.set_session_id(session_id);

    auto *query_payload = request.mutable_query_payload();
    *query_payload = get_report_payload(input); // NOLINT: suppres crytopp warnings
}

static void init_valid_finish_epoch_request(FinishEpochRequest &epoch_request, const std::string &session_id,
    uint64_t epoch, uint64_t processed_input_count, const std::string &dir = std::string{}) {
    epoch_request.set_session_id(session_id);
    epoch_request.set_active_epoch_index(epoch);
    epoch_request.set_processed_input_count(processed_input_count);
    if (!dir.empty()) {
        auto *storage_directory = epoch_request.mutable_storage_directory();
        (*storage_directory) = dir;
    }
}

static void assert_status(Status &status, const std::string &rpcname, bool expected, const std::string &file,
    int line) {
    if (status.ok() != expected) {
        if (expected) {
            throw std::runtime_error("Call to " + rpcname + " failed. Code: " + std::to_string(status.error_code()) +
                " Message: " + status.error_message() + ". Assert at " + file + ":" + std::to_string(line));
        }
        throw std::runtime_error("Call to " + rpcname + " succeded when was expected to fail. Assert at " + file + ":" +
            std::to_string(line));
    }
}

static void assert_status_code(const Status &status, const std::string &rpcname, grpc::StatusCode expected,
    const std::string &file, int line) {
    if (status.error_code() != expected) {
        throw std::runtime_error(rpcname + " was expected to fail with Code: " + std::to_string(expected) +
            " but received " + std::to_string(status.error_code()) + " Message: " + status.error_message() +
            ". Assert at " + file + ":" + std::to_string(line));
    }
}

void assert_bool(bool value, const std::string &msg, const std::string &file, int line) {
    if (!value) {
        throw std::runtime_error(msg + ". Assert at " + file + ":" + std::to_string(line));
    }
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ASSERT(v, msg) assert_bool(v, msg, __FILE__, __LINE__)
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ASSERT_STATUS(s, f, v) assert_status(s, f, v, __FILE__, __LINE__)
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ASSERT_STATUS_CODE(s, f, v) assert_status_code(s, f, v, __FILE__, __LINE__)

static void test_get_version(const std::function<void(const std::string &title, test_function f)> &test) {
    test("The server-manager server version should be 0.4.x", [](ServerManagerClient &manager) {
        Versioning::GetVersionResponse response;
        Status status = manager.get_version(response);
        ASSERT_STATUS(status, "GetVersion", true);
        ASSERT((response.version().major() == 0), "Version Major should be 0");
        ASSERT((response.version().minor() == 4), "Version Minor should be 4");
    });
}

static void test_start_session(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete a request with a invalid session id", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        session_request.clear_session_id();
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a 2nd request with same session id", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // repeat request
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::ALREADY_EXISTS);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should be able to reutilise an session id", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // repeat request
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete a request with a invalid machine request", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        // clear machine request
        session_request.clear_machine_directory();
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when first yield reason is not accepted or rejected",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("init-exception-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete when config.htif.yield_manual = false", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("no-manual-yield-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when config.htif.yield_automatic = false", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("no-automatic-yield-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when config.htif.console_getchar = true", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("console-getchar-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when machine config rollup is undefined", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("no-rollup-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if any of the rollup memory regions are shared", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("shared-rx-buffer-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);

        session_request = create_valid_start_session_request("shared-tx-buffer-machine");
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);

        session_request = create_valid_start_session_request("shared-input-metadata-machine");
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);

        session_request = create_valid_start_session_request("shared-voucher-hashes-machine");
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);

        session_request = create_valid_start_session_request("shared-notice-hashes-machine");
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if active epoch is on the limit", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        session_request.set_active_epoch_index(UINT64_MAX);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);

        session_request.set_active_epoch_index(UINT64_MAX - 1);
        status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete a request with an undefined server_cycles", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        // clear server_cycles
        session_request.clear_server_cycles();
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request if server_cycles.max_advance_state == 0", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        auto *server_cycles = session_request.mutable_server_cycles();
        server_cycles->set_max_advance_state(0);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request if server_cycles.advance_state_increment == 0",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_advance_state_increment(0);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete a request if server_cycles.max_advance_state < server_cycles.advance_state_increment",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_max_advance_state(server_cycles->advance_state_increment() - 1);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete a request if server_cycles.max_inspect_state == 0", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        auto *server_cycles = session_request.mutable_server_cycles();
        server_cycles->set_max_inspect_state(0);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request if server_cycles.inspect_state_increment == 0",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_inspect_state_increment(0);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete a request if server_cycles.max_inspect_state < server_cycles.inspect_state_increment",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_max_inspect_state(server_cycles->inspect_state_increment() - 1);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete a request with an undefined server_deadline", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        // clear server_deadline
        session_request.clear_server_deadline();
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request if server_deadline.advance_state < server_deadline.advance_state_increment",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_deadline = session_request.mutable_server_deadline();
            server_deadline->set_advance_state(server_deadline->advance_state_increment() - 1);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });

    test("Should fail to complete a request if server_deadline.inspect_state < server_deadline.inspect_state_increment",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            auto *server_deadline = session_request.mutable_server_deadline();
            server_deadline->set_inspect_state(server_deadline->inspect_state_increment() - 1);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", false);
            ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
        });
}

static void wait_pending_inputs_to_be_processed(ServerManagerClient &manager, GetEpochStatusRequest &status_request,
    GetEpochStatusResponse &status_response, bool accept_tainted, int retries) {
    for (;;) {
        Status status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        ASSERT(accept_tainted || !status_response.has_taint_status(), "tainted session was not expected");
        if (accept_tainted && status_response.has_taint_status()) {
            break;
        }

        if (status_response.pending_input_count() == 0) {
            break;
        }

        ASSERT((retries > 0), "wait_pending_inputs_to_be_processed max retries reached");
        std::this_thread::sleep_for(3s);
        retries--;
    }
}

static void end_session_after_processing_pending_inputs(ServerManagerClient &manager, const std::string &session_id,
    uint64_t epoch, bool accept_tainted = false) {
    GetEpochStatusRequest status_request;
    GetEpochStatusResponse status_response;

    status_request.set_session_id(session_id);
    status_request.set_epoch_index(epoch);
    wait_pending_inputs_to_be_processed(manager, status_request, status_response, accept_tainted, 10);

    // finish epoch
    if ((!accept_tainted && !status_response.has_taint_status()) && (status_response.state() != EpochState::FINISHED) &&
        (status_response.processed_inputs_size() != 0)) {
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, status_request.session_id(), status_request.epoch_index(),
            status_response.processed_inputs_size());
        Status status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);
    }

    // EndSession
    EndSessionRequest end_session_request;
    end_session_request.set_session_id(session_id);
    Status status = manager.end_session(end_session_request);
    ASSERT_STATUS(status, "EndSession", true);
}

static void test_advance_state(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should complete two valid requests with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // enqueue second
        advance_request.set_current_input_index(advance_request.current_input_index() + 1);
        auto *input_metadata = advance_request.mutable_input_metadata();
        input_metadata->set_input_index(advance_request.current_input_index());
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should not be able to enqueue two identical requests", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // repeated
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should fail to complete if session id is not valid", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        advance_request.set_session_id("NON-EXISTENT");
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session was ended", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // try to enqueue input on ended session
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if epoch is not the same", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        // change epoch index
        advance_request.set_active_epoch_index(advance_request.active_epoch_index() + 1);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if epoch is finished", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // try to enqueue input on ended session
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with success enqueing on a new epoch", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index() + 1, 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index() + 1);
    });

    test("Should fail to complete if active epoch is on the limit", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        session_request.set_active_epoch_index(UINT64_MAX - 1);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index() + 1, 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::OUT_OF_RANGE);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if the input index are not sequential", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // enqueue wrong input index
        advance_request.set_current_input_index(advance_request.current_input_index() + 10);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should fail to complete input metadata is missing", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        advance_request.clear_input_metadata();
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete input metadata msg_sender is missing", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        advance_request.mutable_input_metadata()->clear_msg_sender();
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete input metadata msg_sender greater then 20 bytes", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        auto *msg_sender = advance_request.mutable_input_metadata()->mutable_msg_sender();
        msg_sender->mutable_data()->append("fafafa");
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete input metadata epoch index does not match active epoch index",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            advance_request.mutable_input_metadata()->set_epoch_index(session_request.active_epoch_index() + 1);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", false);
            ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

            // finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            advance_request.mutable_input_metadata()->set_epoch_index(session_request.active_epoch_index());
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", false);

            // end session
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should fail to complete input metadata input index does not match active epoch index",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 1);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", false);
            ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

            // finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            advance_request.mutable_input_metadata()->set_epoch_index(session_request.active_epoch_index() + 1);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", false);

            // end session
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should fail to complete input payload does not fit the memory range", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        auto *input_payload = advance_request.mutable_input_payload();
        input_payload->resize(session_response.config().rollup().rx_buffer().length() + 1, 'x');
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", false);
        ASSERT_STATUS_CODE(status, "AdvanceState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });
}

static void test_get_status(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        GetStatusResponse status_response;
        Status status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 0, "status response should be empty");
    });

    test("Should complete with success when there is one session", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        GetStatusResponse status_response;
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);

        ASSERT(status_response.session_id_size() == 1, "status response should have only one session");
        ASSERT(status_response.session_id()[0] == session_request.session_id(),
            "status response  first session_id should be the same as the one created");

        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 0, "status response should have no sessions");
    });

    test("Should complete with success when there is two sessions", [](ServerManagerClient &manager) {
        // Create 1st session
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // Get status
        GetStatusResponse status_response;
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 1, "status response should have only one session");
        ASSERT(status_response.session_id()[0] == session_request.session_id(),
            "status response  first session_id should be the same as the first created");

        // Create 2nd session
        StartSessionRequest session_request2 = create_valid_start_session_request();
        StartSessionResponse session_response2;
        status = manager.start_session(session_request2, session_response2);
        ASSERT_STATUS(status, "StartSession", true);

        // Get status
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 2, "status response should have 2 sessions");

        // End 1st session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // Get status
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 1, "status response should have 2 sessions");
        ASSERT(status_response.session_id()[0] == session_request2.session_id(),
            "status response  first session_id should be the same as the second created");

        // End 2nd session
        end_session_request.set_session_id(session_request2.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // Get status
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 0, "status response should have no sessions");
    });
}

static void test_get_session_status(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(),
            "status response active_epoch_index should be the same as the one created");
        ASSERT(status_response.epoch_index_size() == 1, "status response should no old epochs");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with a invalid session id", [](ServerManagerClient &manager) {
        GetSessionStatusRequest status_request;
        status_request.set_session_id("NON-EXISTENT");
        GetSessionStatusResponse status_response;
        Status status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", false);
        ASSERT_STATUS_CODE(status, "GetSessionStatus", StatusCode::INVALID_ARGUMENT);
    });

    test("Should report epoch index correctly after FinishEpoch", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // GetSessionStatus
        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(),
            "status response active_epoch_index should be the same as the one created");
        ASSERT(status_response.epoch_index_size() == 1, "status response epoch_indices size should be 1");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // GetSessionStatus
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index() + 1,
            "status response active_epoch_index should be 1");
        ASSERT(status_response.epoch_index_size() == 2, "status response epoch_indices size should be 2");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // finish epoch
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index() + 1, 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // GetSessionStatus
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index() + 2,
            "status response active_epoch_index should be 2");
        ASSERT(status_response.epoch_index_size() == 3, "status response epoch_indices size should be 3");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with session taint_status code DEADLINE_EXCEEDED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_advance_state_increment(1);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        std::this_thread::sleep_for(10s);

        // GetSessionStatus
        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(),
            "status response active_epoch_index should be the same as the one created");
        ASSERT(status_response.epoch_index_size() == 1, "status response epoch_indices size should be 1");
        ASSERT(status_response.has_taint_status(), "status response should have a taint_status");
        ASSERT(status_response.taint_status().error_code() == StatusCode::DEADLINE_EXCEEDED,
            "taint_status code should be DEADLINE_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index(), true);
    });
}

static void check_processed_input(ProcessedInput &processed_input, uint64_t index, int voucher_count, int notice_count,
    int report_count) {
    // processed_input
    ASSERT(processed_input.input_index() == index, "processed input index should sequential");
    ASSERT(processed_input.has_most_recent_machine_hash(), "processed input should contain a most_recent_machine_hash");
    ASSERT(!processed_input.most_recent_machine_hash().data().empty(),
        "processed input should contain a most_recent_machine_hash and it should not be empty");
    ASSERT(processed_input.has_voucher_hashes_in_epoch(), "result should have voucher_hashes_in_epoch");
    ASSERT(processed_input.has_notice_hashes_in_epoch(), "result should have notice_hashes_in_epoch");
    ASSERT(processed_input.reports_size() == report_count,
        "processed input reports size should be equal to report_count");
    ASSERT(processed_input.status() == CompletionStatus::ACCEPTED, "processed input status should be ACCEPTED");
    ASSERT(processed_input.has_accepted_data(), "processed input should contain accepted data");

    const auto &result = processed_input.accepted_data();
    ASSERT(result.has_voucher_hashes_in_machine(), "result should have voucher_hashes_in_machine");
    ASSERT(result.vouchers_size() == voucher_count, "result outputs size should be equal to output_count");
    ASSERT(result.has_notice_hashes_in_machine(), "result should have notice_hashes_in_machine");
    ASSERT(result.notices_size() == notice_count, "result messages size should be equal to message_count");

    // verify proofs
    cryptopp_keccak_256_hasher h;
    auto voucher_root_hash = get_voucher_root_hash(h, index, result.vouchers_size());
    auto notice_root_hash = get_notice_root_hash(h, index, result.notices_size());
    auto metadata_log2_size = ilog2(MEMORY_REGION_LENGTH);
    cartesi::complete_merkle_tree vouchers_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
    cartesi::complete_merkle_tree notices_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};

    for (uint64_t i = 0; i <= index; i++) {
        auto voucher_root_hash = get_voucher_root_hash(h, i, result.vouchers_size());
        auto notice_root_hash = get_notice_root_hash(h, i, result.notices_size());
        vouchers_tree.push_back(voucher_root_hash);
        notices_tree.push_back(notice_root_hash);
    }

    auto voucher_hashes_in_machine_proof = get_proto_proof(result.voucher_hashes_in_machine());
    ASSERT(voucher_hashes_in_machine_proof.get_log2_target_size() == metadata_log2_size,
        "voucher_hashes_in_machine log2 target size should match");
    ASSERT(voucher_hashes_in_machine_proof.get_target_hash() == voucher_root_hash,
        "voucher_hashes_in_machine target hash should match");
    ASSERT(voucher_hashes_in_machine_proof.verify(h), "voucher_hashes_in_machine proof should be valid");

    auto calculated_vouchers_in_epoch_proof = vouchers_tree.get_proof(index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
    auto vouchers_in_epoch_proof = get_proto_proof(processed_input.voucher_hashes_in_epoch());
    ASSERT(vouchers_in_epoch_proof.get_log2_target_size() == calculated_vouchers_in_epoch_proof.get_log2_target_size(),
        "vouchers_hashes_in_epoch log2 target size should match");
    ASSERT(vouchers_in_epoch_proof.get_target_hash() == calculated_vouchers_in_epoch_proof.get_target_hash(),
        "vouchers_hashes_in_epoch target hash should match");
    ASSERT(vouchers_in_epoch_proof.get_log2_root_size() == calculated_vouchers_in_epoch_proof.get_log2_root_size(),
        "vouchers_hashes_in_epoch log2 root size should match");
    ASSERT(vouchers_in_epoch_proof.get_root_hash() == calculated_vouchers_in_epoch_proof.get_root_hash(),
        "vouchers_hashes_in_epoch root hash should match");
    ASSERT(vouchers_in_epoch_proof.verify(h), "vouchers_in_epoch proof should be valid");

    auto notice_hashes_in_machine_proof = get_proto_proof(result.notice_hashes_in_machine());
    ASSERT(notice_hashes_in_machine_proof.get_log2_target_size() == metadata_log2_size,
        "notices_hashes_in_machine log2 target size should match");
    ASSERT(notice_hashes_in_machine_proof.get_target_hash() == notice_root_hash,
        "notices_hashes_in_machine target hash should match");
    ASSERT(notice_hashes_in_machine_proof.verify(h), "notices_hashes_in_machine proof should be valid");

    auto calculated_notices_in_epoch_proof = notices_tree.get_proof(index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
    auto notice_hashes_in_epoch_proof = get_proto_proof(processed_input.notice_hashes_in_epoch());
    ASSERT(notice_hashes_in_epoch_proof.get_log2_target_size() ==
            calculated_notices_in_epoch_proof.get_log2_target_size(),
        "notices_hashes_in_epoch log2 target size should match");
    ASSERT(notice_hashes_in_epoch_proof.get_target_hash() == calculated_notices_in_epoch_proof.get_target_hash(),
        "notices_hashes_in_epoch target hash should match");
    ASSERT(notice_hashes_in_epoch_proof.get_log2_root_size() == calculated_notices_in_epoch_proof.get_log2_root_size(),
        "notices_hashes_in_epoch log2 root size should match");
    ASSERT(notice_hashes_in_epoch_proof.get_root_hash() == calculated_notices_in_epoch_proof.get_root_hash(),
        "notices_hashes_in_epoch root hash should match");
    ASSERT(notice_hashes_in_epoch_proof.verify(h), "notices_hashes_in_epoch proof should be valid");

    // reports
    for (const auto &report : processed_input.reports()) {
        ASSERT(!report.payload().empty(), "report payload should not be empty");
        ASSERT(report.payload() == get_report_payload(index), "report payload should match");
    }

    // vouchers
    for (const auto &voucher : result.vouchers()) {
        ASSERT(voucher.has_keccak() && !voucher.keccak().data().empty(), "voucher should have a keccak hash");
        ASSERT(voucher.has_address(), "voucher should have an address");
        ASSERT(!voucher.payload().empty(), "voucher payload should not be empty");
        ASSERT(voucher.has_keccak_in_voucher_hashes(), "voucher should have keccak_in_voucher_hashes");
        ASSERT(voucher.keccak().data() == get_voucher_keccak(index), "voucher keccak should match");
        ASSERT(voucher.address().data() == get_voucher_address(index), "voucher address should match");
        ASSERT(voucher.payload() == get_voucher_payload(index), "voucher payload should match");
        auto keccak_proof = get_proto_proof(voucher.keccak_in_voucher_hashes());
        ASSERT(keccak_proof.get_log2_target_size() == LOG2_KECCAK_SIZE,
            "keccak_in_voucher_hashes log2 target size should match");
        ASSERT(keccak_proof.get_target_hash() == get_voucher_keccak_hash(h, index),
            "keccak_in_voucher_hashes target hash should match");
        ASSERT(keccak_proof.get_log2_root_size() == metadata_log2_size,
            "keccak_in_voucher_hashes log2 root size should match");
        ASSERT(keccak_proof.get_root_hash() == voucher_root_hash, "keccak_in_voucher_hashes root hash should match");
        ASSERT(keccak_proof.verify(h), "keccak_in_voucher_hashes proof should be valid");
    }

    // notices
    for (const auto &notice : result.notices()) {
        ASSERT(notice.has_keccak() && !notice.keccak().data().empty(), "notice should have a keccak hash");
        ASSERT(!notice.payload().empty(), "notice payload should not be empty");
        ASSERT(notice.has_keccak_in_notice_hashes(), "notice should have keccak_in_notice_hashes");
        ASSERT(notice.keccak().data() == get_notice_keccak(index), "notice keccak should match");
        ASSERT(notice.payload() == get_notice_payload(index), "notice payload should match");
        auto keccak_proof = get_proto_proof(notice.keccak_in_notice_hashes());
        ASSERT(keccak_proof.get_log2_target_size() == LOG2_KECCAK_SIZE,
            "keccak_in_notice_hashes log2 target size should match");
        ASSERT(keccak_proof.get_target_hash() == get_notice_keccak_hash(h, index),
            "keccak_in_notice_hashes target hash should match");
        ASSERT(keccak_proof.get_log2_root_size() == metadata_log2_size,
            "keccak_in_notice_hashes log2 root size should match");
        ASSERT(keccak_proof.get_root_hash() == notice_root_hash, "keccak_in_notice_hashes root hash should match");
        ASSERT(keccak_proof.verify(h), "keccak_in_notice_hashes proof should be valid");
    }
}

static void check_most_recent_epoch_root_hashes(const GetEpochStatusResponse &status_response) {
    auto most_recent_vouchers_epoch_root_hash = get_proto_hash(status_response.most_recent_vouchers_epoch_root_hash());
    auto most_recent_notices_epoch_root_hash = get_proto_hash(status_response.most_recent_notices_epoch_root_hash());
    if (status_response.processed_inputs_size() == 0) {
        cartesi::complete_merkle_tree tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
        ASSERT(most_recent_vouchers_epoch_root_hash == tree.get_root_hash(),
            "most_recent_vouchers_epoch_root_hash should match");
        ASSERT(most_recent_notices_epoch_root_hash == tree.get_root_hash(),
            "most_recent_notices_epoch_root_hash should match");
    } else {
        auto processed_input = (status_response.processed_inputs())[status_response.processed_inputs_size() - 1];
        auto vouchers_in_epoch_proof = get_proto_proof(processed_input.voucher_hashes_in_epoch());
        auto notice_hashes_in_epoch_proof = get_proto_proof(processed_input.notice_hashes_in_epoch());
        ASSERT(most_recent_vouchers_epoch_root_hash == vouchers_in_epoch_proof.get_root_hash(),
            "most_recent_vouchers_epoch_root_hash should match");
        ASSERT(most_recent_notices_epoch_root_hash == notice_hashes_in_epoch_proof.get_root_hash(),
            "most_recent_notices_epoch_root_hash should match");
    }
}

static void check_empty_epoch_status(const GetEpochStatusResponse &status_response, const std::string &session_id,
    uint64_t epoch_index, EpochState epoch_state, uint64_t pending_inputs) {
    cartesi::complete_merkle_tree merkle_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
    const auto empty_root_hash = merkle_tree.get_root_hash();
    ASSERT(status_response.session_id() == session_id,
        "status response session_id should be the same as the one created");
    ASSERT(status_response.epoch_index() == epoch_index,
        "status response epoch_index should be the same as the one created");
    ASSERT(status_response.state() == epoch_state, "status response state should be " + EpochState_Name(epoch_state));
    ASSERT(status_response.has_most_recent_machine_hash(), "status response should have most_recent_machine_hash");
    ASSERT(status_response.has_most_recent_vouchers_epoch_root_hash(),
        "status response should have most_recent_vouchers_epoch_root_hash");
    ASSERT(status_response.has_most_recent_notices_epoch_root_hash(),
        "status response should have most_recent_notices_epoch_root_hash");
    ASSERT(get_proto_hash(status_response.most_recent_vouchers_epoch_root_hash()) == empty_root_hash,
        "status response most_recent_vouchers_epoch_root_hash should match");
    ASSERT(get_proto_hash(status_response.most_recent_notices_epoch_root_hash()) == empty_root_hash,
        "status response most_recent_notices_epoch_root_hash should match");
    ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
    ASSERT(status_response.pending_input_count() == pending_inputs,
        "status response pending_input_count should be " + std::to_string(pending_inputs));
    ASSERT(!status_response.has_taint_status(), "status response should not be tainted");
    check_most_recent_epoch_root_hashes(status_response);
}

static void test_get_epoch_status(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        check_empty_epoch_status(status_response, session_request.session_id(), session_request.active_epoch_index(),
            EpochState::ACTIVE, 0);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with a invalid session id", [](ServerManagerClient &manager) {
        GetEpochStatusRequest status_request;
        status_request.set_session_id("NON-EXISTENT");
        status_request.set_epoch_index(0);
        GetEpochStatusResponse status_response;
        Status status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", false);
        ASSERT_STATUS_CODE(status, "GetEpochStatus", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with a ended session id", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // try to enqueue input on ended session
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", false);
        ASSERT_STATUS_CODE(status, "GetEpochStatus", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if epoch index is not valid", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index() + 10);
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", false);
        ASSERT_STATUS_CODE(status, "GetEpochStatus", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with success with a valid session id and valid old epoch", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // status on old epoch
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        check_empty_epoch_status(status_response, session_request.session_id(), session_request.active_epoch_index(),
            EpochState::FINISHED, 0);

        // status on current epoch
        status_request.set_epoch_index(session_request.active_epoch_index() + 1);
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        check_empty_epoch_status(status_response, session_request.session_id(),
            session_request.active_epoch_index() + 1, EpochState::ACTIVE, 0);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with pending input count equal 1 after AdvanceState", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        check_empty_epoch_status(status_response, session_request.session_id(), session_request.active_epoch_index(),
            EpochState::ACTIVE, 1);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should complete with processed input count equal 1 after processing enqueued input",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 2, 2, 2);
            check_most_recent_epoch_root_hashes(status_response);

            // Finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), status_response.processed_inputs_size());
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            // EndSession
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should complete with processed input count equal 1 after processing enqueued input on new epoch",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index() + 1, 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index() + 1);
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index() + 1,
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 2, 2, 2);
            check_most_recent_epoch_root_hashes(status_response);

            // Finish epoch
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index() + 1, status_response.processed_inputs_size());
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            // EndSession
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should complete with processed input count equal 1 after processing enqueued input (empty payload)",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("no-output-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            advance_request.clear_input_payload();
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 0, 0, 0);
            check_most_recent_epoch_root_hashes(status_response);

            // Finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), status_response.processed_inputs_size());
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            // EndSession
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should fail to complete an taint the session when manual yield reason is TX-EXCEPTION",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("exception-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, true, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed input index should sequential");
            ASSERT(processed_input.has_most_recent_machine_hash(),
                "processed input should contain a most_recent_machine_hash");
            ASSERT(!processed_input.most_recent_machine_hash().data().empty(),
                "processed input should contain a most_recent_machine_hash and it should not be empty");
            ASSERT(processed_input.has_voucher_hashes_in_epoch(), "result should have voucher_hashes_in_epoch");
            ASSERT(processed_input.has_notice_hashes_in_epoch(), "result should have notice_hashes_in_epoch");
            ASSERT(processed_input.reports_size() == 0, "processed input reports size should be equal to report_count");
            ASSERT(processed_input.status() == CompletionStatus::EXCEPTION,
                "processed input status should be EXCEPTION");
            ASSERT(processed_input.has_exception_data(), "processed input should contain exception data");
            ASSERT(processed_input.exception_data() == "test payload",
                "exception data should contain the expected payload");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index(), false);
        });

    test("Should complete with CompletionStatus EXCEPTION after fatal error", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("fatal-error-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
            "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
        ASSERT(processed_input.has_most_recent_machine_hash(),
            "processed input should contain a most_recent_machine_hash");
        ASSERT(!processed_input.most_recent_machine_hash().data().empty(),
            "processed input should contain a most_recent_machine_hash and it should not be empty");
        ASSERT(processed_input.has_voucher_hashes_in_epoch(), "result should have voucher_hashes_in_epoch");
        ASSERT(processed_input.has_notice_hashes_in_epoch(), "result should have notice_hashes_in_epoch");
        ASSERT(processed_input.reports_size() == 0, "processed input reports size should be equal to report_count");
        ASSERT(processed_input.status() == CompletionStatus::EXCEPTION, "processed input status should be EXCEPTION");
        ASSERT(processed_input.has_exception_data(), "processed input should contain exception data");
        ASSERT(processed_input.exception_data() == "dapp exited with exit status: 2",
            "exception data should contain the expected payload");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should complete with CompletionStatus EXCEPTION after rollup-http-server error",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("http-server-error-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
            ASSERT(processed_input.has_most_recent_machine_hash(),
                "processed input should contain a most_recent_machine_hash");
            ASSERT(!processed_input.most_recent_machine_hash().data().empty(),
                "processed input should contain a most_recent_machine_hash and it should not be empty");
            ASSERT(processed_input.has_voucher_hashes_in_epoch(), "result should have voucher_hashes_in_epoch");
            ASSERT(processed_input.has_notice_hashes_in_epoch(), "result should have notice_hashes_in_epoch");
            ASSERT(processed_input.reports_size() == 0, "processed input reports size should be equal to report_count");
            ASSERT(processed_input.status() == CompletionStatus::EXCEPTION,
                "processed input status should be EXCEPTION");
            ASSERT(processed_input.has_exception_data(), "processed input should contain exception data");
            ASSERT(processed_input.exception_data() == "rollup-http-server exited with 0 status",
                "exception data should contain the expected payload");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with first processed input as CompletionStatus CYCLE_LIMIT_EXCEEDED",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            CyclesConfig *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_max_advance_state(2);
            server_cycles->set_advance_state_increment(2);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            std::this_thread::sleep_for(5s);

            // get epoch status
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            status = manager.get_epoch_status(status_request, status_response);
            ASSERT_STATUS(status, "GetEpochStatus", true);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
            ASSERT(processed_input.status() == CompletionStatus::CYCLE_LIMIT_EXCEEDED,
                "CompletionStatus should be CYCLE_LIMIT_EXCEEDED");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with first processed input as CompletionStatus TIME_LIMIT_EXCEEDED",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            CyclesConfig *server_cycles = session_request.mutable_server_cycles();
            server_cycles->set_advance_state_increment(10);
            auto *server_deadline = session_request.mutable_server_deadline();
            server_deadline->set_advance_state(1000);
            server_deadline->set_advance_state_increment(1000);
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            std::this_thread::sleep_for(10s);

            // get epoch status
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            status = manager.get_epoch_status(status_request, status_response);
            ASSERT_STATUS(status, "GetEpochStatus", true);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
            ASSERT(processed_input.status() == CompletionStatus::TIME_LIMIT_EXCEEDED,
                "CompletionStatus should be TIME_LIMIT_EXCEEDED");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with session taint_status code DEADLINE_EXCEEDED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_advance_state_increment(1);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        std::this_thread::sleep_for(10s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
            "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 1, "status response pending_input_count should 1");
        ASSERT(status_response.has_taint_status(), "status response should have a taint_status");
        ASSERT(status_response.taint_status().error_code() == StatusCode::DEADLINE_EXCEEDED,
            "taint_status code should be DEADLINE_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index(), true);
    });

    test("Should complete with first processed input as CompletionStatus REJECTED_BY_MACHINE",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("advance-rejecting-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            std::this_thread::sleep_for(10s);

            // get epoch status
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            status = manager.get_epoch_status(status_request, status_response);
            ASSERT_STATUS(status, "GetEpochStatus", true);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
            ASSERT(processed_input.status() == CompletionStatus::REJECTED, "CompletionStatus should be REJECTED");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with first processed input as CompletionStatus MACHINE_HALTED",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("halting-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            std::this_thread::sleep_for(10s);

            // get epoch status
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            status = manager.get_epoch_status(status_request, status_response);
            ASSERT_STATUS(status, "GetEpochStatus", true);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            auto processed_input = (status_response.processed_inputs())[0];
            ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
            ASSERT(processed_input.status() == CompletionStatus::MACHINE_HALTED,
                "CompletionStatus should be MACHINE_HALTED");

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should return valid InputResults after request completed with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_response content
        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
            "status response epoch_index should be the same as the one created");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // processed_input
        auto processed_input = (status_response.processed_inputs())[0];
        check_processed_input(processed_input, 0, 2, 2, 2);
        check_most_recent_epoch_root_hashes(status_response);

        // end session
        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should return valid InputResults even when there is no outputs or messages",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("no-output-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_response content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be the same as the one created");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            // processed_input
            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 0, 0, 0);
            check_most_recent_epoch_root_hashes(status_response);

            // end session
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with success returning one voucher and no notices or reports",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("one-voucher-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_response content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be the same as the one created");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            // processed_input
            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 1, 0, 0);
            check_most_recent_epoch_root_hashes(status_response);

            // end session
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with success returning one notice and no vouchers or reports",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("one-notice-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_response content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be the same as the one created");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            // processed_input
            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 0, 1, 0);
            check_most_recent_epoch_root_hashes(status_response);

            // end session
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete with success returning one report and no notices or vouchers",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("one-report-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_response content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be the same as the one created");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            // processed_input
            auto processed_input = (status_response.processed_inputs())[0];
            check_processed_input(processed_input, 0, 0, 0, 1);
            check_most_recent_epoch_root_hashes(status_response);

            // end session
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });
}

static void check_inspect_state_response(InspectStateResponse &response, const std::string &session_id, uint64_t epoch,
    uint64_t input, int report_count, CompletionStatus status = CompletionStatus::ACCEPTED) {
    ASSERT(response.session_id() == session_id, "response session id should match");
    ASSERT(response.active_epoch_index() == epoch, "response epoch should match");
    ASSERT(response.status() == status, "response status should match");
    ASSERT(response.reports_size() == report_count, "response reports size should be equal to report_count");
    for (const auto &report : response.reports()) {
        ASSERT(!report.payload().empty(), "report payload should not be empty");
        ASSERT(report.payload() == get_report_payload(input), "report payload should match");
    }
}

static void test_inspect_state(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 2);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete two valid requests with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 2);

        // enqueue second
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 2);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete a valid request with success (empty payload)", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("no-output-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        inspect_request.clear_query_payload();
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus EXCEPTION when receiving a manual yield with reason TX-EXCEPTION",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("exception-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            InspectStateRequest inspect_request;
            init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
            InspectStateResponse inspect_response;
            status = manager.inspect_state(inspect_request, inspect_response);
            ASSERT_STATUS(status, "InspectState", true);

            check_inspect_state_response(inspect_response, inspect_request.session_id(),
                session_request.active_epoch_index(), 0, 0, CompletionStatus::EXCEPTION);

            ASSERT(inspect_response.has_exception_data(), "InspectResponse should containd exception data");
            ASSERT(inspect_response.exception_data() == "test payload",
                "exception_data should contain expected exception payload");
            // end session
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should complete with CompletionStatus EXCEPTION after fatal error", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("fatal-error-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0, CompletionStatus::EXCEPTION);

        ASSERT(inspect_response.has_exception_data(), "InspectResponse should containd exception data");
        ASSERT(inspect_response.exception_data() == "dapp exited with exit status: 2",
            "exception_data should contain expected exception payload");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus EXCEPTION after rollup-http-server error",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("http-server-error-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue first
            InspectStateRequest inspect_request;
            init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
            InspectStateResponse inspect_response;
            status = manager.inspect_state(inspect_request, inspect_response);
            ASSERT_STATUS(status, "InspectState", true);

            check_inspect_state_response(inspect_response, inspect_request.session_id(),
                session_request.active_epoch_index(), 0, 0, CompletionStatus::EXCEPTION);

            ASSERT(inspect_response.has_exception_data(), "InspectResponse should containd exception data");
            ASSERT(inspect_response.exception_data() == "rollup-http-server exited with 0 status",
                "exception_data should contain expected exception payload");

            // end session
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });

    test("Should complete a valid request with accept (voucher on inspect)", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("voucher-on-inspect-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete a valid request with accept (notice on inspect)", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("notice-on-inspect-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete a inspect state request enqueued after a advance state with success",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            InspectStateRequest inspect_request;
            init_valid_inspect_state_request(inspect_request, session_request.session_id(), 1);
            InspectStateResponse inspect_response;
            status = manager.inspect_state(inspect_request, inspect_response);
            ASSERT_STATUS(status, "InspectState", true);

            check_inspect_state_response(inspect_response, inspect_request.session_id(),
                session_request.active_epoch_index(), 1, 2);

            // enqueue second
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should complete a inspect state request enqueued during a advance state with success",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            InspectStateRequest inspect_request;
            init_valid_inspect_state_request(inspect_request, session_request.session_id(), 1);
            InspectStateResponse inspect_response;
            status = manager.inspect_state(inspect_request, inspect_response);
            ASSERT_STATUS(status, "InspectState", true);

            check_inspect_state_response(inspect_response, inspect_request.session_id(),
                session_request.active_epoch_index(), 1, 2);

            // enqueue second
            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });

    test("Should fail to complete if session id is not valid", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        inspect_request.set_session_id("NON-EXISTENT");
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", false);
        ASSERT_STATUS_CODE(status, "InspectState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session was ended", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // try to enqueue input on ended session
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", false);
        ASSERT_STATUS_CODE(status, "InspectState", StatusCode::INVALID_ARGUMENT);
    });

    test("Should complete with success enqueing on a new epoch", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 1);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index() + 1, 1, 2);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if query_payload is greater then rx buffer", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // try to enqueue input on fnished epoch
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        auto *query_payload = inspect_request.mutable_query_payload();
        query_payload->resize(session_response.config().rollup().rx_buffer().length(), 'f');
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", false);
        ASSERT_STATUS_CODE(status, "InspectState", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus CYCLE_LIMIT_EXCEEDED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        CyclesConfig *server_cycles = session_request.mutable_server_cycles();
        server_cycles->set_max_inspect_state(2);
        server_cycles->set_inspect_state_increment(2);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0, CompletionStatus::CYCLE_LIMIT_EXCEEDED);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus REJECTED_BY_MACHINE", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-rejecting-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0, CompletionStatus::REJECTED);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus MACHINE_HALTED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("halting-machine");
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0, CompletionStatus::MACHINE_HALTED);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with CompletionStatus TIME_LIMIT_EXCEEDED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        CyclesConfig *server_cycles = session_request.mutable_server_cycles();
        server_cycles->set_inspect_state_increment(10);
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_inspect_state(1000);
        server_deadline->set_inspect_state_increment(1000);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", true);

        check_inspect_state_response(inspect_response, inspect_request.session_id(),
            session_request.active_epoch_index(), 0, 0, CompletionStatus::TIME_LIMIT_EXCEEDED);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with Status DEADLINE_EXCEEDED", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request("inspect-state-machine");
        StartSessionResponse session_response;
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_inspect_state_increment(1);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        InspectStateRequest inspect_request;
        init_valid_inspect_state_request(inspect_request, session_request.session_id(), 0);
        InspectStateResponse inspect_response;
        status = manager.inspect_state(inspect_request, inspect_response);
        ASSERT_STATUS(status, "InspectState", false);
        ASSERT_STATUS_CODE(status, "InspectState", StatusCode::DEADLINE_EXCEEDED);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });
}

static bool check_session_store(const std::string &machine_dir) {
    static const std::vector<std::string> files = {"0000000000001000-f000.bin", "0000000060000000-200000.bin",
        "0000000060200000-200000.bin", "0000000060400000-1000.bin", "0000000060600000-200000.bin",
        "0000000060800000-200000.bin", "0000000080000000-4000000.bin", "8000000000000000-5000000.bin",
        "config.protobuf", "hash"};
    if (machine_dir.empty()) {
        return false;
    }
    path full_path{machine_dir};
    return std::all_of(files.begin(), files.end(),
        [&full_path](const std::string &f) { return exists(full_path / f); });
}

static void test_finish_epoch(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id is not valid", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        epoch_request.set_session_id("NON-EXISTENT");
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id was ended", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if epoch index is already finished", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if active epoch index is not match", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        epoch_request.set_active_epoch_index(epoch_request.active_epoch_index() + 10);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if active epoch is on the limit", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        session_request.set_active_epoch_index(UINT64_MAX - 1);
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // Go to active_epoch_index = UINT64_MAX
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // status
        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);
        ASSERT(status_response.active_epoch_index() == UINT64_MAX, "active epoch index should be UINT64_MAX");

        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::OUT_OF_RANGE);

        status_request.set_session_id(session_request.session_id());
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);
        ASSERT(status_response.active_epoch_index() == UINT64_MAX, "active epoch index should stop at UINT64_MAX");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if pending input count is not empty", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        epoch_request.set_processed_input_count(2);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);

        // end session
        end_session_after_processing_pending_inputs(manager, session_request.session_id(),
            session_request.active_epoch_index());
    });

    test("Should fail to complete if processed input count does not match", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        epoch_request.set_processed_input_count(10);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with success storing the machine", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_directory(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        ASSERT(check_session_store(machine_dir),
            "FinishEpoch should store machine to disk if storage directory is defined");
        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if the server does not have permission to write", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");
        ASSERT(change_storage_directory_permissions(storage_dir, false),
            "test should be able to change directory permissions");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_directory(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::ABORTED);

        ASSERT(!check_session_store(machine_dir),
            "FinishEpoch should store machine to disk if storage directory is defined");
        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with the directory already exists", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_directory(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        ASSERT(check_session_store(machine_dir),
            "FinishEpoch should store machine to disk if storage directory is defined");

        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index() + 1, 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::ABORTED);

        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("StartSession should complete with success from a previous stored the machine",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            std::string storage_dir{"sessions"};
            ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

            FinishEpochRequest epoch_request;
            std::string machine_dir = get_machine_directory(storage_dir, "test_" + manager.test_id());
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0, machine_dir);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            ASSERT(check_session_store(machine_dir),
                "FinishEpoch should store machine to disk if storage directory is defined");

            // end session
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);

            auto *stored_machine_dir = session_request.mutable_machine_directory();
            (*stored_machine_dir) = machine_dir;
            status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);

            ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");
        });

    test("Should complete with success when processed input count greater than 1", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);
        // enqueue second
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 1);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
            "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), status_response.processed_inputs_size());
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });
}

static void test_end_session(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id is not valid", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        EndSessionRequest end_session_request;
        end_session_request.set_session_id("NON-EXISTENT");
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", false);
        ASSERT_STATUS_CODE(status, "EndSession", StatusCode::INVALID_ARGUMENT);

        // end session
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id was already ended", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // same request again
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", false);
        ASSERT_STATUS_CODE(status, "EndSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete if session active epoch has pending or processed inputs",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", false);
            ASSERT_STATUS_CODE(status, "EndSession", StatusCode::INVALID_ARGUMENT);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", false);
            ASSERT_STATUS_CODE(status, "EndSession", StatusCode::INVALID_ARGUMENT);

            end_session_after_processing_pending_inputs(manager, session_request.session_id(),
                session_request.active_epoch_index());
        });
}

static void test_session_simulations(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should EndSession with success after processing two inputs on one epoch", [](ServerManagerClient &manager) {
        StartSessionRequest session_request = create_valid_start_session_request();
        StartSessionResponse session_response;
        Status status = manager.start_session(session_request, session_response);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue 0 epoch 0
        AdvanceStateRequest advance_request;
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 0);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);
        // enqueue 1 epoch 0
        init_valid_advance_state_request(advance_request, session_request.session_id(),
            session_request.active_epoch_index(), 1);
        status = manager.advance_state(advance_request);
        ASSERT_STATUS(status, "AdvanceState", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(),
            "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
            "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        uint64_t index = 0;
        for (auto processed_input : status_response.processed_inputs()) {
            check_processed_input(processed_input, index, 2, 2, 2);
            index++;
        }

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
            session_request.active_epoch_index(), status_response.processed_inputs_size());
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should EndSession with success after processing multiple inputs on multiple epochs",
        [](ServerManagerClient &manager) {
            StartSessionRequest session_request = create_valid_start_session_request();
            StartSessionResponse session_response;
            Status status = manager.start_session(session_request, session_response);
            ASSERT_STATUS(status, "StartSession", true);

            // enqueue 0 epoch 0
            AdvanceStateRequest advance_request;
            init_valid_advance_state_request(advance_request, session_request.session_id(), 0, 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);
            // enqueue 1 epoch 0
            init_valid_advance_state_request(advance_request, session_request.session_id(), 0, 1);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            // get epoch status after pending input is processed
            GetEpochStatusRequest status_request;
            status_request.set_session_id(session_request.session_id());
            status_request.set_epoch_index(session_request.active_epoch_index());
            GetEpochStatusResponse status_response;
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            // assert status_resonse content
            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == session_request.active_epoch_index(),
                "status response epoch_index should be 0");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            uint64_t index = 0;
            for (auto processed_input : status_response.processed_inputs()) {
                check_processed_input(processed_input, index, 2, 2, 2);
                index++;
            }

            // Finish epoch
            FinishEpochRequest epoch_request;
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(), 0, 2);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            // enqueue 0 epoch 1
            init_valid_advance_state_request(advance_request, session_request.session_id(), 1, 0);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);
            // enqueue 1 epoch 1
            init_valid_advance_state_request(advance_request, session_request.session_id(), 1, 1);
            status = manager.advance_state(advance_request);
            ASSERT_STATUS(status, "AdvanceState", true);

            status_request.set_epoch_index(1);
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == 1, "status response epoch_index should be 1");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            index = 0;
            for (auto processed_input : status_response.processed_inputs()) {
                check_processed_input(processed_input, index, 2, 2, 2);
                index++;
            }

            // Finish epoch
            init_valid_finish_epoch_request(epoch_request, session_request.session_id(), 1, 2);
            status = manager.finish_epoch(epoch_request);
            ASSERT_STATUS(status, "FinishEpoch", true);

            status_request.set_epoch_index(2);
            wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

            ASSERT(status_response.session_id() == session_request.session_id(),
                "status response session_id should be the same as the one created");
            ASSERT(status_response.epoch_index() == 2, "status response epoch_index should be 2");
            ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
            ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
            ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
            ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

            // EndSession
            EndSessionRequest end_session_request;
            end_session_request.set_session_id(session_request.session_id());
            status = manager.end_session(end_session_request);
            ASSERT_STATUS(status, "EndSession", true);
        });
}

static void test_health_check(const std::function<void(const std::string &title, test_function f)> &test) {
    test("The server-manager server health status should be SERVING", [](ServerManagerClient &manager) {
        HealthCheckRequest request;
        HealthCheckResponse response;
        auto *service = request.mutable_service();
        *service = "";
        Status status = manager.health_check(request, response);
        ASSERT_STATUS(status, "HealthCheck", true);
        ASSERT((response.status() == HealthCheckResponse_ServingStatus_SERVING), "Version Major should be 0");
    });

    test("The server-manager ServerManager service health status should be SERVING", [](ServerManagerClient &manager) {
        HealthCheckRequest request;
        HealthCheckResponse response;
        auto *service = request.mutable_service();
        *service = ServerManager::service_full_name();
        Status status = manager.health_check(request, response);
        ASSERT_STATUS(status, "HealthCheck", true);
        ASSERT((response.status() == HealthCheckResponse_ServingStatus_SERVING), "Version Major should be 0");
    });

    test("The server-manager ManagerCheckIn service health status should be SERVING", [](ServerManagerClient &manager) {
        HealthCheckRequest request;
        HealthCheckResponse response;
        auto *service = request.mutable_service();
        *service = CartesiMachine::MachineCheckIn::service_full_name();
        Status status = manager.health_check(request, response);
        ASSERT_STATUS(status, "HealthCheck", true);
        ASSERT((response.status() == HealthCheckResponse_ServingStatus_SERVING), "Version Major should be 0");
    });

    test("The server-manager Health service health status should be SERVING", [](ServerManagerClient &manager) {
        HealthCheckRequest request;
        HealthCheckResponse response;
        auto *service = request.mutable_service();
        *service = Health::service_full_name();
        Status status = manager.health_check(request, response);
        ASSERT_STATUS(status, "HealthCheck", true);
        ASSERT((response.status() == HealthCheckResponse_ServingStatus_SERVING), "Version Major should be 0");
    });

    test("The server-manager Unknown service status should be NOT FOUND", [](ServerManagerClient &manager) {
        HealthCheckRequest request;
        HealthCheckResponse response;
        auto *service = request.mutable_service();
        *service = "UnknownService";
        Status status = manager.health_check(request, response);
        ASSERT_STATUS(status, "HealthCheck", false);
        ASSERT_STATUS_CODE(status, "HealthCheck", StatusCode::NOT_FOUND);
    });
}

static int run_tests(const char *address) {
    ServerManagerClient manager(address);
    test_suite suite(manager);
    suite.add_test_set("GetVersion", test_get_version);
    suite.add_test_set("HealthCheck", test_health_check);
    suite.add_test_set("StartSession", test_start_session);
    suite.add_test_set("AdvanceState", test_advance_state);
    suite.add_test_set("GetStatus", test_get_status);
    suite.add_test_set("GetSessionStatus", test_get_session_status);
    suite.add_test_set("GetEpochStatus", test_get_epoch_status);
    suite.add_test_set("InspectState", test_inspect_state);
    suite.add_test_set("FinishEpoch", test_finish_epoch);
    suite.add_test_set("EndSession", test_end_session);
    suite.add_test_set("Session Simulations", test_session_simulations);
    return suite.run();
}

/// \brief Prints help
/// \param name Program name vrom argv[0]
static void help(const char *name) {
    (void) fprintf(stderr,
        R"(Usage:

    %s [-r] [--help] [--http] <manager-address>

where

    <manager-address>
      server manager address, where <manager-address> can be
        <ipv4-hostname/address>:<port>
        <ipv6-hostname/address>:<port>
        unix:<path>

    -r
      recreate test machines if they already exist

    --help
      prints this message and exits

    --http
      uses rollup http-echo-dapp instead of ioctl-echo-loop
      to perform the tests.


)",
        name);
}

int main(int argc, char *argv[]) try {
    const char *manager_address = nullptr;
    bool rebuild = false;
    bool http_api = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            rebuild = true;
        } else if (strcmp(argv[i], "--http") == 0) {
            http_api = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            exit(0);
        } else {
            manager_address = argv[i];
        }
    }

    if (!manager_address) {
        std::cerr << "missing manager-address\n";
        exit(1);
    }
    initialize_machines(rebuild, http_api);
    return run_tests(manager_address);
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
