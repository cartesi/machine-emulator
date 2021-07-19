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

#include <iostream>
#include <string>
#include <filesystem>
#include <stdexcept>
#include <thread>

#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <grpc++/grpc++.h>
#include <google/protobuf/util/json_util.h>
#include "rollup-machine-manager.grpc.pb.h"
#include "grpc-util.h"
#pragma GCC diagnostic pop

#include "cryptopp-keccak-256-hasher.h"
#include "complete-merkle-tree.h"
#include "back-merkle-tree.h"
#include "machine-config.h"

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;
using CartesiMachine::Void;

using std::chrono_literals::operator""s;

using namespace std::filesystem;
using namespace CartesiRollupMachineManager;
using namespace cartesi;

constexpr static const int LOG2_ROOT_SIZE = 37;
constexpr static const int LOG2_KECCAK_SIZE = 5;
constexpr static const int LOG2_WORD_SIZE = 3;
constexpr static const uint64_t INPUT_METADATA_LENGTH = 128ULL;
constexpr static const uint64_t METADATA_ENTRY_LENGTH = 32ULL;
constexpr static const uint64_t OUTPUT_ENTRY_LENGTH = 256ULL; // 192 bytes of usable data
constexpr static const uint64_t MESSAGE_ENTRY_LENGTH = 256ULL; // 224 bytes of usable data
constexpr static const uint64_t MIN_DRIVE_LENGTH = 4096ULL;
constexpr static const uint64_t OUTPUT_DRIVE_LENGTH = OUTPUT_ENTRY_LENGTH * (MIN_DRIVE_LENGTH / METADATA_ENTRY_LENGTH);
constexpr static const uint64_t MESSAGE_DRIVE_LENGTH = MESSAGE_ENTRY_LENGTH * (MIN_DRIVE_LENGTH / METADATA_ENTRY_LENGTH);
constexpr static const uint64_t INUSE_FLASH_DRIVE_INDEX = 1ULL;
constexpr static const uint64_t UNUSED_FLASH_DRIVE_INDEX = 7ULL;
static const path MANAGER_ROOT_DIR = "/tmp/rollup-machine-manager-root"; // NOLINT: ignore static initialization warning

class RollupMachineManagerClient {

public:
    RollupMachineManagerClient(const std::string &address): m_test_id("not-defined") {
        m_stub = RollupMachineManager::NewStub(grpc::CreateChannel(address,
                grpc::InsecureChannelCredentials()));
    }

    Status get_version(Versioning::GetVersionResponse &response){
        ClientContext context;
        Void request;
        init_client_context(context);
        return m_stub->GetVersion(&context, request, &response);
    }

    Status start_session(const StartSessionRequest &request){
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->StartSession(&context, request, &response);
    }

    Status enqueue_input(const EnqueueInputRequest &request){
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->EnqueueInput(&context, request, &response);
    }

    Status get_status(GetStatusResponse &response){
        ClientContext context;
        Void request;
        init_client_context(context);
        return m_stub->GetStatus(&context, request, &response);
    }

    Status get_session_status(const GetSessionStatusRequest &request, GetSessionStatusResponse &response){
        ClientContext context;
        init_client_context(context);
        return m_stub->GetSessionStatus(&context, request, &response);
    }

    Status get_epoch_status(const GetEpochStatusRequest &request, GetEpochStatusResponse &response){
        ClientContext context;
        init_client_context(context);
        return m_stub->GetEpochStatus(&context, request, &response);
    }

    Status finish_epoch(const FinishEpochRequest &request){
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->FinishEpoch(&context, request, &response);
    }

    Status end_session(const EndSessionRequest &request){
        ClientContext context;
        Void response;
        init_client_context(context);
        return m_stub->EndSession(&context, request, &response);
    }

    void set_test_id(std::string test_id) {
        m_test_id = std::move(test_id);
    }

    std::string test_id() {
        return m_test_id;
    }

private:
    std::unique_ptr<RollupMachineManager::Stub> m_stub;
    std::string m_test_id;

    void init_client_context(ClientContext &context) {
        context.set_wait_for_ready(true);
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(20));
        context.AddMetadata("test-id", test_id());
        context.AddMetadata("request-id", request_id());
    }

    static std::string request_id() {
        uint64_t request_id = static_cast<uint64_t>(std::time(nullptr)) << 32 | (std::rand() & 0xFFFFFFFF); // NOLINT: rand is ok for this
        return std::to_string(request_id);
    }
};

typedef void (*test_function)(RollupMachineManagerClient &manager);
typedef void (*test_setup)(const std::function<void(const std::string &title, test_function f)> &fn);

class test_suite final {
public:
    test_suite(RollupMachineManagerClient &manager): m_manager{manager},
        m_suite{}, m_total_tests{0} {}

    void add_test_set(const std::string &title, test_setup setup) {
        m_suite.push_back({title, std::vector<std::pair<std::string, test_function>>()});
        auto &tests = m_suite.back().second;
        setup([&tests, this](const std::string &title, test_function f){
            tests.push_back({title, f});
            ++m_total_tests;
        });
    }

    int run() {
        int total = 0;
        int total_failed = 0;
        for (const auto& [test, cases]: m_suite) {
            int failed = 0;
            std::cerr << test << ": " ;
            for (const auto& [c, f]: cases) {
                try {
                    std::cerr << "." ;
                    m_manager.set_test_id(std::to_string(total));
                    (*f)(m_manager);
                } catch (std::exception &e) {
                    if (failed == 0) {
                        std::cerr << " FAILED";
                    }
                    std::cerr << "\n  - [" << std::to_string(total) + "] '" << c <<
                        "' expected result failed:\n\t" << e.what() << std::endl;
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
        std::cerr << m_total_tests - total_failed << " of " << m_total_tests
            << " tests passed" << std::endl;
        return total_failed;
    }

private:
    RollupMachineManagerClient &m_manager;
    std::vector<std::pair<std::string, std::vector<std::pair<std::string, test_function>>>> m_suite;
    unsigned int m_total_tests;
};

static void get_word_hash(cryptopp_keccak_256_hasher &h,
    const unsigned char *word, int log2_word_size,
    cryptopp_keccak_256_hasher::hash_type &hash) {
    h.begin();
    h.add_data(word, 1 << log2_word_size);
    h.end(hash);
}

static cryptopp_keccak_256_hasher::hash_type get_leaf_hash(cryptopp_keccak_256_hasher &h,
    const unsigned char *leaf_data, int log2_leaf_size, int log2_word_size) {
    assert(log2_leaf_size >= log2_word_size);
    if (log2_leaf_size > log2_word_size) {
        cryptopp_keccak_256_hasher::hash_type left = get_leaf_hash(h, leaf_data,
            log2_leaf_size-1, log2_word_size);
        cryptopp_keccak_256_hasher::hash_type right = get_leaf_hash(h, leaf_data+(1<<(log2_leaf_size-1)),
            log2_leaf_size-1, log2_word_size);
        get_concat_hash(h, left, right, left);
        return left;
    } else {
        cryptopp_keccak_256_hasher::hash_type leaf;
        get_word_hash(h, leaf_data, log2_word_size, leaf);
        return leaf;
    }
}

#if 0
static void print_hash(const cryptopp_keccak_256_hasher::hash_type &hash, FILE *f) {
    for (auto b: hash) {
        fprintf(f, "%02x", (int) b);
    }
    fprintf(f, "\n");
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

static const std::string DEFAULT_SCRIPT = // NOLINT: ignore static initialization warning
    "-- while true; do "
        "devio '<< /dev/mtdblock2; >> /dev/mtdblock3; cp 64; >> /dev/mtdblock4; cp 384; >> /dev/mtdblock5; cp 64; >> /dev/mtdblock6; cp 352'; "
        "/opt/cartesi/bin/yield rollup 0; "
        "done";

static const std::string NO_OUTPUT_SCRIPT = "-- while true; do /opt/cartesi/bin/yield rollup 0; done"; // NOLINT: ignore static initialization warning

static StartSessionRequest create_valid_start_session_request(const std::string &command = DEFAULT_SCRIPT) {
    const char *env_images_path = std::getenv("CARTESI_IMAGES_PATH");
    path images_path = (env_images_path == nullptr) ? current_path() : env_images_path;

    // Machine config
    machine_config config;

    // Enable machine yield rollup
    config.htif.yield_rollup = true;

    // Flash Drives
    path rootfs = images_path / "rootfs.ext2";
    config.flash_drive.push_back({flash_start_address(0), file_size(rootfs), false, rootfs.string()});
    config.flash_drive.push_back({flash_start_address(1), MIN_DRIVE_LENGTH}); // "input.metadata"
    config.flash_drive.push_back({flash_start_address(2), MIN_DRIVE_LENGTH}); // "input.payload"
    config.flash_drive.push_back({flash_start_address(3), MIN_DRIVE_LENGTH}); // "output.metadata"
    config.flash_drive.push_back({flash_start_address(4), OUTPUT_DRIVE_LENGTH}); // "output.payload"
    config.flash_drive.push_back({flash_start_address(5), MIN_DRIVE_LENGTH}); // "message.metadata"
    config.flash_drive.push_back({flash_start_address(6), MESSAGE_DRIVE_LENGTH}); // "message.payload"

    // ROM
    config.rom.image_filename = (images_path / "rom.bin").string();
    config.rom.bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet "
        "mtdparts=flash.0:-(root);flash.1:-(in_metadata);flash.2:-(in_payload);"
        "flash.3:-(out_metadata);flash.4:-(out_payload);"
        "flash.5:-(msg_metadata);flash.6:-(msg_payload) ";

    if (!command.empty()) {
        config.rom.bootargs += command;
    }

    // RAM
    config.ram.image_filename = (images_path / "linux.bin").string();
    config.ram.length = 64 << 20;

    // Convert to proto message
    StartSessionRequest session_request;
    CartesiMachine::MachineRequest *machine_request = session_request.mutable_machine();
    set_proto_machine_config(config, machine_request->mutable_config());

    session_request.set_session_id("test_session_request_id:" + std::to_string(new_session_id()));
    session_request.set_active_epoch_index(0);
    session_request.set_max_cycles_per_input(UINT64_MAX >> 2);
    session_request.set_cycles_per_input_chunk(1 << 22);

    // Set input_description
    auto *input_description = session_request.mutable_input_description();
    input_description->set_metadata_flash_drive_index(1);
    input_description->set_payload_flash_drive_index(2);

    // Set outputs_description
    auto *outputs_description = session_request.mutable_outputs_description();
    auto *out_drive_pair = outputs_description->mutable_drive_pair();
    out_drive_pair->set_metadata_flash_drive_index(3);
    out_drive_pair->set_payload_flash_drive_index(4);
    outputs_description->set_entry_count(MIN_DRIVE_LENGTH / METADATA_ENTRY_LENGTH);
    outputs_description->set_payload_entry_length(OUTPUT_ENTRY_LENGTH);

    // Set messages_description
    auto *messages_description = session_request.mutable_messages_description();
    auto *msg_drive_pair = messages_description->mutable_drive_pair();
    msg_drive_pair->set_metadata_flash_drive_index(5);
    msg_drive_pair->set_payload_flash_drive_index(6);
    messages_description->set_entry_count(MIN_DRIVE_LENGTH / METADATA_ENTRY_LENGTH);
    messages_description->set_payload_entry_length(MESSAGE_ENTRY_LENGTH);

    // Set server_deadline
    auto *server_deadline = session_request.mutable_server_deadline();
    server_deadline->set_check_in(1000*5);
    server_deadline->set_update_merkle_tree(1000*60*2);
    server_deadline->set_run_input(1000*60*3);
    server_deadline->set_run_input_chunk(1000*10);
    server_deadline->set_machine(1000*60);
    server_deadline->set_store(1000*60*3);
    server_deadline->set_fast(1000*5);

    return session_request;
}

static const std::string OUTPUT_ADDRESS_1  = "000000000000000000000000fafafafafafafafafafafafafafafafafafafafa"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_OFFSET_1   = "0000000000000000000000000000000000000000000000000000000000000040"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_LENGTH_1   = "0000000000000000000000000000000000000000000000000000000000000080"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_PAYLOAD_1  = "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"  // NOLINT: ignore static initialization warning
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765720000";
static const std::string OUTPUT_KECCAK_1   = "028c8a06ce878fcd02522f0ca3174f9e6fe7c9267750a0c45844e597e7cbab03"; // NOLINT: ignore static initialization warning

static const std::string OUTPUT_ADDRESS_2  = "000000000000000000000000babababababababababababababababababababa"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_OFFSET_2   = "0000000000000000000000000000000000000000000000000000000000000040"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_LENGTH_2   = "0000000000000000000000000000000000000000000000000000000000000020"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_PAYLOAD_2  = "4c6f72656d20697073756d20646f6c6f722073697420616d657420637261732e"; // NOLINT: ignore static initialization warning
static const std::string OUTPUT_KECCAK_2   = "4af9ac1565a66632741c1cf848847920ae4ef6e7e96ef9fd5bae9fa316f5cb33"; // NOLINT: ignore static initialization warning

static const std::string EMPTY_32_BYTES    = "0000000000000000000000000000000000000000000000000000000000000000"; // NOLINT: ignore static initialization warning

static const std::string MESSAGE_OFFSET_1  = "0000000000000000000000000000000000000000000000000000000000000020"; // NOLINT: ignore static initialization warning
static const std::string MESSAGE_LENGTH_1  = "0000000000000000000000000000000000000000000000000000000000000040"; // NOLINT: ignore static initialization warning
static const std::string MESSAGE_PAYLOAD_1 = "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020"  // NOLINT: ignore static initialization warning
                                             "6361727465736920726f6c6c7570206d616368696e65206d616e616765722020";
static const std::string MESSAGE_KECCAK_1  = "d08ae55c73b87ab95ff17b36a4d7d3d8e0683a4e9befae9ec20fb123306ba09b"; // NOLINT: ignore static initialization warning

static const std::string MESSAGE_OFFSET_2  = "0000000000000000000000000000000000000000000000000000000000000020"; // NOLINT: ignore static initialization warning
static const std::string MESSAGE_LENGTH_2  = "0000000000000000000000000000000000000000000000000000000000000020"; // NOLINT: ignore static initialization warning
static const std::string MESSAGE_PAYLOAD_2 = "4c6f72656d20697073756d20646f6c6f722073697420616d657420637261732e"; // NOLINT: ignore static initialization warning
static const std::string MESSAGE_KECCAK_2  = "8c35a8e6f7e96bf5b0f9200e6cf35db282e9de960e9e958c5d52b14a66af6c47"; // NOLINT: ignore static initialization warning

static const std::string DEFAULT_INPUT = // NOLINT: ignore static initialization warning
    OUTPUT_KECCAK_1 + OUTPUT_KECCAK_2 +
    OUTPUT_ADDRESS_1 + OUTPUT_OFFSET_1 + OUTPUT_LENGTH_1 + OUTPUT_PAYLOAD_1 + EMPTY_32_BYTES +
    OUTPUT_ADDRESS_2 + OUTPUT_OFFSET_2 + OUTPUT_LENGTH_2 + OUTPUT_PAYLOAD_2 +
    MESSAGE_KECCAK_1 + MESSAGE_KECCAK_2 +
    MESSAGE_OFFSET_1 + MESSAGE_LENGTH_1 + MESSAGE_PAYLOAD_1 +
    EMPTY_32_BYTES + EMPTY_32_BYTES + EMPTY_32_BYTES + EMPTY_32_BYTES +
    MESSAGE_OFFSET_2 + MESSAGE_LENGTH_2 + MESSAGE_PAYLOAD_2;

static void hex_string_to_binary(const std::string &input, std::string &dest) {
    CryptoPP::StringSource ss(input, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(dest))); // NOLINT: suppress cryptopp warnings
}

static void get_input_payload(std::string &payload) {
    hex_string_to_binary(DEFAULT_INPUT, payload);
}

static std::string get_output_keccak(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? OUTPUT_KECCAK_1 : OUTPUT_KECCAK_2, value);
    return value;
}

static std::string get_output_address(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? OUTPUT_ADDRESS_1 : OUTPUT_ADDRESS_2, value);
    return value;
}

static std::string get_output_payload(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? OUTPUT_PAYLOAD_1 : OUTPUT_PAYLOAD_2, value);
    return value;
}

static std::string get_message_keccak(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? MESSAGE_KECCAK_1 : MESSAGE_KECCAK_2, value);
    return value;
}

static std::string get_message_payload(uint64_t index) {
    std::string value;
    hex_string_to_binary((index & 0x1) ? MESSAGE_PAYLOAD_1 : MESSAGE_PAYLOAD_2, value);
    return value;
}

static inline int ilog2(uint64_t v) {
    return 63 - __builtin_clzll(v);
}

static cryptopp_keccak_256_hasher::hash_type get_data_hash(cryptopp_keccak_256_hasher &h, int log2_root_size, std::string &data) {
    cartesi::complete_merkle_tree tree{log2_root_size, LOG2_WORD_SIZE, LOG2_WORD_SIZE};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data_c_str = reinterpret_cast<const unsigned char*>(data.c_str());
    uint64_t leaf_size = UINT64_C(1) << LOG2_WORD_SIZE;
    for (uint64_t i = 0; i < data.size(); i += leaf_size) {
        // Compute leaf hash
        auto leaf_hash = get_leaf_hash(h, data_c_str+i, 3, 3);
        // Add leaf to the tree
        tree.push_back(leaf_hash);
    }
    return tree.get_root_hash();
}

static cryptopp_keccak_256_hasher::hash_type get_output_keccak_hash(cryptopp_keccak_256_hasher &h, uint64_t index) {
    std::string keccak = get_output_keccak(index);
    return get_data_hash(h, LOG2_KECCAK_SIZE, keccak);
}

static cryptopp_keccak_256_hasher::hash_type get_message_keccak_hash(cryptopp_keccak_256_hasher &h, uint64_t index) {
    std::string keccak = get_message_keccak(index);
    return get_data_hash(h, LOG2_KECCAK_SIZE, keccak);
}

static cryptopp_keccak_256_hasher::hash_type get_output_metadata_root_hash(cryptopp_keccak_256_hasher &h, uint64_t count){
    std::string metadata_content;
    for (uint64_t i = 1; i <= count ; i++) {
        metadata_content += get_output_keccak(i);
    }
    return get_data_hash(h, ilog2(MIN_DRIVE_LENGTH), metadata_content);
}

static cryptopp_keccak_256_hasher::hash_type get_message_metadata_root_hash(cryptopp_keccak_256_hasher &h, uint64_t count){
    std::string metadata_content;
    for (uint64_t i = 1; i <= count ; i++) {
        metadata_content += get_message_keccak(i);
    }
    return get_data_hash(h, ilog2(MIN_DRIVE_LENGTH), metadata_content);
}

static void init_valid_enqueue_input_request(EnqueueInputRequest &enqueue_request,
        const std::string &session_id, uint64_t epoch, uint64_t input_index) {
    enqueue_request.set_session_id(session_id);
    enqueue_request.set_active_epoch_index(epoch);
    enqueue_request.set_current_input_index(input_index);

    auto *input_metadata = enqueue_request.mutable_input_metadata();
    input_metadata->resize(INPUT_METADATA_LENGTH, 0);

    auto *input_payload = enqueue_request.mutable_input_payload();
    get_input_payload(*input_payload); // NOLINT: suppres crytopp warnings
}

static void init_valid_finish_epoch_request(FinishEpochRequest &epoch_request,
        const std::string &session_id, uint64_t epoch, uint64_t processed_input_count,
        const std::string &dir = std::string{}) {
    epoch_request.set_session_id(session_id);
    epoch_request.set_active_epoch_index(epoch);
    epoch_request.set_processed_input_count(processed_input_count);
    if (!dir.empty()) {
        auto *storage_directory = epoch_request.mutable_storage_directory();
        (*storage_directory) = dir;
    }
}

static void assert_status(Status &status, const std::string &rpcname, bool expected,
        const std::string &file, int line) {
    if (status.ok() != expected) {
        if (expected) {
            throw std::runtime_error("Call to " + rpcname + " failed. Code: " +
                    std::to_string(status.error_code()) + " Message: " +
                    status.error_message() + ". Assert at " + file +
                    ":" + std::to_string(line));
        }
        throw std::runtime_error("Call to " + rpcname +
                " succeded when was expected to fail. Assert at " + file +
                ":" + std::to_string(line));
    }
}

static void assert_status_code(const Status &status, const std::string &rpcname, grpc::StatusCode expected,
        const std::string &file, int line) {
    if (status.error_code() != expected) {
        throw std::runtime_error(rpcname + " was expected to fail with Code: " +
                std::to_string(expected) + " but received " + std::to_string(status.error_code()) +
                " Message: " + status.error_message() + ". Assert at " + file + ":" + std::to_string(line));

    }
}

void assert_bool(bool value, const std::string& msg, const std::string& file, int line) {
    if (!value) {
        throw std::runtime_error(msg+ ". Assert at " + file + ":" + std::to_string(line));
    }
}

#define ASSERT(v, msg) assert_bool(v, msg, __FILE__, __LINE__) // NOLINT(cppcoreguidelines-macro-usage)
#define ASSERT_STATUS(s, f, v) assert_status(s, f, v, __FILE__, __LINE__) // NOLINT(cppcoreguidelines-macro-usage)
#define ASSERT_STATUS_CODE(s, f, v) assert_status_code(s, f, v, __FILE__, __LINE__) // NOLINT(cppcoreguidelines-macro-usage)

static void test_get_version(const std::function<void(const std::string &title, test_function f)> &test) {
    test("The rollup-machine-manager server version should be 0.0.x", [](RollupMachineManagerClient &manager){
        Versioning::GetVersionResponse response;
        Status status = manager.get_version(response);
        ASSERT_STATUS(status, "GetVersion", true);
        ASSERT((response.version().major() == 0), "Version Major should be 0");
        ASSERT((response.version().minor() == 0), "Version Minor should be 0");
    });
}

static void test_start_session(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete a request with a invalid session id", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.clear_session_id();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request with a invalid machine request", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // clear machine request
        session_request.clear_machine();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when config.htif.yield_rollup = false", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // set yield_rollup false
        auto *htif = session_request.mutable_machine()->mutable_config()->mutable_htif();
        htif->set_yield_rollup(false);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when config.htif.yield_progress = true", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // set yield_progress true
        auto *htif = session_request.mutable_machine()->mutable_config()->mutable_htif();
        htif->set_yield_progress(true);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete when there is no flash drives", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // clear flash drives
        auto *config = session_request.mutable_machine()->mutable_config();
        config->clear_flash_drive();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete a request with a invalid input description ", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // clear input description
        session_request.clear_input_description();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request with invalid outputs description", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // clear outputs description
        session_request.clear_outputs_description();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete a request with invalid messages description", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // clear messages description
        session_request.clear_messages_description();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with invalid input metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *description = session_request.mutable_input_description();
        description->set_metadata_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid input payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *description = session_request.mutable_input_description();
        description->set_payload_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid output metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_outputs_description()->mutable_drive_pair();
        drive_pair->set_metadata_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid output payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_outputs_description()->mutable_drive_pair();
        drive_pair->set_payload_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid message metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_messages_description()->mutable_drive_pair();
        drive_pair->set_metadata_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid message payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_messages_description()->mutable_drive_pair();
        drive_pair->set_payload_flash_drive_index(UNUSED_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with repeated input metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *description = session_request.mutable_input_description();
        description->set_metadata_flash_drive_index(INUSE_FLASH_DRIVE_INDEX + 1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with repeated input payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *description = session_request.mutable_input_description();
        description->set_payload_flash_drive_index(INUSE_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with repeated output metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_outputs_description()->mutable_drive_pair();
        drive_pair->set_metadata_flash_drive_index(INUSE_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with repeated output payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_outputs_description()->mutable_drive_pair();
        drive_pair->set_payload_flash_drive_index(INUSE_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with repeated message metadata drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_messages_description()->mutable_drive_pair();
        drive_pair->set_metadata_flash_drive_index(INUSE_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with repeated message payload drive index", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change index
        auto *drive_pair = session_request.mutable_messages_description()->mutable_drive_pair();
        drive_pair->set_payload_flash_drive_index(INUSE_FLASH_DRIVE_INDEX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with invalid outputs entry_count", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change output entry_count
        auto *outputs_description = session_request.mutable_outputs_description();
        outputs_description->set_entry_count((MIN_DRIVE_LENGTH/METADATA_ENTRY_LENGTH) + 1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid outputs payload_entry_length", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change output payload_entry_length
        auto *outputs_description = session_request.mutable_outputs_description();
        outputs_description->set_payload_entry_length(OUTPUT_ENTRY_LENGTH * 2);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete with invalid messages entry_count", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change messages entry_count
        auto *messages_description = session_request.mutable_messages_description();
        messages_description->set_entry_count((MIN_DRIVE_LENGTH/METADATA_ENTRY_LENGTH) + 1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete if active epoch is on the limit", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.set_active_epoch_index(UINT64_MAX);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);

        session_request.set_active_epoch_index(UINT64_MAX-1);
        status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with invalid messages payload_entry_length", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        // change output payload_entry_length
        auto *messages_description = session_request.mutable_messages_description();
        messages_description->set_payload_entry_length(MESSAGE_ENTRY_LENGTH * 2);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::OUT_OF_RANGE);
    });

    test("Should fail to complete a 2nd request with same session id", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // repeat request
        status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", false);
        ASSERT_STATUS_CODE(status, "StartSession", StatusCode::ALREADY_EXISTS);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should be able to reutilise an session id", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // repeat request
        status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // EndSession
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });
}

static void wait_pending_inputs_to_be_processed(RollupMachineManagerClient &manager, GetEpochStatusRequest &status_request,
        GetEpochStatusResponse &status_response, bool accept_tainted, int retries) {
    for ( ;; ) {
        Status status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        ASSERT(accept_tainted || !status_response.has_taint_status(),
                "tainted session was not expected");
        if (accept_tainted && status_response.has_taint_status()) {
            break;
        }

        if (status_response.pending_input_count() == 0) {
            break;
        }

        ASSERT((retries > 0), "wait_pending_inputs_to_be_processed max retries reached" );
        std::this_thread::sleep_for(3s);
        retries--;
    }
}

static void end_session_after_processing_pending_inputs(RollupMachineManagerClient &manager,
        const std::string &session_id, uint64_t epoch, bool accept_tainted = false) {
    GetEpochStatusRequest status_request;
    GetEpochStatusResponse status_response;

    status_request.set_session_id(session_id);
    status_request.set_epoch_index(epoch);
    wait_pending_inputs_to_be_processed(manager, status_request, status_response, accept_tainted, 10);

    // finish epoch
    if ((!accept_tainted && !status_response.has_taint_status())
            && (status_response.state() != EpochState::FINISHED)
            && (status_response.processed_inputs_size() != 0)) {
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request,
                status_request.session_id(),
                status_request.epoch_index(),
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

static void test_enqueue_input(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should not be able to enqueue two identical requests", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // repeated
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should complete two valid requests with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // enqueue second
        enqueue_request.set_current_input_index(enqueue_request.current_input_index() + 1);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should fail to complete if the input index are not sequential", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // enqueue wrong input index
        enqueue_request.set_current_input_index(enqueue_request.current_input_index() + 10);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should fail to complete if epoch is not the same", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        // change epoch index
        enqueue_request.set_active_epoch_index(enqueue_request.active_epoch_index() + 1);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if epoch is finished", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // try to enqueue input on ended session
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with success enqueing on a new epoch", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index() + 1, 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index() + 1);
    });

    test("Should fail to complete if active epoch is on the limit", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.set_active_epoch_index(UINT64_MAX-1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index() + 1, 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::OUT_OF_RANGE);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete input metadata does not fit the drive", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        auto *input_metadata = enqueue_request.mutable_input_metadata();
        input_metadata->resize(MIN_DRIVE_LENGTH + 1, 'x');
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete input payload does not fit the drive", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        auto *input_payload = enqueue_request.mutable_input_payload();
        input_payload->resize(MIN_DRIVE_LENGTH + 1, 'x');
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id is not valid", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        enqueue_request.set_session_id("NON-EXISTENT");
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session was ended", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        // try to enqueue input on ended session
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", false);
        ASSERT_STATUS_CODE(status, "EnqueueInput", StatusCode::INVALID_ARGUMENT);
    });
}

static void test_get_status(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        GetStatusResponse status_response;
        Status status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 0, "status response should be empty");
    });

    test("Should complete with success when there is one session", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        GetStatusResponse status_response;
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);

        ASSERT(status_response.session_id_size() == 1, "status response should have only one session");
        ASSERT(status_response.session_id()[0] == session_request.session_id(), "status response  first session_id should be the same as the one created");

        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 0, "status response should have no sessions");
    });

    test("Should complete with success when there is two sessions", [](RollupMachineManagerClient &manager){
        // Create 1st session
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // Get status
        GetStatusResponse status_response;
        status = manager.get_status(status_response);
        ASSERT_STATUS(status, "GetStatus", true);
        ASSERT(status_response.session_id_size() == 1, "status response should have only one session");
        ASSERT(status_response.session_id()[0] == session_request.session_id(), "status response  first session_id should be the same as the first created");

        // Create 2nd session
        StartSessionRequest session_request2 = create_valid_start_session_request();
        status = manager.start_session(session_request2);
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
        ASSERT(status_response.session_id()[0] == session_request2.session_id(), "status response  first session_id should be the same as the second created");

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
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(), "status response active_epoch_index should be the same as the one created");
        ASSERT(status_response.epoch_index_size() == 1, "status response should no old epochs");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should report epoch index correctly after FinishEpoch", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // GetSessionStatus
        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(), "status response active_epoch_index should be the same as the one created");
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

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index() + 1, "status response active_epoch_index should be 1");
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

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index() + 2, "status response active_epoch_index should be 2");
        ASSERT(status_response.epoch_index_size() == 3, "status response epoch_indices size should be 3");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with session taint_status code DEADLINE_EXCEEDED", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_run_input_chunk(1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(10s);

        // GetSessionStatus
        GetSessionStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        GetSessionStatusResponse status_response;
        status = manager.get_session_status(status_request, status_response);
        ASSERT_STATUS(status, "GetSessionStatus", true);

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.active_epoch_index() == session_request.active_epoch_index(), "status response active_epoch_index should be the same as the one created");
        ASSERT(status_response.epoch_index_size() == 1, "status response epoch_indices size should be 1");
        ASSERT(status_response.has_taint_status(), "status response should have a taint_status");
        ASSERT(status_response.taint_status().error_code() == StatusCode::DEADLINE_EXCEEDED, "taint_status code should be DEADLINE_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index(), true);
    });
}

static void check_processed_input(ProcessedInput &processed_input, uint64_t index, int output_count, int message_count) {
    // processed_input
    ASSERT(processed_input.input_index() == index, "processed input index should sequential");
    ASSERT(processed_input.has_machine_hash_after(), "processed input should contain a machine_hash_after");
    ASSERT(!processed_input.machine_hash_after().data().empty(), "processed input should contain a machine_hash_after and it should not be empty");
    ASSERT(processed_input.has_result(), "processed input should contain a result");

    const auto &result = processed_input.result();
    ASSERT(result.has_outputs_metadata_flash_drive_in_machine(), "result should have outputs_metadata_flash_drive_in_machine");
    ASSERT(result.has_outputs_metadata_flash_drive_in_epoch(), "result should have outputs_metadata_flash_drive_in_epoch");
    ASSERT(result.outputs_size() == output_count, "result outputs size should be equal to output_count");
    ASSERT(result.has_messages_metadata_flash_drive_in_machine(), "result should have messages_metadata_flash_drive_in_machine");
    ASSERT(result.has_messages_metadata_flash_drive_in_epoch(), "result should have messages_metadata_flash_drive_in_epoch");
    ASSERT(result.messages_size() == message_count, "result messages size should be equal to message_count");

    // verify proofs
    cryptopp_keccak_256_hasher h;
    auto output_metadata_root_hash = get_output_metadata_root_hash(h, result.outputs_size());
    auto message_metadata_root_hash = get_message_metadata_root_hash(h, result.messages_size());
    auto metadata_log2_size = ilog2(MIN_DRIVE_LENGTH);
    cartesi::complete_merkle_tree outputs_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
    cartesi::complete_merkle_tree messages_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};

    for (uint64_t i = 0; i <= index; i++) {
        outputs_tree.push_back(output_metadata_root_hash);
        messages_tree.push_back(message_metadata_root_hash);
    }

    auto outputs_metadata_in_machine_proof = get_proto_proof(result.outputs_metadata_flash_drive_in_machine());
    ASSERT(outputs_metadata_in_machine_proof.get_log2_target_size() == metadata_log2_size, "outputs_metadata_flash_drive_in_machine log2 target size should match");
    ASSERT(outputs_metadata_in_machine_proof.get_target_hash() == output_metadata_root_hash, "outputs_metadata_flash_drive_in_machine target hash should match");
    ASSERT(outputs_metadata_in_machine_proof.verify(h), "outputs_metadata_flash_drive_in_machine proof should be valid");

    auto calculated_outputs_in_epoch_proof = outputs_tree.get_proof(index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
    auto outputs_in_epoch_proof = get_proto_proof(result.outputs_metadata_flash_drive_in_epoch());
    ASSERT(outputs_in_epoch_proof.get_log2_target_size() == calculated_outputs_in_epoch_proof.get_log2_target_size(), "outputs_metadata_flash_drive_in_epoch log2 target size should match");
    ASSERT(outputs_in_epoch_proof.get_target_hash() == calculated_outputs_in_epoch_proof.get_target_hash(), "outputs_metadata_flash_drive_in_epoch target hash should match");
    ASSERT(outputs_in_epoch_proof.get_log2_root_size() == calculated_outputs_in_epoch_proof.get_log2_root_size(), "outputs_metadata_flash_drive_in_epoch log2 root size should match");
    ASSERT(outputs_in_epoch_proof.get_root_hash() == calculated_outputs_in_epoch_proof.get_root_hash(), "outputs_metadata_flash_drive_in_epoch root hash should match");
    ASSERT(outputs_in_epoch_proof.verify(h), "outputs_metadata_flash_drive_in_epoch proof should be valid");

    auto messages_metadata_in_machine_proof = get_proto_proof(result.messages_metadata_flash_drive_in_machine());
    ASSERT(messages_metadata_in_machine_proof.get_log2_target_size() == metadata_log2_size, "messages_metadata_flash_drive_in_machine log2 target size should match");
    ASSERT(messages_metadata_in_machine_proof.get_target_hash() == message_metadata_root_hash, "messages_metadata_flash_drive_in_machine target hash should match");
    ASSERT(messages_metadata_in_machine_proof.verify(h), "messages_metadata_flash_drive_in_machine proof should be valid");

    auto calculated_messages_in_epoch_proof = messages_tree.get_proof(index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
    auto messages_in_epoch_proof = get_proto_proof(result.messages_metadata_flash_drive_in_epoch());
    ASSERT(messages_in_epoch_proof.get_log2_target_size() == calculated_messages_in_epoch_proof.get_log2_target_size(), "messages_metadata_flash_drive_in_epoch log2 target size should match");
    ASSERT(messages_in_epoch_proof.get_target_hash() == calculated_messages_in_epoch_proof.get_target_hash(), "messages_metadata_flash_drive_in_epoch target hash should match");
    ASSERT(messages_in_epoch_proof.get_log2_root_size() == calculated_messages_in_epoch_proof.get_log2_root_size(), "messages_metadata_flash_drive_in_epoch log2 root size should match");
    ASSERT(messages_in_epoch_proof.get_root_hash() == calculated_messages_in_epoch_proof.get_root_hash(), "messages_metadata_flash_drive_in_epoch root hash should match");
    ASSERT(messages_in_epoch_proof.verify(h), "messages_metadata_flash_drive_in_epoch proof should be valid");

    // outputs
    uint64_t output_index = 1;
    for (const auto &output: result.outputs()) {
        ASSERT(output.has_keccak() && !output.keccak().data().empty(), "output should have a keccak hash");
        ASSERT(output.has_address(), "output should have an address");
        ASSERT(!output.payload().empty(), "output payload should not be empty");
        ASSERT(output.has_keccak_in_output_metadata_flash_drive(), "output should have keccak_in_output_metadata_flash_drive");
        ASSERT(output.keccak().data() == get_output_keccak(output_index), "output keccak should match");
        ASSERT(output.address().data() == get_output_address(output_index), "output address should match");
        ASSERT(output.payload() == get_output_payload(output_index), "output payload should match");
        auto keccak_proof = get_proto_proof(output.keccak_in_output_metadata_flash_drive());
        ASSERT(keccak_proof.get_log2_target_size() == LOG2_KECCAK_SIZE, "keccak_in_output_metadata_flash_drive log2 target size should match");
        ASSERT(keccak_proof.get_target_hash() == get_output_keccak_hash(h, output_index), "keccak_in_output_metadata_flash_drive target hash should match");
        ASSERT(keccak_proof.get_log2_root_size() == metadata_log2_size, "keccak_in_output_metadata_flash_drive log2 root size should match");
        ASSERT(keccak_proof.get_root_hash() == output_metadata_root_hash, "keccak_in_output_metadata_flash_drive root hash should match");
        ASSERT(keccak_proof.verify(h), "keccak_in_output_metadata_flash_drive proof should be valid");
        output_index++;
    }

    // messages
    uint64_t message_index = 1;
    for (const auto &message: result.messages()) {
        ASSERT(message.has_keccak() && !message.keccak().data().empty(), "message should have a keccak hash");
        ASSERT(!message.payload().empty(), "message payload should not be empty");
        ASSERT(message.has_keccak_in_message_metadata_flash_drive(), "message should have keccak_in_message_metadata_flash_drive");
        ASSERT(message.keccak().data() == get_message_keccak(message_index), "message keccak should match");
        ASSERT(message.payload() == get_message_payload(message_index), "message payload should match");
        auto keccak_proof = get_proto_proof(message.keccak_in_message_metadata_flash_drive());
        ASSERT(keccak_proof.get_log2_target_size() == LOG2_KECCAK_SIZE, "keccak_in_message_metadata_flash_drive log2 target size should match");
        ASSERT(keccak_proof.get_target_hash() == get_message_keccak_hash(h, message_index), "keccak_in_message_metadata_flash_drive target hash should match");
        ASSERT(keccak_proof.get_log2_root_size() == metadata_log2_size, "keccak_in_message_metadata_flash_drive log2 root size should match");
        ASSERT(keccak_proof.get_root_hash() == message_metadata_root_hash, "keccak_in_message_metadata_flash_drive root hash should match");
        ASSERT(keccak_proof.verify(h), "keccak_in_message_metadata_flash_drive proof should be valid");
        message_index++;
    }
}

static void test_get_epoch_status(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be the same as the one created");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with a invalid session id", [](RollupMachineManagerClient &manager){
        GetEpochStatusRequest status_request;
        status_request.set_session_id("NON-EXISTENT");
        status_request.set_epoch_index(0);
        GetEpochStatusResponse status_response;
        Status status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", false);
        ASSERT_STATUS_CODE(status, "GetEpochStatus", StatusCode::INVALID_ARGUMENT);
    });

    test("Should fail to complete with a ended session id", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if epoch index is not valid", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index()+10);
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

    test("Should complete with success with a valid session id and valid old epoch", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::FINISHED, "status response state should be FINISHED");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // status on current epoch
        status_request.set_epoch_index(session_request.active_epoch_index() + 1);
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index() + 1, "status response epoch_index should be 1");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with pending input count equal 1 after EnqueueInput", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 1, "status response pending_input_count should 1");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should complete with processed input count equal 1 after processing enqueued input", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        check_processed_input(processed_input, 0, 2, 2);

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request,
                session_request.session_id(),
                session_request.active_epoch_index(),
                status_response.processed_inputs_size());
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should complete with first processed input as InputSkipReason CYCLE_LIMIT_EXCEEDED", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.set_max_cycles_per_input(2);
        session_request.set_cycles_per_input_chunk(2);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(5s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
        ASSERT(processed_input.has_skip_reason(), "processed_input should have skip reason");
        ASSERT(processed_input.skip_reason() == InputSkipReason::CYCLE_LIMIT_EXCEEDED, "skip reason should be CYCLE_LIMIT_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should complete with first processed input as InputSkipReason TIME_LIMIT_EXCEEDED", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.set_cycles_per_input_chunk(10);
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_run_input(1000);
        server_deadline->set_run_input_chunk(1000);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(10s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
        ASSERT(processed_input.has_skip_reason(), "processed_input should have skip reason");
        ASSERT(processed_input.skip_reason() == InputSkipReason::TIME_LIMIT_EXCEEDED, "skip reason should be TIME_LIMIT_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should complete with session taint_status code DEADLINE_EXCEEDED", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        auto *server_deadline = session_request.mutable_server_deadline();
        server_deadline->set_run_input_chunk(1);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(10s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 0, "status response processed_inputs size should be 0");
        ASSERT(status_response.pending_input_count() == 1, "status response pending_input_count should 1");
        ASSERT(status_response.has_taint_status(), "status response should have a taint_status");
        ASSERT(status_response.taint_status().error_code() == StatusCode::DEADLINE_EXCEEDED, "taint_status code should be DEADLINE_EXCEEDED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index(), true);
    });

    test("Should complete with first processed input as InputSkipReason REQUESTED_BY_MACHINE", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request("-- /opt/cartesi/bin/yield rollup 1");
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(10s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
        ASSERT(processed_input.has_skip_reason(), "processed_input should have skip reason");
        ASSERT(processed_input.skip_reason() == InputSkipReason::REQUESTED_BY_MACHINE, "skip reason should be REQUESTED_BY_MACHINE");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should complete with first processed input as InputSkipReason MACHINE_HALTED", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request("");
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        std::this_thread::sleep_for(10s);

        // get epoch status
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        status = manager.get_epoch_status(status_request, status_response);
        ASSERT_STATUS(status, "GetEpochStatus", true);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        ASSERT(processed_input.input_index() == 0, "processed_input input index should be 0");
        ASSERT(processed_input.has_skip_reason(), "processed_input should have skip reason");
        ASSERT(processed_input.skip_reason() == InputSkipReason::MACHINE_HALTED, "skip reason should be MACHINE_HALTED");

        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should return valid InputResults after request completed with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_response content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be the same as the one created");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // processed_input
        auto processed_input = (status_response.processed_inputs())[0];
        check_processed_input(processed_input, 0, 2, 2);

        // end session
        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });

    test("Should return valid InputResults even when there is no outputs or messages", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request(NO_OUTPUT_SCRIPT);
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_response content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be the same as the one created");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // processed_input
        auto processed_input = (status_response.processed_inputs())[0];
        check_processed_input(processed_input, 0, 0, 0);

        // end session
        end_session_after_processing_pending_inputs(manager, session_request.session_id(), session_request.active_epoch_index());
    });
}

static bool check_session_store(const std::string &machine_dir) {
    static const std::vector<std::string> files = {
        "0000000000001000-f000.bin",
        "0000000080000000-4000000.bin",
        "8000000000000000-3c00000.bin",
        "9000000000000000-1000.bin",
        "a000000000000000-1000.bin",
        "b000000000000000-1000.bin",
        "c000000000000000-8000.bin",
        "d000000000000000-1000.bin",
        "e000000000000000-8000.bin",
        "config",
        "hash"
    };
    if (machine_dir.empty()) {
        return false;
    }
    path full_path{machine_dir};
    return std::all_of(files.begin(), files.end(), [&full_path](const std::string &f){ return exists(full_path / f); });
}

static std::string get_machine_dir(const std::string &storage_path, const std::string &session_path) {
    return  MANAGER_ROOT_DIR / storage_path / session_path;
}

static bool delete_storage_directory(const std::string &storage_path) {
    if (storage_path.empty()) {
        return false;
    }
    return remove_all(MANAGER_ROOT_DIR / storage_path) > 0;
}

static bool create_storage_directory(const std::string &storage_path) {
    if (storage_path.empty()) {
        return false;
    }
    path root_path = MANAGER_ROOT_DIR / storage_path;
    if (exists(root_path) && !delete_storage_directory(storage_path)) {
        return false;
    }
    return create_directories(root_path) > 0;
}

static bool change_storage_directory_permissions(const std::string &storage_path, bool writable) {
    if (storage_path.empty()) {
        return false;
    }
    auto new_perms =  writable ? (perms::owner_all) : (perms::owner_read | perms::owner_exec);
    std::error_code ec;
    permissions(MANAGER_ROOT_DIR / storage_path, new_perms, ec);
    return ec.value() == 0;
}

static void test_finish_epoch(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if active epoch index is not correct", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if active epoch is on the limit", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        session_request.set_active_epoch_index(UINT64_MAX-1);
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if processed input count does not match", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should complete with success storing the machine", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_dir(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        ASSERT(check_session_store(machine_dir), "FinishEpoch should store machine to disk if storage directory is defined");
        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if the server does not have permission to write", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");
        ASSERT(change_storage_directory_permissions(storage_dir, false), "test should be able to change directory permissions");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_dir(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", false);
        ASSERT_STATUS_CODE(status, "FinishEpoch", StatusCode::ABORTED);

        ASSERT(!check_session_store(machine_dir), "FinishEpoch should store machine to disk if storage directory is defined");
        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete with the directory already exists", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_dir(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        ASSERT(check_session_store(machine_dir), "FinishEpoch should store machine to disk if storage directory is defined");

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

    test("StartSession should complete with success from a previous stored the machine", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        std::string storage_dir{"sessions"};
        ASSERT(create_storage_directory(storage_dir), "test should be able to create directory");

        FinishEpochRequest epoch_request;
        std::string machine_dir = get_machine_dir(storage_dir, "test_" + manager.test_id());
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(),
                session_request.active_epoch_index(), 0, machine_dir);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        ASSERT(check_session_store(machine_dir), "FinishEpoch should store machine to disk if storage directory is defined");

        // end session
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        auto *machine_request = session_request.mutable_machine();
        machine_request->clear_config();
        auto *stored_machine_dir = machine_request->mutable_directory();
        (*stored_machine_dir) = machine_dir;
        status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);

        ASSERT(delete_storage_directory(storage_dir), "test should be able to remove dir");
    });

    test("Should complete with success when processed input count greater than 1", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue first
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);
        // enqueue second
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 1);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request,
                session_request.session_id(),
                session_request.active_epoch_index(),
                status_response.processed_inputs_size());
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id is not valid", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if session id was ended", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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
}

static void test_end_session(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should complete a valid request with success", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should fail to complete if session id is not valid", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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

    test("Should fail to complete if session id was already ended", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
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
}

static void test_session_simulations(const std::function<void(const std::string &title, test_function f)> &test) {
    test("Should EndSession with success after processing two inputs on one epoch", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(),
                session_request.active_epoch_index(), 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 1, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        auto processed_input = (status_response.processed_inputs())[0];
        check_processed_input(processed_input, 0, 2, 2);

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request,
                session_request.session_id(),
                session_request.active_epoch_index(),
                status_response.processed_inputs_size());
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // EndSession
        EndSessionRequest end_session_request;
        end_session_request.set_session_id(session_request.session_id());
        status = manager.end_session(end_session_request);
        ASSERT_STATUS(status, "EndSession", true);
    });

    test("Should EndSession with success after processing multiple inputs on multiple epochs", [](RollupMachineManagerClient &manager){
        StartSessionRequest session_request = create_valid_start_session_request();
        Status status = manager.start_session(session_request);
        ASSERT_STATUS(status, "StartSession", true);

        // enqueue 0 epoch 0
        EnqueueInputRequest enqueue_request;
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(), 0, 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);
        // enqueue 1 epoch 0
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(), 0, 1);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        // get epoch status after pending input is processed
        GetEpochStatusRequest status_request;
        status_request.set_session_id(session_request.session_id());
        status_request.set_epoch_index(session_request.active_epoch_index());
        GetEpochStatusResponse status_response;
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        // assert status_resonse content
        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == session_request.active_epoch_index(), "status response epoch_index should be 0");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        uint64_t index = 0;
        for (auto processed_input: status_response.processed_inputs()) {
            check_processed_input(processed_input, index, 2, 2);
            index++;
        }

        // Finish epoch
        FinishEpochRequest epoch_request;
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(), 0, 2);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        // enqueue 0 epoch 1
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(), 1, 0);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);
        // enqueue 1 epoch 1
        init_valid_enqueue_input_request(enqueue_request, session_request.session_id(), 1, 1);
        status = manager.enqueue_input(enqueue_request);
        ASSERT_STATUS(status, "EnqueueInput", true);

        status_request.set_epoch_index(1);
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
        ASSERT(status_response.epoch_index() == 1, "status response epoch_index should be 1");
        ASSERT(status_response.state() == EpochState::ACTIVE, "status response state should be ACTIVE");
        ASSERT(status_response.processed_inputs_size() == 2, "status response processed_inputs size should be 1");
        ASSERT(status_response.pending_input_count() == 0, "status response pending_input_count should 0");
        ASSERT(!status_response.has_taint_status(), "status response should not be tainted");

        index = 0;
        for (auto processed_input: status_response.processed_inputs()) {
            check_processed_input(processed_input, index, 2, 2);
            index++;
        }

        // Finish epoch
        init_valid_finish_epoch_request(epoch_request, session_request.session_id(), 1, 2);
        status = manager.finish_epoch(epoch_request);
        ASSERT_STATUS(status, "FinishEpoch", true);

        status_request.set_epoch_index(2);
        wait_pending_inputs_to_be_processed(manager, status_request, status_response, false, 10);

        ASSERT(status_response.session_id() == session_request.session_id(), "status response session_id should be the same as the one created");
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

static int run_tests(const char *address) {
    RollupMachineManagerClient manager(address);
    test_suite suite(manager);
    suite.add_test_set("GetVersion", test_get_version);
    suite.add_test_set("StartSession", test_start_session);
    suite.add_test_set("EnqueueInput", test_enqueue_input);
    suite.add_test_set("GetStatus", test_get_status);
    suite.add_test_set("GetSessionStatus", test_get_session_status);
    suite.add_test_set("GetEpochStatus", test_get_epoch_status);
    suite.add_test_set("FinishEpoch", test_finish_epoch);
    suite.add_test_set("EndSession", test_end_session);
    suite.add_test_set("Session Simulations", test_session_simulations);
    return suite.run();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << argv[0] << " <ip>:<port>" << std::endl;
        std::cerr << argv[0] << " unix:<path>" << std::endl;
        return 1;
    }
    return run_tests(argv[1]);
}
