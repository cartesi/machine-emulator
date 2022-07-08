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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <map>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <boost/coroutine2/coroutine.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/process.hpp>
#define BOOST_DLL_USE_STD_FS
#include <boost/dll/runtime_symbol_info.hpp>
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include <grpc++/alarm.h>
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>

#include "cartesi-machine-checkin.grpc.pb.h"
#include "cartesi-machine.grpc.pb.h"
#include "server-manager.grpc.pb.h"
#pragma GCC diagnostic pop

static constexpr uint32_t manager_version_major = 0;
static constexpr uint32_t manager_version_minor = 3;
static constexpr uint32_t manager_version_patch = 0;
static constexpr const char *manager_version_pre_release = "";
static constexpr const char *manager_version_build = "";

static constexpr uint32_t machine_version_major = 0;
static constexpr uint32_t machine_version_minor = 5;

using namespace CartesiServerManager;
using namespace CartesiMachine;
using namespace Versioning;

#ifndef NDEBUG
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define THROW(e)                                                                                                       \
    do {                                                                                                               \
        std::cerr << "Throwing from " << __FILE__ << ":" << __LINE__ << " at " << __PRETTY_FUNCTION__ << '\n';         \
        throw(e);                                                                                                      \
    } while (0);
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define THROW(e)                                                                                                       \
    do {                                                                                                               \
        throw(e);                                                                                                      \
    } while (0);
#endif

/// \brief Debug output, prefixed by session-id and request-id gRPC metadata,
/// and terminated by endline
class dout {
public:
    dout(const grpc::ServerContext &context) {
#ifndef NDEBUG
        static const std::array keys = {"request-id", "test-id"};
        for (const auto &key : keys) {
            auto [begin, end] = context.client_metadata().equal_range(key);
            if (begin != end) {
                out() << key << ':';
                while (begin != end) {
                    out() << begin->second << ' ';
                    ++begin;
                }
            }
        }
#else
        (void) context;
#endif
    }

    static std::ostream &out(void) {
        return std::clog;
    }

    ~dout() {
#ifndef NDEBUG
        out() << std::endl;
#endif
    }

    dout(const dout &other) = delete;
    dout(dout &&other) = delete;
    dout &operator=(const dout &other) = delete;
    dout &operator=(dout &&other) = delete;
};

template <class T>
dout &operator<<(dout &&os, const T &x) {
    dout::out() << x;
    return os;
}

template <class T>
dout &operator<<(dout &os, const T &x) {
    dout::out() << x;
    return os;
}

#include <htif-defines.h>

constexpr const uint64_t ROLLUP_ADVANCE_STATE = 0;
constexpr const uint64_t ROLLUP_INSPECT_STATE = 1;

#include "complete-merkle-tree.h"
#include "htif.h"
#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "protobuf-util.h"
#include "strict-aliasing.h"

// gRPC async server calls involve a variety of objects:
// 1) The service object;
// 2) A server context object;
// 3) One or two server completion queues;
// 4) The protobuf request and response messages;
// 5) A writer object for the response message.
// 6) A request status object
//
// gRPC async server calls have the following life-cycle
// 1) We "request" from the service object that it starts accepting requests
// for a given <RPC-name> by calling service->Request<RPC-name>() method, and
// passing the server context, a request message to receive the request, the
// writer object for the response, the completion queue, and a tag.
// 2) Once a request for <RPC-name> arrives, the completion queue will return
// the corresponding tag
// 3) After performing the requested task, we fill out a response message, and
// ask the writer object to send the response, using writer->Finish(), passing
// the response message, a status object, and a tag
// 4) Once the response has been acknowledged, the completion queue will return
// the tag
//
// PS: To allow for overlapped processing of multiple calls to <RPC-name>, we
// can call service->Request<RPC-name>() with a new tag as soon as the
// completion queue returns the previous tag in 2).
// PS2: In 1), we can pass two completion queues, one to return the tag in 2)
// and another to return the tag in 4). These queues are usually the same.
// PS3: It seems as though a different server context object must be used for
// each call
//
// gRPC async client calls involve fewer objects
// 1) A stub object
// 2) A client context object
// 3) A vanila completion queue
// 4) Protobuf request and response messages
// 5) A reader object for the response message
// 6) A request status object
//
// gRPC async client calls have the following life-cycle
// 1) After filling out a request message, we tell the stub to perform
// <RPC-name> by calling stub->Async<RPC-name>(), passing the client context,
// the request message, and the completion queue. This method returns the reader
// object.
// 2) We then call reader->Finish() passing the response object to be filled,
// the status object to be filled, and a tag
// 3) Once the response is received, the completion queue will return the tag.
//
// In the case of a proxy, the typical situation is that the proxy receives a
// server call that it can only complete after it performed a client call.
// The idea is as follows:
// 1) Completion queue returns tag-1 identifying an <RPC-name> server call
// 2) Processing of tag-1 starts the appropriate client call
// using stub->Async<RPC-name>() and reader->Finish(), and specifes tag-2 for
// completion
// 4) Completion queue returns tag-2 identifying the client call is complete
// 5) Processing of tag-2 passes result back using write->Finish(), and
// specifies tag-3 for completion
// 6) Completion queue returns tag-3 identifying results were received
// 7) Processing of tag-3 calls service->Request<RPC-name>() to specify a new
// tag to handle the next <RPC-name> server call
//
// Rather than using a state-machine to advance the call state through
// all these steps, we use coroutines. Each coroutine handles the entire
// sequence of steps above.
//
// The coroutine always arrives in the completion queue.  If it is already
// "finished", it will be deleted. Otherwise, it will be "resumed". If the
// coroutine returns because it is finished, it will be deleted. If the
// coroutine returns because it "yielded", and if it yielded
// side_effect::shutdown, it will be deleted and the server will be shutdown.
// Otherwise, the coroutine must have yielded side_effect::none, and therefore
// it *must* arrange for itself to arrive again in the completion queue. If it
// doesn't arrange this, it will never be deleted. THIS WILL LEAK.
// Conversely, if the coroutine arranged to be returned from the completion
// queue, it *must* yield instead of finishing. Otherwise, it will be
// immediately deleted and a dangling pointer will be returned by the completion
// queue. THIS WILL CRASH!
//

/// \brief Class to use when computing hashes
using hasher_type = cartesi::keccak_256_hasher;

/// \brief Hash type
using hash_type = hasher_type::hash_type;

/// \brief Merkle tree proof type
using proof_type = cartesi::merkle_tree_proof<hash_type, uint64_t>;

/// \brief Shortcut to time_point type
using time_point_type = std::chrono::time_point<std::chrono::system_clock>;

/// \brief Desired side effect when a handler yields
enum class side_effect {
    none,    ///< do nothing
    shutdown ///< shutdown server
};

/// \brief A handler is simply a coroutine that returns a side_effect
using handler_type = boost::coroutines2::coroutine<side_effect>;

/// \brief Memory range description
struct memory_range_description_type {
    uint64_t index{};
    uint64_t start{};
    uint64_t length{};
    uint64_t log2_size{};
    MemoryRangeConfig config{};
};

constexpr const uint64_t EVM_ADDRESS_LENGTH = 20;
using evm_address_type = std::array<uint8_t, EVM_ADDRESS_LENGTH>;

struct input_metadata_type {
    evm_address_type msg_sender;
    uint64_t block_number;
    uint64_t timestamp;
    uint64_t epoch_index;
    uint64_t input_index;
};

constexpr const int LOG2_ROOT_SIZE = 37;
constexpr const int LOG2_KECCAK_SIZE = 5;
constexpr const uint64_t KECCAK_SIZE = UINT64_C(1) << LOG2_KECCAK_SIZE;
constexpr const uint64_t EVM_ABI_UINT64_LENGTH = 32;
constexpr const uint64_t EVM_ABI_ADDRESS_LENGTH = 32;
constexpr const uint64_t EVM_ABI_OFFSET_LENGTH = 32;
constexpr const uint64_t EVM_ABI_LENGTH_LENGTH = 32;
constexpr const uint64_t VOUCHER_HEADER_LENGTH = EVM_ABI_ADDRESS_LENGTH + EVM_ABI_OFFSET_LENGTH + EVM_ABI_LENGTH_LENGTH;
constexpr const uint64_t EVM_ABI_INPUT_METADATA_LENGTH = EVM_ABI_ADDRESS_LENGTH + 4 * EVM_ABI_UINT64_LENGTH;
constexpr const uint64_t EVM_ABI_STRING_HEADER_LENGTH = EVM_ABI_OFFSET_LENGTH + EVM_ABI_LENGTH_LENGTH;

using evm_abi_input_metadata_type = std::array<uint8_t, EVM_ABI_INPUT_METADATA_LENGTH>;

/// \brief Type holding an AdvanceState input for processing
struct input_type {
    input_type(const input_metadata_type &input_metadata, const std::string &input_payload) : metadata(input_metadata) {
        payload.insert(payload.end(), input_payload.begin(), input_payload.end());
    }
    std::vector<uint8_t> payload;
    input_metadata_type metadata{};
};

/// \brief Type holding an voucher/notice metadata generated by a processed input
struct keccak_type {
    hash_type keccak;
    proof_type keccak_in_hashes;
};

/// \brief Type holding an voucher generated by a processed input
struct voucher_type {
    evm_address_type address;
    std::string payload;
    std::optional<keccak_type> hash;
};

/// \brief Type holding a notice generated by a processed input
struct notice_type {
    std::string payload;
    std::optional<keccak_type> hash;
};

/// \brief Type holding a report generated by a processed input
struct report_type {
    std::string payload;
};

/// \brief Reason why an rpc might have been aborted
enum class completion_status {
    accepted,
    rejected,
    exception,
    machine_halted,
    cycle_limit_exceeded,
    time_limit_exceeded
};

/// \brief Type holding an input that was successfully processed
struct accepted_data_type {
    proof_type voucher_hashes_in_machine;
    std::vector<voucher_type> vouchers;
    proof_type notice_hashes_in_machine;
    std::vector<notice_type> notices;
};

/// \brief Type of exception data (payload)
using exception_data_type = std::string;

/// \brief Type holding a processed input
struct processed_input_type {
    uint64_t input_index;               ///< Index of input in epoch
    hash_type most_recent_machine_hash; ///< Machine hash after processing input
    proof_type voucher_hashes_in_epoch; ///< Proof of the new vouchers entry in the epoch Merkle tree
    proof_type notice_hashes_in_epoch;  ///< Proof of the new notices entry to the epoch Merkle tree
    completion_status status;           ///< Completion status of the processed input
    std::variant<accepted_data_type, exception_data_type> processed; // Accepted data or exception data
    std::vector<report_type> reports; ///< List of reports produced while input was processed
};

/// \brief Type holding an InspectState request/response while it is processed
struct query_type {
    query_type(const std::string &query_payload) {
        payload.insert(payload.end(), query_payload.begin(), query_payload.end());
    }
    std::vector<uint8_t> payload;
    completion_status status{completion_status::accepted};
    handler_type::pull_type *coroutine{nullptr};
    uint64_t current_input_index{0};
    std::optional<exception_data_type> exception_data;
    std::vector<report_type> reports;
};

/// \brief State of epoch
enum class epoch_state { active, finished };

/// \brief Type of session ids
using id_type = std::string;

/// \brief Type holding an epoch;
struct epoch_type {
    uint64_t epoch_index{};
    epoch_state state{epoch_state::active};
    hash_type most_recent_machine_hash{};
    cartesi::complete_merkle_tree vouchers_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
    cartesi::complete_merkle_tree notices_tree{LOG2_ROOT_SIZE, LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE};
    std::vector<processed_input_type> processed_inputs;
    std::deque<input_type> pending_inputs;
    std::optional<query_type> pending_query;
};

/// \brief Type holding the deadlines for varios server tasks
struct deadline_config_type {
    uint64_t checkin{};                 ///< Deadline for receiving checkin from spawned machine
    uint64_t advance_state{};           ///< Deadline for completing the AdvanceState RPC
    uint64_t advance_state_increment{}; ///< Deadline for completing an increment of the AdvanceState RPC
    uint64_t inspect_state{};           ///< Deadline for completing the InspectState RPC
    uint64_t inspect_state_increment{}; ///< Deadline for completing an increment of the InspectState RPC
    uint64_t machine{};                 ///< Deadline for instantiating a machine
    uint64_t store{};                   ///< Deadline for storing a machine
    uint64_t fast{};                    ///< Deadline for quick server operations
};

/// \brief Type holding important memory ranges
struct memory_ranges_type {
    memory_range_description_type rx_buffer{};      ///< RX memory range, where inputs and queries arrive
    memory_range_description_type tx_buffer{};      ///< TX memory range, where vouchers, notices, and reports leave
    memory_range_description_type input_metadata{}; ///< Input metadata memory range
    memory_range_description_type voucher_hashes{}; ///< Voucher hashes memory range
    memory_range_description_type notice_hashes{};  ///< Notice hashes memory range
};

/// \brief Type holding cycle limits for various server tasks
struct cycles_config_type {
    uint64_t max_advance_state{}; ///< Maximum number of cycles that processing the input in an AdvanceState can take
    uint64_t advance_state_increment{}; ///< Number of cycles in each increment to processing an input
    uint64_t max_inspect_state{}; ///< Maximum number of cycles that processing the query in an InspectState can take
    uint64_t inspect_state_increment{}; ///< Number of cycles in each increment to processing a query
};

/// \brief Type holding a session;
struct session_type {
    id_type id{};                                 ///< Session id
    bool session_lock{};                          ///< Session lock
    std::string session_lock_reason{};            ///< Who/why session was locked
    bool processing_lock{};                       ///< Lock for handler processing inputs
    bool tainted{};                               ///< Taint flag
    grpc::Status taint_status{};                  ///< Status explaining why taint flag is set
    std::unique_ptr<Machine::Stub> server_stub{}; ///< Connection to machine server
    uint64_t current_mcycle{};                    ///< Current mcycle for machine in server
    uint64_t active_epoch_index{};                ///< Index of active epoch
    uint64_t max_input_payload_length{};          ///< Maximum length of an input payload
    memory_ranges_type memory_range{};            ///< Important memory ranges
    std::map<uint64_t, epoch_type> epochs{};      ///< Map of cached epochs
    deadline_config_type server_deadline{};       ///< Deadlines for various server tasks
    cycles_config_type server_cycles;             ///< Cycle count limits for various server tasks
    boost::process::group server_process_group{}; ///< remote-cartesi-machine process group
    std::string server_address{};                 ///< remote-cartesi-machine address
};

/// \brief Encodes an input metadata structure according to the EVM ABI
/// \param parsed Structure with input metadata
/// \return EVM ABI encoded data
static evm_abi_input_metadata_type evm_abi_encoded_input_metadata(const input_metadata_type &parsed) {
    using namespace boost::endian;
    evm_abi_input_metadata_type encoded;
    encoded.fill(0);
    std::copy(parsed.msg_sender.begin(), parsed.msg_sender.end(),
        encoded.begin() + EVM_ABI_ADDRESS_LENGTH - EVM_ADDRESS_LENGTH);
    auto *block_number_ptr = encoded.data() + EVM_ABI_ADDRESS_LENGTH + EVM_ABI_UINT64_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(block_number_ptr, parsed.block_number);
    auto *timestamp_ptr = encoded.data() + EVM_ABI_ADDRESS_LENGTH + 2 * EVM_ABI_UINT64_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(timestamp_ptr, parsed.timestamp);
    auto *epoch_index_ptr = encoded.data() + EVM_ABI_ADDRESS_LENGTH + 3 * EVM_ABI_UINT64_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(epoch_index_ptr, parsed.epoch_index);
    auto *input_index_ptr = encoded.data() + EVM_ABI_ADDRESS_LENGTH + 4 * EVM_ABI_UINT64_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(input_index_ptr, parsed.input_index);
    return encoded;
}

/// \brief Automatically unlocks a session when out of scope
class auto_lock final {
public:
    /// \brief Constructor acquires locks
    /// \param lock Reference to lock to be acquired
    auto_lock(bool &lock, std::string name) : m_lock{lock}, m_name{std::move(name)} {
        acquire();
    }

    auto_lock(const auto_lock &other) = delete;
    auto_lock(auto_lock &&other) = delete;
    auto_lock &operator=(const auto_lock &other) = delete;
    auto_lock &operator=(auto_lock &&other) = delete;

    /// \brief Acquire lock if it is not already locked
    void acquire(void) {
        if (m_lock) {
            THROW((std::runtime_error{m_name + " already locked"}));
        } else {
            m_lock = true;
        }
    }

    /// \brief Release lock if it is acquired
    void release(void) {
        if (!m_lock) {
            THROW((std::runtime_error{m_name + " not locked"}));
        } else {
            m_lock = false;
        }
    }

    /// \brief Desctructor automatically releases lock
    ~auto_lock() {
        m_lock = false;
    }

private:
    bool &m_lock;
    std::string m_name;
};

/// \brief Context shared by all handlers
struct handler_context {
    std::string remote_cartesi_machine_path;            ///< Path to remote-cartesi-machine executable
    std::string manager_address;                        ///< Address to which manager is bound
    std::string server_address;                         ///< Address to which machine servers are bound
    std::unordered_map<id_type, session_type> sessions; ///< Known sessions
    /// Sessions waiting for server checkin
    std::unordered_map<id_type, handler_type::pull_type *> sessions_waiting_checkin;
    ServerManager::AsyncService manager_async_service;             ///< Assynchronous manager service
    MachineCheckIn::AsyncService checkin_async_service;            ///< Assynchronous checkin service
    std::unique_ptr<grpc::ServerCompletionQueue> completion_queue; ///< Completion queue where all handlers arrive
    bool ok;                                                       ///< gRPC status of requests arriving in queue
};

/// \brief Context for internal functions that need to perform async operations
struct async_context {
    session_type &session;
    const grpc::ServerContext &request_context;
    grpc::ServerCompletionQueue *completion_queue;
    handler_type::pull_type *self;
    handler_type::push_type &yield;
};

/// \brief Schedule a coroutine to be returned immediately by the completion queue
static void enqueue_completion_queue(grpc::ServerCompletionQueue *cq, handler_type::pull_type *self) {
    grpc::Alarm alarm;
    alarm.Set(cq, gpr_now(gpr_clock_type::GPR_CLOCK_REALTIME), self);
}

/// \brief Checks if integer is a power of 2
/// \param value Integer to test
/// \return True if integer is power of 2, false otherwise
static inline bool is_power_of_two(uint64_t value) {
    return value > 0 && (value & (value - 1)) == 0;
}

/// \brief Computes to Log<sub>2</sub> of an integer
/// \param v Integer from which to compute Log<sub>2</sub>
/// \detail The return value is undefined if v == 0
/// This works on gcc and clang and uses the lzcnt instruction
static inline uint64_t ilog2(uint64_t v) {
    return 63 - __builtin_clzll(v);
}

/// \brief Base class for exceptions holding a grpc::Status
class handler_exception : public std::exception {
public:
    explicit handler_exception(grpc::Status status) : m_status{std::move(status)} {}
    handler_exception(grpc::StatusCode code, const std::string &message) : m_status{code, message} {}
    const grpc::Status &status(void) const {
        return m_status;
    }

private:
    grpc::Status m_status;
};

/// \brief Exception thrown when RPC reached an error after it was restarted
class finish_error_yield_none : public handler_exception {
public:
    using handler_exception::handler_exception;
};

/// \brief Exception thrown when an error condition prevents further interactions with the session
class taint_session : public std::exception {
public:
    taint_session(session_type &tainted, grpc::Status status) : m_session{tainted}, m_status{std::move(status)} {}
    taint_session(session_type &tainted, grpc::StatusCode code, const std::string &message) :
        m_session{tainted},
        m_status{code, message} {}
    const grpc::Status &status(void) const {
        return m_status;
    }
    session_type &session(void) const {
        return m_session;
    }

private:
    session_type &m_session;
    grpc::Status m_status;
};

/// \brief Creates a new handler for the GetVersion RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetVersion_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        Void request;
        ServerAsyncResponseWriter<GetVersionResponse> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestGetVersion(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_GetVersion_handler(hctx);
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        dout{request_context} << "Received GetVersion";
        Status status;
        GetVersionResponse response;
        auto *version = response.mutable_version();
        version->set_major(manager_version_major);
        version->set_minor(manager_version_minor);
        version->set_patch(manager_version_patch);
        version->set_pre_release(manager_version_pre_release);
        version->set_build(manager_version_build);
        writer.Finish(response, grpc::Status::OK, self);
        yield(side_effect::none);
    }};
    return self;
}

/// \brief Creates a new handler for the GetStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetStatus_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        Void request;
        ServerAsyncResponseWriter<GetStatusResponse> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestGetStatus(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_GetStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) { // NOLINT: Unknown. Maybe linter bug?
            return;
        }
        dout{request_context} << "Received GetStatus";
        Status status;
        GetStatusResponse response;
        for (const auto &[session_id, session] : hctx.sessions) {
            dout{request_context} << "  " << session_id;
            response.add_session_id(session_id);
        }
        writer.Finish(response, grpc::Status::OK, self); // NOLINT: Unknown. Maybe linter bug?
        yield(side_effect::none);
    }};
    return self;
}

/// \brief Sets a deadline for the request in a ClientContext
/// \param deadline Deadline in milliseconds
static inline void set_deadline(grpc::ClientContext &client_context, uint64_t deadline) {
    client_context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(deadline));
}

/// \brief Asynchronously stores current machine to directory.
/// \param actx Context for async operations
/// \param directory Directory to store session
static void store(async_context &actx, const std::string &directory) {
    StoreRequest request;
    request.set_directory(directory);
    Void response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.store);
    auto reader = actx.session.server_stub->AsyncStore(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
}

/// \brief Marks epoch finished and update all proofs now that all leaves are present
/// \param e Associated epoch
static void finish_epoch(epoch_type &e) {
    e.state = epoch_state::finished;
    for (auto &i : e.processed_inputs) {
        i.voucher_hashes_in_epoch = e.vouchers_tree.get_proof(i.input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
        i.notice_hashes_in_epoch = e.notices_tree.get_proof(i.input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
    }
}

/// \brief Start a new epoch in session
/// \param session Associated session
static void start_new_epoch(epoch_type &prev_epoch, session_type &session) {
    session.active_epoch_index++;
    epoch_type e;
    e.epoch_index = session.active_epoch_index;
    e.state = epoch_state::active;
    e.most_recent_machine_hash = prev_epoch.most_recent_machine_hash;
    session.epochs[e.epoch_index] = std::move(e);
}

/// \brief Gives a description for why the session was locked
static std::string get_session_lock_reason(const std::string &rpc, const std::string &peer) {
    return "RPC " + rpc + " from " + peer;
}

/// \brief Creates a new handler for the FinishEpoch RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_FinishEpoch_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        FinishEpochRequest request;
        ServerAsyncResponseWriter<Void> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestFinishEpoch(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_FinishEpoch_handler(hctx);
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            Status status;
            Void response;
            auto &sessions = hctx.sessions;
            const auto &id = request.session_id();
            auto epoch_index = request.active_epoch_index();
            dout{request_context} << "Received FinishEpoch for session " << id << " epoch " << epoch_index;
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If active_epoch_index is too large, bail
            if (session.active_epoch_index == UINT64_MAX) {
                THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "active epoch index will overflow"}));
            }
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("FinishEpoch", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "FinishEpoch session lock");
            session.session_lock_reason = new_lock_reason;
            // If session is tainted, report potential data loss
            if (session.tainted) {
                THROW((finish_error_yield_none{grpc::StatusCode::DATA_LOSS, "session is tainted"}));
            }
            auto &epochs = session.epochs;
            // If epoch is unknown, a bail out
            if (epochs.find(epoch_index) == epochs.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "unknown epoch index"}));
            }
            auto &e = epochs[epoch_index];
            // If epoch is not active, bail out
            if (e.state != epoch_state::active) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "epoch already finished"}));
            }
            // If there are still pending inputs to process, bail out
            if (!e.pending_inputs.empty()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "epoch still has pending inputs"}));
            }
            // If the number of processed inputs does not match the expecte, bail out
            if (e.processed_inputs.size() != request.processed_input_count()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "incorrect processed input count (expected " + std::to_string(e.processed_inputs.size()) +
                        ", got " + std::to_string(request.processed_input_count()) + ")"}));
            }
            // Try to store session before we change anything
            if (!request.storage_directory().empty()) {
                dout{request_context} << "  Storing into " << request.storage_directory();
                async_context actx{session, request_context, hctx.completion_queue.get(), self, yield};
                store(actx, request.storage_directory());
            }
            finish_epoch(e);
            start_new_epoch(e, session);
            writer.Finish(response, grpc::Status::OK, self);
            yield(side_effect::none);
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
            writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Asynchronously shutsdown the machine server
/// \param actx Context for async operations
static void shutdown_server(async_context &actx) {
    dout{actx.request_context} << "  Shutting server down";
    Void request;
    Void response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncShutdown(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
}

/// \brief Creates a new handler for the EndSession RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_EndSession_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        EndSessionRequest request;
        ServerAsyncResponseWriter<Void> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestEndSession(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_EndSession_handler(hctx);
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            Status status;
            Void response;
            auto &sessions = hctx.sessions;
            const auto &id = request.session_id();
            dout{request_context} << "Received EndSession for session " << id;
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("EndSession", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "EndSession session lock");
            session.session_lock_reason = new_lock_reason;
            async_context actx{session, request_context, cq, self, yield};
            // If the session is tainted, nothing is going on with it, so we can erase it
            if (!session.tainted) {
                // If the session is not tainted, we will only delete it if the active epoch is pristine
                auto &epochs = session.epochs;
                auto &e = epochs[session.active_epoch_index];
                if (!e.pending_inputs.empty()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                        "active epoch has pending inputs"}));
                }
                if (!e.processed_inputs.empty()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                        "active epoch has processed inputs"}));
                }
            }
            // This is just for peace of mind, there no way this branch can enter
            if (session.processing_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "session is processing inputs!"}));
            }
            shutdown_server(actx);
            if (session.tainted) {
                dout{request_context} << "Session " << id
                                      << " is tainted. Terminating remote-cartesi-machine process group";
                session.server_process_group.terminate();
            }
            sessions.erase(id);
            writer.Finish(response, grpc::Status::OK, self);
            yield(side_effect::none);
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
            writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Creates a new handler for the GetSessionStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetSessionStatus_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        GetSessionStatusRequest request;
        ServerAsyncResponseWriter<GetSessionStatusResponse> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestGetSessionStatus(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_GetSessionStatus_handler(hctx);
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        Status status; // NOLINT: cannot leak (pointer is in completion queue)
        GetSessionStatusResponse response;
        auto &sessions = hctx.sessions;
        const auto &id = request.session_id();
        dout{request_context} << "Received GetSessionStatus for session " << id;
        try {
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found!"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("GetSessionStatus", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "GetSessionStatus session lock");
            session.session_lock_reason = new_lock_reason;
            response.set_session_id(id);
            response.set_active_epoch_index(session.active_epoch_index);
            for (const auto &[index, epoch] : session.epochs) {
                dout{request_context} << "  " << index;
                response.add_epoch_index(index);
            }
            if (session.tainted) {
                response.mutable_taint_status()->set_error_code(session.taint_status.error_code());
                response.mutable_taint_status()->set_error_message(session.taint_status.error_message());
            }
            writer.Finish(response, grpc::Status::OK, self);
            yield(side_effect::none);
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
            writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Converts C++ address to proto Address
/// \param a C++ address to convert
/// \param proto_a Pointer to proto Address receiving result of conversion
static void set_proto_evm_address(const evm_address_type &a, Address *proto_a) {
    proto_a->set_data(a.data(), a.size());
}

/// \brief Converts proto Address to C++ address
/// \param proto_a Proto Address to convert
/// \returns Converted C++ address
evm_address_type get_proto_evm_address(const Address &proto_a) {
    evm_address_type a;
    if (proto_a.data().size() != a.size()) {
        throw std::invalid_argument("invalid address size");
    }
    memcpy(a.data(), proto_a.data().data(), proto_a.data().size());
    return a;
}

/// \brief Fills out Voucher message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_voucher(const voucher_type &o, Voucher *proto_o) {
    set_proto_evm_address(o.address, proto_o->mutable_address());
    proto_o->set_payload(o.payload);
    if (o.hash.has_value()) {
        cartesi::set_proto_hash(o.hash.value().keccak, proto_o->mutable_keccak());
        cartesi::set_proto_proof(o.hash.value().keccak_in_hashes, proto_o->mutable_keccak_in_voucher_hashes());
    }
}

/// \brief Fills out Notice message from structure
/// \param m Structure
/// \param proto_m Pointer to message receiving structure contents
static void set_proto_notice(const notice_type &m, Notice *proto_m) {
    proto_m->set_payload(m.payload);
    if (m.hash.has_value()) {
        cartesi::set_proto_hash(m.hash.value().keccak, proto_m->mutable_keccak());
        cartesi::set_proto_proof(m.hash.value().keccak_in_hashes, proto_m->mutable_keccak_in_notice_hashes());
    }
}

/// \brief Fills out Report message from structure
/// \param m Structure
/// \param proto_m Pointer to message receiving structure contents
static void set_proto_report(const report_type &m, Report *proto_m) {
    proto_m->set_payload(m.payload);
}

/// \brief Fills out ProcessedInput accepted data message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_accepted_data(const processed_input_type &i, ProcessedInput *proto_i) {
    if (std::holds_alternative<accepted_data_type>(i.processed)) {
        const auto &data = std::get<accepted_data_type>(i.processed);
        auto *accepted_data_p = proto_i->mutable_accepted_data();
        cartesi::set_proto_proof(data.voucher_hashes_in_machine, accepted_data_p->mutable_voucher_hashes_in_machine());
        for (const auto &o : data.vouchers) {
            set_proto_voucher(o, accepted_data_p->add_vouchers());
        }
        cartesi::set_proto_proof(data.notice_hashes_in_machine, accepted_data_p->mutable_notice_hashes_in_machine());
        for (const auto &m : data.notices) {
            set_proto_notice(m, accepted_data_p->add_notices());
        }
    }
}

/// \brief Fills out ProcessedInput exception data message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_exception_data(const processed_input_type &i, ProcessedInput *proto_i) {
    if (std::holds_alternative<std::string>(i.processed)) {
        const auto &data = std::get<std::string>(i.processed);
        proto_i->set_exception_data(data);
    }
}

/// \brief Fills out ProcessedInput message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_processed_input(const processed_input_type &i, ProcessedInput *proto_i) {
    proto_i->set_input_index(i.input_index);
    cartesi::set_proto_hash(i.most_recent_machine_hash, proto_i->mutable_most_recent_machine_hash());
    cartesi::set_proto_proof(i.voucher_hashes_in_epoch, proto_i->mutable_voucher_hashes_in_epoch());
    cartesi::set_proto_proof(i.notice_hashes_in_epoch, proto_i->mutable_notice_hashes_in_epoch());
    for (const auto &r : i.reports) {
        set_proto_report(r, proto_i->add_reports());
    }
    switch (i.status) {
        case completion_status::accepted:
            proto_i->set_status(CompletionStatus::ACCEPTED);
            set_proto_accepted_data(i, proto_i);
            break;
        case completion_status::rejected:
            proto_i->set_status(CompletionStatus::REJECTED);
            break;
        case completion_status::exception:
            proto_i->set_status(CompletionStatus::EXCEPTION);
            set_proto_exception_data(i, proto_i);
            break;
        case completion_status::machine_halted:
            proto_i->set_status(CompletionStatus::MACHINE_HALTED);
            break;
        case completion_status::cycle_limit_exceeded:
            proto_i->set_status(CompletionStatus::CYCLE_LIMIT_EXCEEDED);
            break;
        case completion_status::time_limit_exceeded:
            proto_i->set_status(CompletionStatus::TIME_LIMIT_EXCEEDED);
            break;
    }
}

/// \brief Creates a new handler for the GetEpochStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetEpochStatus_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        GetEpochStatusRequest request;
        ServerAsyncResponseWriter<GetEpochStatusResponse> writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        hctx.manager_async_service.RequestGetEpochStatus(&request_context, &request, &writer, cq, cq, self);
        yield(side_effect::none);
        new_GetEpochStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            GetEpochStatusResponse response; // NOLINT: Unknown. Maybe linter bug?
            auto &sessions = hctx.sessions;
            const auto &id = request.session_id();
            auto epoch_index = request.epoch_index();
            dout{request_context} << "Received GetEpochStatus for session " << id << " epoch " << epoch_index;
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("GetEpochStatus", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "GetEpochStatus session lock");
            session.session_lock_reason = new_lock_reason;
            auto &epochs = session.epochs;
            // If a session is unknown, a bail out
            if (epochs.find(epoch_index) == epochs.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "unknown epoch index"}));
            }
            auto &e = epochs[epoch_index];
            response.set_session_id(id);
            response.set_epoch_index(epoch_index);
            switch (e.state) {
                case epoch_state::active:
                    response.set_state(EpochState::ACTIVE);
                    break;
                case epoch_state::finished:
                    response.set_state(EpochState::FINISHED);
                    break;
            }
            for (const auto &i : e.processed_inputs) {
                set_proto_processed_input(i, response.add_processed_inputs());
            }
            response.set_pending_input_count(e.pending_inputs.size());
            if (session.tainted) {
                response.mutable_taint_status()->set_error_code(session.taint_status.error_code());
                response.mutable_taint_status()->set_error_message(session.taint_status.error_message());
            }
            cartesi::set_proto_hash(e.most_recent_machine_hash, response.mutable_most_recent_machine_hash());
            cartesi::set_proto_hash(e.vouchers_tree.get_root_hash(),
                response.mutable_most_recent_vouchers_epoch_root_hash());
            cartesi::set_proto_hash(e.notices_tree.get_root_hash(),
                response.mutable_most_recent_notices_epoch_root_hash());
            writer.Finish(response, grpc::Status::OK, self);
            yield(side_effect::none);
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
            writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Initializes new deadline config structure from request
/// \param proto_p Corresponding DeadlineConfig
static auto get_proto_deadline_config(const DeadlineConfig &proto_p) {
    deadline_config_type d{};
    d.checkin = proto_p.checkin();
    d.advance_state = proto_p.advance_state();
    d.advance_state_increment = proto_p.advance_state_increment();
    d.inspect_state = proto_p.inspect_state();
    d.inspect_state_increment = proto_p.inspect_state_increment();
    d.machine = proto_p.machine();
    d.store = proto_p.store();
    d.fast = proto_p.fast();
    return d;
}

/// \brief Initializes new input_metadata structure from request
/// \param proto_p Corresponding InputMetadata
static auto get_proto_input_metadata(const InputMetadata &proto_p) {
    input_metadata_type i{};
    i.msg_sender = get_proto_evm_address(proto_p.msg_sender());
    i.block_number = proto_p.block_number();
    i.timestamp = proto_p.timestamp();
    i.epoch_index = proto_p.epoch_index();
    i.input_index = proto_p.input_index();
    return i;
}

/// \brief Initializes new cycles config structure from request
/// \param proto_p Corresponding CyclesConfig
static auto get_proto_cycles_config(const CyclesConfig &proto_p) {
    cycles_config_type c{};
    c.max_advance_state = proto_p.max_advance_state();
    c.advance_state_increment = proto_p.advance_state_increment();
    c.max_inspect_state = proto_p.max_inspect_state();
    c.inspect_state_increment = proto_p.inspect_state_increment();
    return c;
}

/// \brief Initializes new session structure from request
/// \param request Corresponding StartSessionRequest
static auto get_proto_session(const StartSessionRequest &request) {
    session_type session;
    session.id = request.session_id();
    session.session_lock = false;
    session.tainted = false;
    session.processing_lock = false;
    session.active_epoch_index = request.active_epoch_index();
    session.server_deadline = get_proto_deadline_config(request.server_deadline());
    session.server_cycles = get_proto_cycles_config(request.server_cycles());
    return session;
}

/// \brief Asynchronously checks that server version matches manager
/// \param actx Context for async operations
static void check_server_version(async_context &actx) {
    dout{actx.request_context} << "  Checking server version";
    // Try to get version from client
    GetVersionResponse response;
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncGetVersion(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
    // If version is incompatible, bail out
    if (response.version().major() != machine_version_major || response.version().minor() != machine_version_minor) {
        THROW((finish_error_yield_none{grpc::StatusCode::FAILED_PRECONDITION,
            "manager is incompatible with machine server"}));
    }
}

/// \brief Asynchronously starts a machine in the server
/// \param actx Context for async operations
/// \param request Machine request received from StartSession RPC
static void check_server_machine(async_context &actx, const std::string &directory) {
    dout{actx.request_context} << "  Instantiating machine " << directory;
    MachineRequest request;
    request.set_directory(directory);
    Void response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.machine);
    auto reader = actx.session.server_stub->AsyncMachine(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
}

/// \brief Asynchronously gets the initial machine configuration from server
/// \param actx Context for async operations
/// \return Initial MachineConfig returned by server
static MachineConfig get_initial_config(async_context &actx) {
    dout{actx.request_context} << "  Getting initial config";
    Void request;
    GetInitialConfigResponse response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncGetInitialConfig(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
    return response.config();
}

/// \brief Checks that a memory range config is valid
/// \param request_context ServerContext used by handler
/// \param name Name of memory range
/// \param config MemoryRangeConfig returned by server
static void check_memory_range_config(grpc::ServerContext &request_context, memory_range_description_type &desc,
    const std::string &name, const MemoryRangeConfig &config) {
    dout{request_context} << "  Checking " << name << " buffer config";
    desc.config = config;
    if (desc.config.shared()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, name + " buffer cannot be shared"}));
    }
    // Clear the image_filename because we use the config with replace_memory_range to clear the memory range
    desc.config.clear_image_filename();
    desc.length = desc.config.length();
    if (!is_power_of_two(desc.length)) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE,
            name + " memory range length not a power of two (" + std::to_string(desc.length) + ")"}));
    }
    desc.log2_size = ilog2(desc.length);
    desc.start = desc.config.start();
    auto aligned_start = (desc.start >> desc.log2_size) << desc.log2_size;
    if ((desc.start != aligned_start)) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE,
            name + " memory range start not aligned to its power of two size"}));
    }
}

/// \brief Checks HTIF device configuration is valid for rollups
/// \param htif HTIFConfig returned by server
static void check_htif_config(const HTIFConfig &htif) {
    if (!htif.yield_manual()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "yield manual must be enabled"}));
    }
    if (!htif.yield_automatic()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "yield automatic must be enabled"}));
    }
    if (htif.console_getchar()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "console getchar must be disabled"}));
    }
}

/// \brief Checks if rollup configuration is valid for rollups
/// \param config MachineConfig returned by server
static void check_rollup_config(grpc::ServerContext &request_context, session_type &session,
    const MachineConfig &config) {
    // If rollup config, bail out
    if (!config.has_rollup()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "missing server rollup config"}));
    }
    const auto &rollup = config.rollup();
    if (rollup.rx_buffer().length() == 0 && rollup.tx_buffer().length() == 0 && rollup.input_metadata().length() == 0 &&
        rollup.voucher_hashes().length() == 0 && rollup.notice_hashes().length() == 0) {
        THROW(
            (finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "server rollup config was not initialized"}));
    }
    check_memory_range_config(request_context, session.memory_range.tx_buffer, "tx buffer", rollup.tx_buffer());
    check_memory_range_config(request_context, session.memory_range.rx_buffer, "rx buffer", rollup.rx_buffer());
    check_memory_range_config(request_context, session.memory_range.input_metadata, "input metadata",
        rollup.input_metadata());
    check_memory_range_config(request_context, session.memory_range.voucher_hashes, "voucher hashes",
        rollup.voucher_hashes());
    check_memory_range_config(request_context, session.memory_range.notice_hashes, "notice hashes",
        rollup.notice_hashes());
}

/// \brief Start and checks the server stub
/// \param session Associated session
static void check_server_stub(session_type &session) {
    // Instantiate client connection
    session.server_stub =
        Machine::NewStub(grpc::CreateChannel(session.server_address, grpc::InsecureChannelCredentials()));
    // If unable to create stub, bail out
    if (!session.server_stub) {
        THROW((finish_error_yield_none{grpc::StatusCode::RESOURCE_EXHAUSTED,
            "unable to create machine stub for session"}));
    }
}

template <class T>
void trigger_and_wait_checkin(handler_context &hctx, async_context &actx, T trigger_checkin) {
    // trigger remote check-in
    dout{actx.request_context} << "  Triggering machine server check-in";
    hctx.sessions_waiting_checkin[actx.session.id] = actx.self;
    trigger_checkin(hctx, actx); // NOLINT: avoid boost warnings?
    // Wait for CheckIn
    dout{actx.request_context} << "  Waiting check-in";
    actx.yield(side_effect::none);
    dout{actx.request_context} << "  Check-in for session " << actx.session.id << " passed with address "
                               << actx.session.server_address;
    // update server stub
    check_server_stub(actx.session);
}

/// \brief Extracts the data field in HTIF's fromhost/tohost register value
/// \param reg Old register value
/// \param data New data field
/// \return Register value with replaced data field
static constexpr uint64_t htif_replace_data_field(uint64_t reg, uint64_t data) {
    return (reg & (~HTIF_DATA_MASK_DEF)) | ((data << HTIF_DATA_SHIFT_DEF) & HTIF_DATA_MASK_DEF);
}

/// \brief Obtains the dev field in HTIF's fromhost/tohost register value
/// \return Dev data field in register
static constexpr uint64_t htif_dev_field(uint64_t reg) {
    return (reg & HTIF_DEV_MASK_DEF) >> HTIF_DEV_SHIFT_DEF;
}

/// \brief Extracts the cmd field in HTIF's fromhost/tohost register value
/// \return cmd data field in register
static constexpr uint64_t htif_cmd_field(uint64_t reg) {
    return (reg & HTIF_CMD_MASK_DEF) >> HTIF_CMD_SHIFT_DEF;
}

/// \brief Extracts the data field in HTIF's fromhost/tohost register value
/// \return cmd data field in register
static constexpr uint64_t htif_data_field(uint64_t reg) {
    return (reg & HTIF_DATA_MASK_DEF) >> HTIF_DATA_SHIFT_DEF;
}

/// \brief Checks if HTIF's tohost/fromhost matches an yield device manual command
/// \param actx Context for async operations
/// \param regname "htif.tohost" or "htif.fromhost"
/// \param value Register value
static void check_htif_yield_manual(async_context &actx, const std::string &regname, uint64_t value) {
    auto dev = htif_dev_field(value);
    if (dev != HTIF_DEVICE_YIELD_DEF) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
            "invalid dev field in " + regname + " (expected " + std::to_string(HTIF_DEVICE_YIELD_DEF) + ", got " +
                std::to_string(dev) + ")"}));
    }
    auto cmd = htif_cmd_field(value);
    if (cmd != HTIF_YIELD_MANUAL_DEF) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
            "invalid cmd field in " + regname + " (expected " + std::to_string(HTIF_YIELD_MANUAL_DEF) + ", got " +
                std::to_string(cmd) + ")"}));
    }
}

/// \brief Checks if HTIF's tohost matches an yield reason equal to accepted
/// \param value Register value
static void check_yield_reason_accepted(uint64_t value) {
    auto data = htif_data_field(value) << 16 >> 48;
    if (data != HTIF_YIELD_REASON_RX_ACCEPTED_DEF) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
            "invalid data field in htif.tohost (expected " + std::to_string(HTIF_YIELD_REASON_RX_ACCEPTED_DEF) +
                ", got " + std::to_string(data) + ")"}));
    }
}

/// \brief Asynchronously gets the value of MCYCLE CSR
/// \param actx Context for async operations
/// \return Register value
static uint64_t get_current_mcycle(async_context &actx) {
    dout{actx.request_context} << "  Reading machine current mcycle";
    ReadCsrRequest request;
    request.set_csr(Csr::MCYCLE);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadCsr(&client_context, request, actx.completion_queue);
    grpc::Status status;
    ReadCsrResponse response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{std::move(status)}));
    }
    return response.value();
}

/// \brief Asynchronously runs the machine until it is in an yielded state
/// \param actx Context for async operations
static uint64_t check_is_yielded(async_context &actx) {
    // if already yielded manual, this won't change anything
    auto current_mcycle = get_current_mcycle(actx);
    dout{actx.request_context} << "  Checking machine is yielded";
    RunRequest run_request;
    run_request.set_limit(current_mcycle); // This will not change the machine
    grpc::ClientContext client_context;
    auto reader = actx.session.server_stub->AsyncRun(&client_context, run_request, actx.completion_queue);
    grpc::Status run_status;
    RunResponse run_response;
    reader->Finish(&run_response, &run_status, actx.self);
    actx.yield(side_effect::none);
    if (!run_status.ok()) {
        THROW((finish_error_yield_none{std::move(run_status)}));
    }
    if (!run_response.iflags_y()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "expected manual yield"}));
    }
    if (current_mcycle != run_response.mcycle()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "mcycle shouldn't have changed"}));
    }
    check_htif_yield_manual(actx, "htif.tohost", run_response.tohost());
    check_yield_reason_accepted(run_response.tohost());
    return run_response.mcycle();
}

/// \brief Asynchronously get current root hash from machine server. (Assumes Merkle tree has been updated)
/// \param actx Context for async operations
static hash_type get_root_hash(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncGetRootHash(&client_context, request, actx.completion_queue);
    grpc::Status status;
    GetRootHashResponse response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
    return cartesi::get_proto_hash(response.hash());
}

/// \brief Starts the first epoch in a session
/// \param actx Context for async operations
/// \param session Session where first epoch should be started
static void start_first_epoch(async_context &actx, session_type &session) {
    epoch_type e;
    e.epoch_index = session.active_epoch_index;
    e.state = epoch_state::active;
    e.most_recent_machine_hash = get_root_hash(actx);
    session.epochs[e.epoch_index] = std::move(e);
}

/// \brief Creates a new handler for the StartSession RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_StartSession_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        StartSessionRequest start_session_request;
        ServerAsyncResponseWriter<StartSessionResponse> start_session_writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        // Wait for a StartSession RPC
        hctx.manager_async_service.RequestStartSession(&request_context, &start_session_request, &start_session_writer,
            cq, cq, self);
        yield(side_effect::none);
        new_StartSession_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            // We now received a StartSession RPC
            auto &sessions = hctx.sessions; // NOLINT: Unknown. Maybe linter bug?
            const auto &id = start_session_request.session_id();
            dout{request_context} << "Received StartSession request for session " << id;
            // Empty id is invalid, so a bail out
            if (id.empty()) {
                start_session_writer.FinishWithError(grpc::Status{StatusCode::INVALID_ARGUMENT, "session id is empty"},
                    self);
                yield(side_effect::none);
                return;
            }
            // If a session with this id already exists, a bail out
            if (sessions.find(id) != sessions.end()) {
                start_session_writer.FinishWithError(grpc::Status{StatusCode::ALREADY_EXISTS, "session id is taken"},
                    self);
                yield(side_effect::none);
                return;
            }
            // Allocate a new session with data from request
            auto &session = (sessions[id] = get_proto_session(start_session_request));
            // Lock session so other rpcs to the same session are rejected
            auto new_lock_reason = get_session_lock_reason("StartSession", request_context.peer());
            auto_lock lock(session.session_lock, "StartSession session lock");
            session.session_lock_reason = new_lock_reason;
            // If no machine config or directory is set on machine request, bail out
            if (start_session_request.machine_directory().empty()) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "missing machine directory"}));
            }
            // If active_epoch_index is too large, bail
            if (session.active_epoch_index == UINT64_MAX) {
                THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "active epoch index will overflow"}));
            }
            // If no deadline config, bail out
            if (!start_session_request.has_server_deadline()) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "missing server deadline config"}));
            }
            // If advance_state deadline is less than advance_state_increment deadline, bail out
            if (session.server_deadline.advance_state < session.server_deadline.advance_state_increment) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "advance state deadline is less than advance state increment deadline"}));
            }
            // If inspect_state deadline is less than inspect_state_increment deadline, bail out
            if (session.server_deadline.inspect_state < session.server_deadline.inspect_state_increment) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "inspect state deadline is less than inspect state increment deadline"}));
            }
            // If no cycles config, bail out
            if (!start_session_request.has_server_cycles()) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "missing server cycles config"}));
            }
            // If advance state have no cycles to complete, bail out
            if (session.server_cycles.max_advance_state == 0 || session.server_cycles.advance_state_increment == 0) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "max cycles per advance state or cycles per advance state increment is zero"}));
            }
            // If max cycles per advance state is less than cycles per advance state increment, bail out
            if (session.server_cycles.max_advance_state < session.server_cycles.advance_state_increment) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "max cycles per advance state is less than cycles per advance state increment"}));
            }
            // If inspect state have no cycles to complete, bail out
            if (session.server_cycles.max_inspect_state == 0 || session.server_cycles.inspect_state_increment == 0) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "max cycles per inspect state or cycles per inspect state increment is zero"}));
            }
            // If max cycles per inspect state is less than cycles per inspect state increment, bail out
            if (session.server_cycles.max_inspect_state < session.server_cycles.inspect_state_increment) {
                THROW((finish_error_yield_none{StatusCode::INVALID_ARGUMENT,
                    "max cycles per inspect state is less than cycles per inspect state increment"}));
            }
            // Wait for machine server to checkin after spawned
            async_context actx{session, request_context, cq, self, yield};
            trigger_and_wait_checkin(hctx, actx, [](handler_context &hctx, async_context &actx) {
                // Spawn a new server and ask it to check-in
                auto cmdline = hctx.remote_cartesi_machine_path + " --session-id=" + actx.session.id +
                    " --checkin-address=" + hctx.manager_address + " --server-address=" + hctx.server_address;
                dout{actx.request_context} << "  Spawning " << cmdline;
                try {
                    // NOLINTNEXTLINE: boost generated warnings
                    auto server_process = boost::process::child(cmdline, actx.session.server_process_group);
                    server_process.detach();
                } catch (boost::process::process_error &e) {
                    THROW((finish_error_yield_none{StatusCode::INTERNAL,
                        "failed spawning remote-cartesi-machine with command-line '" + cmdline + "' (" + e.what() +
                            ")"}));
                }
            });
            try {
                check_server_version(actx);
                check_server_machine(actx, start_session_request.machine_directory());
                auto config = get_initial_config(actx);
                check_htif_config(config.htif());
                check_rollup_config(request_context, session, config);
                // Machine may have started at mcycle != 0, so we save it for
                // when we need to run an input for at most max_cycles_per_input
                session.current_mcycle = check_is_yielded(actx);
                start_first_epoch(actx, session);
                // StartSession Passed!
                StartSessionResponse start_session_response;
                start_session_response.set_allocated_config(&config);
                start_session_writer.Finish(start_session_response, grpc::Status::OK, self);
                yield(side_effect::none);
                (void) start_session_response.release_config();
            } catch (...) {
                // If there is any error here, we try to shutdown the machine server
                grpc::ClientContext client_context;
                set_deadline(client_context, session.server_deadline.fast);
                Void request;
                Void response;
                auto status = session.server_stub->Shutdown(&client_context, request, &response);
                throw; // rethrow so it is caught outside and we report the error
            }
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
            hctx.sessions.erase(start_session_request.session_id());
            start_session_writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            hctx.sessions.erase(start_session_request.session_id());
            start_session_writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Asynchronously clears the rx buffer, input metadata, voucher hashes, and notice hashes memory ranges
/// \param actx Context for async operations
static void clear_memory_ranges(async_context &actx) {
    std::array<std::pair<MemoryRangeConfig *, const char *>, 4> range_configs = {
        std::make_pair(&actx.session.memory_range.rx_buffer.config, "rx buffer"),
        std::make_pair(&actx.session.memory_range.input_metadata.config, "input metadata"),
        std::make_pair(&actx.session.memory_range.voucher_hashes.config, "voucher hashes"),
        std::make_pair(&actx.session.memory_range.notice_hashes.config, "notice hashes")};
    for (auto config : range_configs) {
        dout{actx.request_context} << "      clearing " << config.second;
        ReplaceMemoryRangeRequest replace_request;
        replace_request.set_allocated_config(config.first);
        Void replace_response;
        grpc::ClientContext client_context;
        set_deadline(client_context, actx.session.server_deadline.fast);
        auto reader =
            actx.session.server_stub->AsyncReplaceMemoryRange(&client_context, replace_request, actx.completion_queue);
        grpc::Status replace_status;
        reader->Finish(&replace_response, &replace_status, actx.self);
        actx.yield(side_effect::none);
        (void) replace_request.release_config();
        if (!replace_status.ok()) {
            THROW((taint_session{actx.session, std::move(replace_status)}));
        }
    }
}

/// \brief Asynchronously clears the rx buffer
/// \param actx Context for async operations
static void clear_rx_buffer(async_context &actx) {
    ReplaceMemoryRangeRequest replace_request;
    replace_request.set_allocated_config(&actx.session.memory_range.rx_buffer.config);
    Void replace_response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader =
        actx.session.server_stub->AsyncReplaceMemoryRange(&client_context, replace_request, actx.completion_queue);
    grpc::Status replace_status;
    reader->Finish(&replace_response, &replace_status, actx.self);
    actx.yield(side_effect::none);
    (void) replace_request.release_config();
    if (!replace_status.ok()) {
        THROW((taint_session{actx.session, std::move(replace_status)}));
    }
}

/// \brief Asynchronously writes data to a memory range
/// \param actx Context for async operations
/// \param begin First byte to write
/// \param end One past last byte to write
/// \param drive MemoryRangeConfig describing drive
template <typename IT>
static void write_memory_range(async_context &actx, IT begin, IT end, const MemoryRangeConfig &drive) {
    WriteMemoryRequest write_request;
    write_request.set_address(drive.start());
    auto *data = write_request.mutable_data();
    data->insert(data->end(), begin, end);
    Void write_response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncWriteMemory(&client_context, write_request, actx.completion_queue);
    grpc::Status write_status;
    reader->Finish(&write_response, &write_status, actx.self);
    actx.yield(side_effect::none);
    if (!write_status.ok()) {
        THROW((taint_session{actx.session, std::move(write_status)}));
    }
}

/// \brief Asynchronously writes an EVM ABI string to a memory range
/// \param actx Context for async operations
/// \param begin First byte to write
/// \param end One past last byte to write
/// \param drive MemoryRangeConfig describing drive
template <typename IT>
static void write_evm_abi_string(async_context &actx, IT begin, IT end, const MemoryRangeConfig &drive) {
    using namespace boost::endian;
    WriteMemoryRequest write_request;
    write_request.set_address(drive.start());
    auto *data = write_request.mutable_data();
    std::array<unsigned char, EVM_ABI_STRING_HEADER_LENGTH> header{};
    header.fill(0);
    auto *offset_ptr = header.data() + EVM_ABI_OFFSET_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(offset_ptr, EVM_ABI_OFFSET_LENGTH);
    auto *length_ptr = header.data() + EVM_ABI_OFFSET_LENGTH + EVM_ABI_LENGTH_LENGTH - sizeof(uint64_t);
    endian_store<uint64_t, sizeof(uint64_t), order::big>(length_ptr, end - begin);
    data->insert(data->end(), header.begin(), header.end());
    data->insert(data->end(), begin, end);
    Void write_response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncWriteMemory(&client_context, write_request, actx.completion_queue);
    grpc::Status write_status;
    reader->Finish(&write_response, &write_status, actx.self);
    actx.yield(side_effect::none);
    if (!write_status.ok()) {
        THROW((taint_session{actx.session, std::move(write_status)}));
    }
}

/// \brief Asynchronously runs machine server up to given max cycle
/// \param actx Context for async operations
/// \param curr_mcycle current mcycle
/// \param mcycle_increment increment to mcycle in call to machine run
/// \param max_mcycle mcycle limit
/// \param start_time Time point given start of operation
/// \param deadline_increment maximum time in ms allowed for mcycle increment
/// \param max_deadline maximum time in ms allowed for entire run
/// \return RunResponse returned by machine server, or nothing if deadline expired
static std::optional<RunResponse> run_machine(async_context &actx, uint64_t curr_mcycle, uint64_t mcycle_increment,
    uint64_t max_mcycle, time_point_type start_time, uint64_t deadline_increment, uint64_t max_deadline) {
    // We will run in increments of mcycle_increment cycles. The assumption is that
    // the emulator will finish these increments faster than the deadline_increment deadline.
    // After each increment, if the machine has not yielded, or halted, or we haven't reached max_mcycle,
    // we check the total time elapsed against the max_deadline deadline.
    // If the max_deadline expired, we return nothing but the server is responsive.
    // If the request for any single increment does not return by the deadline_increment deadline,
    // we assume the machine is not responsive and therefore we taint the session.
    auto limit = std::min(curr_mcycle + mcycle_increment, max_mcycle);
    int i = 0;
    for (;;) {
        dout{actx.request_context} << "  Running advance/inspect state increment " << i++;
        RunRequest run_request;
        run_request.set_limit(limit);
        grpc::ClientContext client_context;
        set_deadline(client_context, deadline_increment);
        auto reader = actx.session.server_stub->AsyncRun(&client_context, run_request, actx.completion_queue);
        grpc::Status run_status;
        RunResponse run_response;
        reader->Finish(&run_response, &run_status, actx.self);
        actx.yield(side_effect::none);
        if (!run_status.ok()) {
            THROW((taint_session{actx.session, std::move(run_status)}));
        }
        // Check if yielded or halted or reached max_mcycle and return
        if (run_response.iflags_y() || run_response.iflags_x() || run_response.iflags_h() ||
            run_response.mcycle() >= max_mcycle) {
            return run_response;
        }
        // Check if max_deadline has expired.
        auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start_time)
                .count();
        if (elapsed > static_cast<decltype(elapsed)>(max_deadline)) {
            return {};
        }
        // Move on to next chunk
        limit = std::min(limit + mcycle_increment, max_mcycle);
    }
}

/// \brief Asynchronously reads the contents of a memory range
/// \param actx Context for async operations
/// \param drive MemoryRangeConfig describing range
/// \return String with range contents
static std::string read_memory_range(async_context &actx, const MemoryRangeConfig &range) {
    ReadMemoryRequest read_request;
    read_request.set_address(range.start());
    read_request.set_length(range.length());
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, std::move(read_status)}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we
    // want to move out
    auto *data = read_response.release_data();
    return data ? std::move(*data) : std::string{};
}

/// \brief Checkes if all values are null
/// \param begin First element
/// \param end One past last element
/// \return True if all are null, false otherwie
template <typename IT>
static inline bool is_null(IT begin, IT end) {
    while (begin != end) {
        if (*begin) {
            return false;
        }
        ++begin;
    }
    return true;
}

/// \brief Counts number of entries until the first null entry
/// \param data String with binary data
/// \param entry_length Length of each entry
/// \return Number of entries
static uint64_t count_null_terminated_entries(const std::string &data, int entry_length) {
    auto begin = data.begin();
    uint64_t count = 0;
    while (begin + entry_length <= data.end()) {
        if (is_null(begin, begin + entry_length)) {
            return count;
        }
        count++;
        begin += entry_length;
    }
    return count;
}

/// \brief Converts a string to a hash
/// \param begin Start of hash data
/// \param end one-past-end of hash data
/// \return Converted hash
template <typename IT>
static inline hash_type get_hash(session_type &session, IT begin, IT end) {
    hash_type hash;
    if (end - begin != hash.size()) {
        THROW((taint_session{session, grpc::StatusCode::OUT_OF_RANGE, "invalid hash length"}));
    }
    std::copy(begin, end, hash.begin());
    return hash;
}

/// \brief Converts a string to an EVM address
/// \param begin Start of address data
/// \param end one-past-end of address data
/// \return Converted address
template <typename IT>
static inline evm_address_type get_evm_address(session_type &session, IT begin, IT end) {
    evm_address_type a;
    if (end - begin != a.size()) {
        THROW((taint_session{session, grpc::StatusCode::OUT_OF_RANGE, "invalid address length"}));
    }
    std::copy(begin, end, a.begin());
    return a;
}

/// \brief Converts a payload length from large big-endian to a native 64-bit integer
/// \param session Session to taint in case of error
/// \param begin Start of large big-endian number
/// \param end one-past-end of large big-endian number
/// \return Converted 64-bit native integer
static inline uint64_t get_payload_length(session_type &session, const char *begin, const char *end) {
    using namespace boost::endian;
    if (!is_null(begin, end - sizeof(uint64_t))) {
        THROW((taint_session{session, grpc::StatusCode::OUT_OF_RANGE, "payload length too large"}));
    }
    return endian_load<uint64_t, sizeof(uint64_t), order::big>(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<const unsigned char *>(end) - sizeof(uint64_t));
}

/// \brief Asynchronously reads an voucher address and payload data length from the tx buffer
/// \param actx Context for async operations
/// \param payload_data_length Receives payload data length
/// \return Address for voucher
static evm_address_type read_voucher_address_and_payload_data_length(async_context &actx,
    uint64_t *payload_data_length) {
    ReadMemoryRequest read_request;
    const MemoryRangeConfig &range = actx.session.memory_range.tx_buffer.config;
    read_request.set_address(range.start());
    read_request.set_length(VOUCHER_HEADER_LENGTH);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, std::move(read_status)}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    const auto *payload_data_length_begin =
        read_response.data().data() + EVM_ABI_ADDRESS_LENGTH + EVM_ABI_OFFSET_LENGTH;
    const auto *payload_data_length_end = payload_data_length_begin + EVM_ABI_LENGTH_LENGTH;
    *payload_data_length = get_payload_length(actx.session, payload_data_length_begin, payload_data_length_end);
    auto address_begin = read_response.data().begin() + EVM_ABI_ADDRESS_LENGTH - EVM_ADDRESS_LENGTH;
    auto address_end = address_begin + EVM_ADDRESS_LENGTH;
    return get_evm_address(actx.session, address_begin, address_end);
}

/// \brief Asynchronously reads an voucher payload data from the tx buffer
/// \param actx Context for async operations
/// \param payload_data_length Length of payload data in entry
/// \return Contents of voucher payload data
static std::string read_voucher_payload_data(async_context &actx, uint64_t payload_data_length) {
    auto payload_data_offset = VOUCHER_HEADER_LENGTH;
    const MemoryRangeConfig &range = actx.session.memory_range.tx_buffer.config;
    if (payload_data_length > actx.session.memory_range.tx_buffer.length - payload_data_offset) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "voucher payload length is out of bounds"}));
    }
    ReadMemoryRequest read_request;
    read_request.set_address(range.start() + payload_data_offset);
    read_request.set_length(payload_data_length);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, std::move(read_status)}));
    }
    if (read_response.data().size() != payload_data_length) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we want to move out
    auto *data = read_response.release_data();
    return data ? std::move(*data) : std::string{};
}

/// \brief Asynchronously reads a notice or report data length from the tx buffer
/// \param actx Context for async operations
/// \return Payload data length for notice or report
static uint64_t read_tx_payload_data_length(async_context &actx) {
    ReadMemoryRequest read_request;
    const MemoryRangeConfig &range = actx.session.memory_range.tx_buffer.config;
    read_request.set_address(range.start());
    read_request.set_length(EVM_ABI_STRING_HEADER_LENGTH);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, std::move(read_status)}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    const auto *payload_data_length_begin = read_response.data().data() + EVM_ABI_OFFSET_LENGTH;
    const auto *payload_data_length_end = payload_data_length_begin + EVM_ABI_LENGTH_LENGTH;
    return get_payload_length(actx.session, payload_data_length_begin, payload_data_length_end);
}

/// \brief Asynchronously reads a notice or report payload data from the tx buffer
/// \param actx Context for async operations
/// \param payload_data_length Length of payload data in entry
/// \return Contents of notice payload data
static std::string read_tx_payload_data(async_context &actx, uint64_t payload_data_length) {
    auto payload_data_offset = EVM_ABI_STRING_HEADER_LENGTH;
    const MemoryRangeConfig &range = actx.session.memory_range.tx_buffer.config;
    if (payload_data_length > actx.session.memory_range.tx_buffer.length - payload_data_offset) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "notice payload length is out of bounds"}));
    }
    ReadMemoryRequest read_request;
    read_request.set_address(range.start() + payload_data_offset);
    read_request.set_length(payload_data_length);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, std::move(read_status)}));
    }
    if (read_response.data().size() != payload_data_length) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we want to move out
    auto *data = read_response.release_data();
    return data ? std::move(*data) : std::string{};
}

/// \brief Gets a Merkle tree proof from the machine server
/// \param actx Context for async operations
/// \param address Target node address
/// \param log2_size Log<sub>2</sub> of target node
/// \return Proof that target node belongs to Merkle tree
static proof_type get_proof(async_context &actx, uint64_t address, uint64_t log2_size) {
    GetProofRequest proof_request;
    proof_request.set_address(address);
    proof_request.set_log2_size(log2_size);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncGetProof(&client_context, proof_request, actx.completion_queue);
    grpc::Status proof_status;
    GetProofResponse proof_response;
    reader->Finish(&proof_response, &proof_status, actx.self);
    actx.yield(side_effect::none);
    if (!proof_status.ok()) {
        THROW((taint_session{actx.session, std::move(proof_status)}));
    }
    return cartesi::get_proto_proof(proof_response.proof());
}

/// \brief Asynchronously reads an voucher from the tx buffer
/// \param actx Context for async operations
/// \return Voucher
static voucher_type read_voucher(async_context &actx) {
    uint64_t payload_data_length = 0;
    dout{actx.request_context} << "      Reading voucher address and length";
    auto address = read_voucher_address_and_payload_data_length(actx, &payload_data_length);
    dout{actx.request_context} << "      Reading voucher payload of length " << payload_data_length;
    auto payload_data = read_voucher_payload_data(actx, payload_data_length);
    return {std::move(address), std::move(payload_data), {}};
}

/// \brief Asynchronously reads a notice from the tx buffer
/// \param actx Context for async operations
/// \return Notice
static notice_type read_notice(async_context &actx) {
    dout{actx.request_context} << "      Reading notice length";
    auto payload_data_length = read_tx_payload_data_length(actx);
    dout{actx.request_context} << "      Reading notice payload of length " << payload_data_length;
    auto payload_data = read_tx_payload_data(actx, payload_data_length);
    return {std::move(payload_data), {}};
}

/// \brief Asynchronously reads a report from the tx buffer
/// \param actx Context for async operations
/// \return Report
static report_type read_report(async_context &actx) {
    dout{actx.request_context} << "      Reading report length";
    auto payload_data_length = read_tx_payload_data_length(actx);
    dout{actx.request_context} << "      Reading report payload of length " << payload_data_length;
    auto payload_data = read_tx_payload_data(actx, payload_data_length);
    return {std::move(payload_data)};
}

/// \brief Asynchronously reads an exception from the tx buffer
/// \param actx Context for async operations
/// \return Exception
static std::string read_exception(async_context &actx) {
    dout{actx.request_context} << "      Reading exception length";
    auto payload_data_length = read_tx_payload_data_length(actx);
    dout{actx.request_context} << "      Reading exception payload of length " << payload_data_length;
    return read_tx_payload_data(actx, payload_data_length);
}

/// \brief Asynchronously creates a new machine server snapshot. Used before processing an input.
/// \param actx Context for async operations
static void snapshot(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncSnapshot(&client_context, request, actx.completion_queue);
    grpc::Status status;
    Void response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
}

/// \brief Asynchronously rollback machine server. Used after an input was skipped.
/// \param actx Context for async operations
static void rollback(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncRollback(&client_context, request, actx.completion_queue);
    grpc::Status status;
    Void response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
}

/// \brief Asynchronously resets the iflags.y flag after a machine has yielded
/// \param actx Context for async operations
static void reset_iflags_y(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncResetIflagsY(&client_context, request, actx.completion_queue);
    grpc::Status status;
    Void response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
}

/// \brief Asynchronously gets the value of HTIF's fromhost CSR
/// \param actx Context for async operations
/// \return Register value
static uint64_t get_htif_fromhost(async_context &actx) {
    ReadCsrRequest request;
    request.set_csr(Csr::HTIF_FROMHOST);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadCsr(&client_context, request, actx.completion_queue);
    grpc::Status status;
    ReadCsrResponse response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
    return response.value();
}

/// \brief Asynchronously sets the value of HTIF's fromhost CSR
/// \param actx Context for async operations
/// \param value New register value
static void set_htif_fromhost(async_context &actx, uint64_t value) {
    WriteCsrRequest request;
    request.set_csr(Csr::HTIF_FROMHOST);
    request.set_value(value);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncWriteCsr(&client_context, request, actx.completion_queue);
    grpc::Status status;
    Void response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, std::move(status)}));
    }
}

/// \brief Asynchronously sets htif fromhost ack to specify a given request
/// \param actx Context for async operations
static void set_htif_yield_ack_data(async_context &actx, uint64_t reqid) {
    auto old_value = get_htif_fromhost(actx);
    check_htif_yield_manual(actx, "htif.fromhost", old_value);
    set_htif_fromhost(actx, htif_replace_data_field(old_value, reqid));
}

/// \brief Asynchronously check htif fromhost ack
/// \param actx Context for async operations
static void check_htif_yield_ack_data(async_context &actx, uint64_t reqid) {
    auto value = get_htif_fromhost(actx);
    check_htif_yield_manual(actx, "htif.fromhost", value);
    auto data = htif_data_field(value);
    if (data != reqid) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
            "invalid data field in htif.fromhost (expected " + std::to_string(reqid) + ", got " + std::to_string(data) +
                ")"}));
    }
}

/// \brief Processes a pending query
/// \param actx Context for async operations
/// \param e Associated epoch
static void process_pending_query(handler_context &hctx, async_context &actx, epoch_type &e) {
    if (!e.pending_query.has_value()) { // should never happen
        return;
    }
    auto &q = e.pending_query.value();
    q.current_input_index = e.pending_inputs.size() + e.processed_inputs.size();
    dout{actx.request_context} << "  Processing pending query";
    dout{actx.request_context} << "    Creating Snapshot";
    // Wait machine server to checkin after spawned
    trigger_and_wait_checkin(hctx, actx, [](handler_context &hctx, async_context &actx) {
        (void) hctx;
        snapshot(actx);
    });
    dout{actx.request_context} << "    Clearing rx buffer";
    clear_rx_buffer(actx);
    dout{actx.request_context} << "    Writing rx buffer";
    write_evm_abi_string(actx, q.payload.begin(), q.payload.end(), actx.session.memory_range.rx_buffer.config);
    dout{actx.request_context} << "    Resetting iflags_Y";
    reset_iflags_y(actx);
    dout{actx.request_context} << "    Setting inspect request in htif fromhost";
    set_htif_yield_ack_data(actx, ROLLUP_INSPECT_STATE);
    auto max_mcycle = actx.session.current_mcycle + actx.session.server_cycles.max_inspect_state;
    // Loop getting reports until the machine exceeds max_mcycle, rejects the query, accepts the query,
    // or behaves inaproppriately
    q.status = completion_status::accepted;
    auto start_time = std::chrono::system_clock::now();
    auto current_mcycle = actx.session.current_mcycle;
    auto mcycle_increment = actx.session.server_cycles.inspect_state_increment;
    auto deadline_increment = actx.session.server_deadline.inspect_state_increment;
    auto max_deadline = actx.session.server_deadline.inspect_state;
    for (;;) {
        auto run_response = run_machine(actx, current_mcycle, mcycle_increment, max_mcycle, start_time,
            deadline_increment, max_deadline);
        if (!run_response.has_value()) {
            q.status = completion_status::time_limit_exceeded;
            dout{actx.request_context} << "    Query aborted because time limit was exceeded";
            break;
        }
        if (run_response.value().mcycle() >= max_mcycle) {
            q.status = completion_status::cycle_limit_exceeded;
            dout{actx.request_context} << "    Query aborted because cycle limit was exceeded";
            break;
        }
        if (run_response.value().iflags_h()) {
            q.status = completion_status::machine_halted;
            dout{actx.request_context} << "    Query aborted because machine is halted";
            break;
        }
        uint64_t yield_reason = run_response.value().tohost() << 16 >> 48;
        // process manual yields
        if (run_response.value().iflags_y()) {
            if (yield_reason == cartesi::HTIF_YIELD_REASON_RX_REJECTED) {
                q.status = completion_status::rejected;
                dout{actx.request_context} << "    Query aborted because machine rejected it";
                break;
            } else if (yield_reason == cartesi::HTIF_YIELD_REASON_RX_ACCEPTED) {
                q.status = completion_status::accepted;
                dout{actx.request_context} << "    Query accepted";
                break;
            } else if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_EXCEPTION) {
                q.status = completion_status::exception;
                dout{actx.request_context} << "    Received an exception while executing query";
                q.exception_data = read_exception(actx);
                break;
            }
            THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "unknown machine yield reason"}));
        }
        if (!run_response.value().iflags_x()) {
            THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
                "machine returned without hitting mcycle limit or yielding"}));
        }
        // process automatic yields
        if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_REPORT) {
            dout{actx.request_context} << "    Reading report " << q.reports.size();
            q.reports.push_back(read_report(actx));
        } // else ignore automatic yield
        // advance current mcycle and continue
        current_mcycle = run_response.value().mcycle();
    }
    dout{actx.request_context} << "  Done processing query";
    dout{actx.request_context} << "    Rolling back";
    // Wait machine server to checkin after spawned
    trigger_and_wait_checkin(hctx, actx, [](handler_context &hctx, async_context &actx) {
        (void) hctx;
        rollback(actx);
    });
}

/// \brief Loops processing all pending inputs
/// \param actx Context for async operations
/// \param e Associated epoch
static void process_pending_inputs(handler_context &hctx, async_context &actx, epoch_type &e) {
    // This is just for peace of mind: there is no way two concurrent calls can happen
    // (See discussion where process_pending_inputs is called.)
    if (actx.session.processing_lock) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
            "concurrent input processing detected in session"}));
    }
    auto_lock processing_lock(actx.session.processing_lock, "process_pending_inputs processing lock");
    while (!e.pending_inputs.empty()) {
        auto input_index = e.processed_inputs.size();
        dout{actx.request_context} << "  Processing input " << input_index;
        dout{actx.request_context} << "    Creating Snapshot";
        // Wait machine server to checkin after spawned
        trigger_and_wait_checkin(hctx, actx, [](handler_context &hctx, async_context &actx) {
            (void) hctx;
            snapshot(actx);
        });
        dout{actx.request_context} << "    Clearing buffers";
        clear_memory_ranges(actx);
        const auto &i = e.pending_inputs.front();
        dout{actx.request_context} << "    Writing rx buffer";
        write_evm_abi_string(actx, i.payload.begin(), i.payload.end(), actx.session.memory_range.rx_buffer.config);
        dout{actx.request_context} << "    Writing input metadata";
        auto metadata = evm_abi_encoded_input_metadata(i.metadata);
        write_memory_range(actx, metadata.begin(), metadata.end(), actx.session.memory_range.input_metadata.config);
        dout{actx.request_context} << "    Resetting iflags_Y";
        reset_iflags_y(actx);
        check_htif_yield_ack_data(actx, ROLLUP_ADVANCE_STATE);
        auto max_mcycle = actx.session.current_mcycle + actx.session.server_cycles.max_advance_state;
        // Loop getting vouchers and notices until the machine exceeds
        // max_mcycle, rejects the input, accepts the input, or behaves inaproppriately
        completion_status skip_reason = completion_status::accepted;
        auto start_time = std::chrono::system_clock::now();
        auto current_mcycle = actx.session.current_mcycle;
        auto mcycle_increment = actx.session.server_cycles.advance_state_increment;
        auto deadline_increment = actx.session.server_deadline.advance_state_increment;
        auto max_deadline = actx.session.server_deadline.advance_state;
        std::vector<voucher_type> vouchers;
        std::vector<notice_type> notices;
        std::vector<report_type> reports;
        exception_data_type exception_data;
        for (;;) {
            auto run_response = run_machine(actx, current_mcycle, mcycle_increment, max_mcycle, start_time,
                deadline_increment, max_deadline);
            if (!run_response.has_value()) {
                skip_reason = completion_status::time_limit_exceeded;
                dout{actx.request_context} << "    Input skipped because time limit was exceeded";
                break;
            }
            if (run_response.value().mcycle() >= max_mcycle) {
                skip_reason = completion_status::cycle_limit_exceeded;
                dout{actx.request_context} << "    Input skipped because cycle limit was exceeded";
                break;
            }
            if (run_response.value().iflags_h()) {
                skip_reason = completion_status::machine_halted;
                dout{actx.request_context} << "    Input skipped because machine is halted";
                break;
            }
            uint64_t yield_reason = run_response.value().tohost() << 16 >> 48;
            // process manual yields
            if (run_response.value().iflags_y()) {
                if (yield_reason == cartesi::HTIF_YIELD_REASON_RX_REJECTED) {
                    skip_reason = completion_status::rejected;
                    dout{actx.request_context} << "    Input skipped because machine requested";
                    break;
                } else if (yield_reason == cartesi::HTIF_YIELD_REASON_RX_ACCEPTED) {
                    // no skip reason because it was not skipped
                    dout{actx.request_context} << "    Input accepted";
                    current_mcycle = run_response.value().mcycle();
                    break;
                } else if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_EXCEPTION) {
                    skip_reason = completion_status::exception;
                    dout{actx.request_context} << "    Received an exception while processing input";
                    exception_data = read_exception(actx);
                    break;
                }
                THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "unknown machine yield reason"}));
            }
            if (!run_response.value().iflags_x()) {
                THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
                    "machine returned without hitting mcycle limit or yielding"}));
            }
            // process automatic yields
            if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_VOUCHER) {
                dout{actx.request_context} << "    Reading voucher " << vouchers.size();
                // read voucher payload
                vouchers.push_back(read_voucher(actx));
            } else if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_NOTICE) {
                dout{actx.request_context} << "    Reading notice " << notices.size();
                notices.push_back(read_notice(actx));
            } else if (yield_reason == cartesi::HTIF_YIELD_REASON_TX_REPORT) {
                dout{actx.request_context} << "    Reading report " << reports.size();
                reports.push_back(read_report(actx));
            } // else ignore automatic yield
            // advance current mcycle and continue
            current_mcycle = run_response.value().mcycle();
        }
        if (e.vouchers_tree.size() != input_index) {
            THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
                "inconsistent number of entries in epoch's session vouchers Merkle tree"}));
        }
        if (e.notices_tree.size() != input_index) {
            THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL,
                "inconsistent number of entries in epoch's session notices Merkle tree"}));
        }
        // If the machine accepted the input
        if (skip_reason == completion_status::accepted) {
            // Read proof of voucher hashes memory range in machine
            dout{actx.request_context} << "    Getting voucher hashes memory range proof";
            auto voucher_hashes_in_machine = get_proof(actx, actx.session.memory_range.voucher_hashes.start,
                actx.session.memory_range.voucher_hashes.log2_size);
            // Get proof of voucher hashes memory range in epoch
            e.vouchers_tree.push_back(voucher_hashes_in_machine.get_target_hash());
            auto voucher_hashes_in_epoch = e.vouchers_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Read voucher hashes memory range and count the number of non-zero hashes
            dout{actx.request_context} << "    Reading voucher hashes memory range";
            auto voucher_hashes = read_memory_range(actx, actx.session.memory_range.voucher_hashes.config);
            uint64_t voucher_count = count_null_terminated_entries(voucher_hashes, KECCAK_SIZE);
            dout{actx.request_context} << "    Voucher count " << voucher_count;
            if (voucher_count != vouchers.size()) {
                THROW((taint_session{actx.session, grpc::StatusCode::INVALID_ARGUMENT,
                    "number of vouchers yielded and non-zero voucher hashes disagree"}));
            }
            // Get hash for each voucher
            for (uint64_t entry_index = 0; entry_index < voucher_count; ++entry_index) {
                auto keccak = get_hash(actx.session, &voucher_hashes[entry_index * KECCAK_SIZE],
                    &voucher_hashes[(entry_index + 1) * KECCAK_SIZE]);
                dout{actx.request_context} << "      Getting proof of keccak " << entry_index
                                           << " in voucher hashes memory range";
                auto keccak_in_voucher_hashes =
                    get_proof(actx, actx.session.memory_range.voucher_hashes.start + entry_index * KECCAK_SIZE,
                        LOG2_KECCAK_SIZE)
                        .slice(hasher_type{}, static_cast<int>(actx.session.memory_range.voucher_hashes.log2_size),
                            LOG2_KECCAK_SIZE);
                vouchers[entry_index].hash = keccak_type{std::move(keccak), std::move(keccak_in_voucher_hashes)};
            }
            // Read proof of notice hashes memory range in machine
            dout{actx.request_context} << "    Getting notice hashes memory range proof";
            auto notice_hashes_in_machine = get_proof(actx, actx.session.memory_range.notice_hashes.start,
                actx.session.memory_range.notice_hashes.log2_size);
            // Get proof of notice hashes memory range in epoch
            e.notices_tree.push_back(notice_hashes_in_machine.get_target_hash());
            auto notice_hashes_in_epoch = e.notices_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Read notice hashes memory range count the number of non-zero hashes
            dout{actx.request_context} << "    Reading notice hashes memory range";
            auto notice_hashes = read_memory_range(actx, actx.session.memory_range.notice_hashes.config);
            uint64_t notice_count = count_null_terminated_entries(notice_hashes, KECCAK_SIZE);
            dout{actx.request_context} << "    Notice count " << notice_count;
            if (notice_count != notices.size()) {
                THROW((taint_session{actx.session, grpc::StatusCode::INVALID_ARGUMENT,
                    "number notices yielded and non-zero notice hashes disagree"}));
            }
            // Get hash for each notice
            for (uint64_t entry_index = 0; entry_index < notice_count; ++entry_index) {
                auto keccak = get_hash(actx.session, &notice_hashes[entry_index * KECCAK_SIZE],
                    &notice_hashes[(entry_index + 1) * KECCAK_SIZE]);
                dout{actx.request_context} << "      Getting proof of keccak " << entry_index
                                           << " in notice hashes memory range";
                auto keccak_in_notice_hashes =
                    get_proof(actx, actx.session.memory_range.notice_hashes.start + entry_index * KECCAK_SIZE,
                        LOG2_KECCAK_SIZE)
                        .slice(hasher_type{}, static_cast<int>(actx.session.memory_range.notice_hashes.log2_size),
                            LOG2_KECCAK_SIZE);
                notices[entry_index].hash = keccak_type{std::move(keccak), std::move(keccak_in_notice_hashes)};
            }
            // Update most recent machine hash in epoch
            e.most_recent_machine_hash = get_root_hash(actx);
            // Add input results to list of processed inputs
            e.processed_inputs.push_back(processed_input_type{input_index, e.most_recent_machine_hash,
                std::move(voucher_hashes_in_epoch), std::move(notice_hashes_in_epoch), skip_reason,
                accepted_data_type{
                    std::move(voucher_hashes_in_machine),
                    std::move(vouchers),
                    std::move(notice_hashes_in_machine),
                    std::move(notices),
                },
                std::move(reports)});
            // Advance session.current_mcycle
            actx.session.current_mcycle = current_mcycle;
            dout{actx.request_context} << "  Done processing input " << input_index;
        } else {
            dout{actx.request_context} << "  Skipped input " << input_index;
            dout{actx.request_context} << "    Rolling back";
            // Wait machine server to checkin after spawned
            trigger_and_wait_checkin(hctx, actx, [](handler_context &hctx, async_context &actx) {
                (void) hctx;
                rollback(actx);
            });
            // Add null hashes to the epoch Merkle trees
            hash_type zero;
            std::fill_n(zero.begin(), zero.size(), 0);
            // Get proof of null hash in epoch's vouchers metadata memory range Merkle tree
            e.vouchers_tree.push_back(zero);
            auto voucher_hashes_in_epoch = e.vouchers_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Get proof of null hash in epoch's notices metadata memory range Merkle tree
            e.notices_tree.push_back(zero);
            auto notice_hashes_in_epoch = e.notices_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Check the machine hash has not changed
            if (e.most_recent_machine_hash != get_root_hash(actx)) {
                THROW((
                    taint_session{actx.session, grpc::StatusCode::INTERNAL, "machine hash is changed after rollback"}));
            }
            // Add skipped input to list of processed inputs
            e.processed_inputs.push_back(
                processed_input_type{input_index, e.most_recent_machine_hash, std::move(voucher_hashes_in_epoch),
                    std::move(notice_hashes_in_epoch), skip_reason, std::move(exception_data), std::move(reports)});
            // Leave session.current_mcycle alone
        }
        // Check if there is a pending query
        if (e.pending_query.has_value()) {
            // Resume its coroutine so it can process the query and complete the InspectState rpc
            // To do so, we use an alarm to add the coroutine to the completion queue, then we yield
            // Once the coroutine is done, it will use the same process to add us back to the completion queue
            enqueue_completion_queue(hctx.completion_queue.get(), e.pending_query.value().coroutine);
            e.pending_query.value().coroutine = actx.self;
            actx.yield(side_effect::none);
        }
        // Finally remove pending
        e.pending_inputs.pop_front();
    }
}

/// \brief Creates a new handler for the AdvanceState RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_AdvanceState_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        AdvanceStateRequest advance_state_request;
        ServerAsyncResponseWriter<Void> advance_state_writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        // Wait for a AdvanceState RPC
        hctx.manager_async_service.RequestAdvanceState(&request_context, &advance_state_request, &advance_state_writer,
            cq, cq, self);
        yield(side_effect::none);
        // We now received a AdvanceState
        // We will handle other AdvanceState rpcs if we yield, but not in the same session, due to the session lock
        new_AdvanceState_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            // Check if session id exists
            auto &sessions = hctx.sessions; // NOLINT: Unknown. Maybe linter bug?
            const auto &id = advance_state_request.session_id();
            dout{request_context} << "Received AdvanceState for session " << id << " epoch "
                                  << advance_state_request.active_epoch_index();
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found!"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If active_epoch_index is too large, bail
            if (session.active_epoch_index == UINT64_MAX) {
                THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "active epoch index will overflow"}));
            }
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("AdvanceState", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "AdvanceState session lock");
            session.session_lock_reason = new_lock_reason;
            // If session is tainted, report potential data loss
            if (session.tainted) {
                THROW((finish_error_yield_none{grpc::StatusCode::DATA_LOSS, "session is tainted"}));
            }
            // If active epoch does not match expected, bail out
            if (session.active_epoch_index != advance_state_request.active_epoch_index()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "incorrect active epoch index (expected " + std::to_string(session.active_epoch_index) + ", got " +
                        std::to_string(advance_state_request.active_epoch_index()) + ")"}));
            }
            // We should be able to find the active epoch, otherwise bail
            auto &epochs = session.epochs;
            if (epochs.find(session.active_epoch_index) == epochs.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "active epoch not found"}));
            }
            auto &e = epochs[session.active_epoch_index];
            // If epoch is finished, bail out
            if (e.state != epoch_state::active) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "epoch is finished"}));
            }
            // If current input does not match expected, bail out
            auto current_input_index = e.pending_inputs.size() + e.processed_inputs.size();
            if (current_input_index != advance_state_request.current_input_index()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "incorrect current input index (expected " + std::to_string(current_input_index) + ", got " +
                        std::to_string(advance_state_request.current_input_index()) + ")"}));
            }
            // Check size of input payload
            const auto input_payload_size = advance_state_request.input_payload().size();
            dout{request_context} << "  Input payload size " << input_payload_size;
            if (input_payload_size + EVM_ABI_STRING_HEADER_LENGTH >= session.memory_range.rx_buffer.length) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "input payload too long for rx buffer length (expected " +
                        std::to_string(session.memory_range.rx_buffer.length - EVM_ABI_STRING_HEADER_LENGTH) +
                        " bytes max, got " + std::to_string(input_payload_size) + " bytes)"}));
            }
            // Check input metadata
            if (!advance_state_request.has_input_metadata()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "missing input metadata"}));
            }
            if (!advance_state_request.input_metadata().has_msg_sender()) {
                THROW(
                    (finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "missing input metadata msg_sender"}));
            }
            if (advance_state_request.input_metadata().msg_sender().data().size() != EVM_ADDRESS_LENGTH) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "invalid input metadata msg_sender length (expected " + std::to_string(EVM_ADDRESS_LENGTH) +
                        " bytes, got " +
                        std::to_string(advance_state_request.input_metadata().msg_sender().data().size()) +
                        " bytes)"}));
            }
            auto input_metadata = get_proto_input_metadata(advance_state_request.input_metadata());
            // Double-check that epoch index and input index are correct
            if (input_metadata.epoch_index != session.active_epoch_index) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "input metadata epoch index (" + std::to_string(input_metadata.epoch_index) +
                        ") is inconsistent with active epoch index (" + std::to_string(session.active_epoch_index) +
                        ")"}));
            }
            if (input_metadata.input_index != current_input_index) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "input metadata input index (" + std::to_string(input_metadata.input_index) +
                        ") is inconsistent with current input index (" + std::to_string(current_input_index) + ")"}));
            }
            // Enqueue input
            e.pending_inputs.emplace_back(input_metadata, advance_state_request.input_payload());
            // Tell caller RPC succeeded
            Void advance_state_response;
            advance_state_writer.Finish(advance_state_response, grpc::Status::OK, self);
            yield(side_effect::none); // Here the session is still locked, so no concurrent calls are possible
            // Release the lock so other RPCs can enqueue additional inputs to the same session/epoch or call inspect
            // state
            session_lock.release();
            // Between unlocking the session and the check here, there is no
            // yield, and so no other AdvanceState RPC can be in flight for
            // the same session. This means that the handler entering the
            // branch will be exactly the handler that enqueued the input that
            // caused the pending_inputs queue to not be empty anymore. While
            // working on this single input, the handler can yield (because
            // it talks to the machine server asynchronously) and allow
            // other AdvanceState RPCs to grow the pending_inputs queue further.
            // However, those other RPCs will not enter the branch, because
            // process_pending_inputs only removes an item from the queue when
            // it is completely done with it. Between removing the pending
            // input and checking if there are other pending inputs, the
            // handler does not yield. Therefore, it will process all
            // pending inputs that have been enqueue while it is working.
            //??D Victor and Diego both think this logic is sound but is too complicated.
            //??D Any better ideas?
            if (e.pending_inputs.size() == 1) {
                async_context actx{session, request_context, hctx.completion_queue.get(), self, yield};
                // While inputs are processed, a query might have arrived. If everything works, its coroutine will be
                // waiting to be resumed between inputs, so the query can be processed. However, if
                // process_pending_inputs exits via an exception, that coroutine might never be called. It would
                // eventually timeout. So we resume it in the exception handlers below.
                //??D Looks Ugly to repeat the code in each handler, but I couldn't find a more elegant solution
                process_pending_inputs(hctx, actx, e);
            }
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none '" << e.status().error_message() << '\'';
            advance_state_writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (taint_session &x) {
            dout{request_context} << "Caught taint_status " << x.status().error_message();
            auto &session = x.session();
            session.tainted = true;
            session.taint_status = x.status();
            auto &e = session.epochs[session.active_epoch_index];
            // Check if there is a pending query
            if (e.pending_query.has_value()) {
                // Resume its coroutine so it can process the query and complete the InspectState rpc
                // To do so, we use an alarm to add the coroutine to the completion queue, then we yield
                // Once the coroutine is done, it will use the same process to add us back to the completion queue
                enqueue_completion_queue(hctx.completion_queue.get(), e.pending_query.value().coroutine);
                e.pending_query.value().coroutine = self;
                yield(side_effect::none);
            }
            // No need to return rpc results because we already have if we reach here
        } catch (std::exception &x) {
            dout{request_context} << "Caught unexpected exception " << x.what();
            const auto &id = advance_state_request.session_id();
            if (hctx.sessions.find(id) != hctx.sessions.end()) {
                auto &session = hctx.sessions[id];
                session.tainted = true;
                session.taint_status =
                    grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + x.what()};
                auto &e = session.epochs[session.active_epoch_index];
                // Check if there is a pending query
                if (e.pending_query.has_value()) {
                    // Resume its coroutine so it can process the query and complete the InspectState rpc
                    // To do so, we use an alarm to add the coroutine to the completion queue, then we yield
                    // Once the coroutine is done, it will use the same process to add us back to the completion queue
                    enqueue_completion_queue(hctx.completion_queue.get(), e.pending_query.value().coroutine);
                    e.pending_query.value().coroutine = self;
                    yield(side_effect::none);
                }
            }
            // No need to return rpc results because we already have if we reach here
        }
    }};
    return self;
}

class auto_resume final {
public:
    explicit auto_resume(grpc::ServerCompletionQueue *cq) : m_cq(cq), m_coroutine(nullptr) {}
    void reset(handler_type::pull_type *coroutine = nullptr) {
        m_coroutine = coroutine;
    }

    auto_resume(const auto_resume &other) = delete;
    auto_resume(auto_resume &&other) = delete;
    auto_resume &operator=(const auto_resume &other) = delete;
    auto_resume &operator=(auto_resume &&other) = delete;

    ~auto_resume() {
        if (m_coroutine) {
            enqueue_completion_queue(m_cq, m_coroutine);
        }
    }

private:
    grpc::ServerCompletionQueue *m_cq;
    handler_type::pull_type *m_coroutine;
};

/// \brief Creates a new handler for the InspectState RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_InspectState_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        ServerContext request_context;
        InspectStateRequest inspect_state_request;
        ServerAsyncResponseWriter<InspectStateResponse> inspect_state_writer(&request_context);
        auto *cq = hctx.completion_queue.get();
        // Wait for a InspectState RPC
        hctx.manager_async_service.RequestInspectState(&request_context, &inspect_state_request, &inspect_state_writer,
            cq, cq, self);
        yield(side_effect::none);
        // We now received a InspectState
        // We will handle other InspectState rpcs if we yield, but not in the same session, due to the session lock
        new_InspectState_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            // Check if session id exists
            auto &sessions = hctx.sessions; // NOLINT: Unknown. Maybe linter bug?
            const auto &id = inspect_state_request.session_id();
            dout{request_context} << "Received InspectState for session " << id;
            // If a session is unknown, a bail out
            if (sessions.find(id) == sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found!"}));
            }
            // Otherwise, get session and lock until we exit handler
            auto &session = sessions[id];
            // If session is already locked, bail out
            auto new_lock_reason = get_session_lock_reason("InspectState", request_context.peer());
            if (session.session_lock) {
                THROW((finish_error_yield_none{grpc::StatusCode::ABORTED,
                    "concurrent call in session (already locked by " + session.session_lock_reason +
                        " when attempted lock by " + new_lock_reason + ")"}));
            }
            // Lock session so other rpcs to the same session are rejected
            auto_lock session_lock(session.session_lock, "InspectState session lock");
            session.session_lock_reason = new_lock_reason;
            // If session is tainted, report potential data loss
            if (session.tainted) {
                THROW((finish_error_yield_none{grpc::StatusCode::DATA_LOSS, "session is tainted"}));
            }
            // We should be able to find the active epoch, otherwise bail
            auto &epochs = session.epochs;
            if (epochs.find(session.active_epoch_index) == epochs.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "active epoch not found"}));
            }
            auto &e = epochs[session.active_epoch_index];
            // Check size of query payload
            const auto query_payload_size = inspect_state_request.query_payload().size();
            if (query_payload_size + EVM_ABI_STRING_HEADER_LENGTH >= session.memory_range.rx_buffer.length) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "query payload too long for rx buffer length (expected " +
                        std::to_string(session.memory_range.rx_buffer.length - EVM_ABI_STRING_HEADER_LENGTH) +
                        " bytes max, got " + std::to_string(query_payload_size) + " bytes)"}));
            }
            // Make sure there isn't already another pending query
            if (e.pending_query.has_value()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "another query is already pending"}));
            }
            // Add pending query
            e.pending_query.emplace(inspect_state_request.query_payload());
            auto &q = e.pending_query.value();
            // Now, either there are pending AdvanceState inputs being processed in this session, or there aren't.
            // If there aren't, we can immediately process the InspectState query and return results.
            // The session is locked, and therefore no other rpcs can interfere (including AdvanceState rpcs).
            // Otherwise, we will have to yield because AdvanceState may be in the middle of an input.
            // The function process_pending_inputs checks for a pending query between every input it processes.
            // If it finds a pending query, it knows we are yielded and waiting. So it schedules us in the completion
            // queue and yield.
            // We process the query, then, when we are about to leave, we schedule process_pending_input's coroutine
            // back in the completion queue, so it can go on processing its input queue.
            auto_resume resume_on_exit(hctx.completion_queue.get());
            if (!e.pending_inputs.empty()) {
                // Set our coroutine in the pending_query so process_pending_inputs can find us
                q.coroutine = self;
                yield(side_effect::none);
                // Here we have been resumed and process_pending_input has set its coroutine for us to find it
                resume_on_exit.reset(q.coroutine);
            }
            // There is a chance the session was tainted between our yielding and being resumed
            if (session.tainted) {
                THROW((finish_error_yield_none{grpc::StatusCode::DATA_LOSS, "session is tainted"}));
            }
            async_context actx{session, request_context, hctx.completion_queue.get(), self, yield};
            process_pending_query(hctx, actx, e);
            // Copy response
            InspectStateResponse inspect_state_response;
            inspect_state_response.set_session_id(session.id);
            inspect_state_response.set_active_epoch_index(session.active_epoch_index);
            inspect_state_response.set_current_input_index(q.current_input_index);
            for (const auto &r : q.reports) {
                inspect_state_response.add_reports()->set_payload(r.payload);
            }
            switch (q.status) {
                case completion_status::accepted:
                    inspect_state_response.set_status(CompletionStatus::ACCEPTED);
                    break;
                case completion_status::rejected:
                    inspect_state_response.set_status(CompletionStatus::REJECTED);
                    break;
                case completion_status::exception:
                    inspect_state_response.set_status(CompletionStatus::EXCEPTION);
                    if (q.exception_data.has_value()) {
                        inspect_state_response.set_exception_data(q.exception_data.value());
                    }
                    break;
                case completion_status::machine_halted:
                    inspect_state_response.set_status(CompletionStatus::MACHINE_HALTED);
                    break;
                case completion_status::cycle_limit_exceeded:
                    inspect_state_response.set_status(CompletionStatus::CYCLE_LIMIT_EXCEEDED);
                    break;
                case completion_status::time_limit_exceeded:
                    inspect_state_response.set_status(CompletionStatus::TIME_LIMIT_EXCEEDED);
                    break;
            }
            e.pending_query.reset();
            // Tell caller RPC succeeded
            inspect_state_writer.Finish(inspect_state_response, grpc::Status::OK, self);
            yield(side_effect::none);
        } catch (finish_error_yield_none &e) {
            dout{request_context} << "Caught finish_error_yield_none '" << e.status().error_message() << '\'';
            inspect_state_writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (taint_session &e) {
            dout{request_context} << "Caught taint_status " << e.status().error_message();
            auto &session = e.session();
            session.tainted = true;
            session.taint_status = e.status();
            inspect_state_writer.FinishWithError(session.taint_status, self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{request_context} << "Caught unexpected exception " << e.what();
            const auto &id = inspect_state_request.session_id();
            auto taint_status =
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()};
            if (hctx.sessions.find(id) != hctx.sessions.end()) {
                auto &session = hctx.sessions[id];
                session.tainted = true;
                session.taint_status = taint_status;
            }
            inspect_state_writer.FinishWithError(taint_status, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Creates a new handler for the Checkin RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_Checkin_handler(handler_context &hctx) {
    auto *self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type{[self, &hctx](handler_type::push_type &yield) {
        using namespace grpc;
        // Start accepting CheckIn rpcs.
        ServerContext checkin_context;
        CheckInRequest checkin_request;
        ServerAsyncResponseWriter<Void> checkin_writer(&checkin_context);
        auto *cq = hctx.completion_queue.get();
        // Start expecting check-in rpcs
        hctx.checkin_async_service.RequestCheckIn(&checkin_context, &checkin_request, &checkin_writer, cq, cq, self);
        yield(side_effect::none);
        new_Checkin_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
        // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
        if (!hctx.ok) {
            return;
        }
        try {
            const auto &id = checkin_request.session_id(); // NOLINT: Unknown. Maybe linter bug?
            dout{checkin_context} << "Received CheckIn for session " << id;
            // If check-in is for the wrong session, bail out
            if (hctx.sessions_waiting_checkin.find(id) == hctx.sessions_waiting_checkin.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "check-in with wrong session id " + id}));
            }
            // If the actual session is unknown, a bail out
            if (hctx.sessions.find(id) == hctx.sessions.end()) {
                THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT,
                    "could not find an actual session with id " + id}));
            }
            // get session and handler coroutine
            auto &session = hctx.sessions[id];
            auto *coroutine = hctx.sessions_waiting_checkin[id];
            hctx.sessions_waiting_checkin.erase(id);
            session.server_address = checkin_request.address();
            // Acknowledge check-in
            Void checkin_response;
            checkin_writer.Finish(checkin_response, grpc::Status::OK, self);
            yield(side_effect::none);
            // Resume after checkin trigger
            (*coroutine)();

        } catch (finish_error_yield_none &e) {
            dout{checkin_context} << "Caught finish_error_yield_none " << e.status().error_message();
            checkin_writer.FinishWithError(e.status(), self);
            yield(side_effect::none);
        } catch (std::exception &e) {
            dout{checkin_context} << "Caught unexpected exception " << e.what();
            checkin_writer.FinishWithError(
                grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
            yield(side_effect::none);
        }
    }};
    return self;
}

/// \brief Replaces the port specification (i.e., after ':') in an address
/// with a new port
/// \param address Original address
/// \param port New port
/// \return New address with replaced port
static std::string replace_port(const std::string &address, int port) {
    // Unix address?
    if (address.find("unix:") == 0) {
        return address;
    }
    auto pos = address.find_last_of(':');
    // If already has a port, replace
    if (pos != std::string::npos) {
        return address.substr(0, pos) + ":" + std::to_string(port);
        // Otherwise, concatenate
    } else {
        return address + ":" + std::to_string(port);
    }
}

/// \brief Builds the manager server object and returns it
/// \param manage_address Address where manager will bind
/// \param hctx Handler context to be shared among all handlers
static auto build_manager(const char *manager_address, handler_context &hctx) {
    grpc::ServerBuilder builder;
    int manager_port = 0;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(manager_address, grpc::InsecureServerCredentials(), &manager_port);
    builder.RegisterService(&hctx.manager_async_service);
    builder.RegisterService(&hctx.checkin_async_service);
    hctx.completion_queue = builder.AddCompletionQueue();
    auto manager = builder.BuildAndStart();
    hctx.manager_address = replace_port(manager_address, manager_port);
    return manager;
}

/// \brief Drains a completion queue of all pending handlers and deletes them
/// \param cq Completion queue
static void drain_completion_queue(grpc::ServerCompletionQueue *cq) {
    cq->Shutdown();
    bool ok = false;
    handler_type::pull_type *h = nullptr;
    while (cq->Next(reinterpret_cast<void **>(&h), &ok)) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        delete h;
    }
}

/// \brief Checks if a handler is finished
/// \param c Handler
/// \return True if finished, false otherwise
static bool finished(handler_type::pull_type *c) {
    return !(*c);
}

/// \brief Prints help
/// \param name Program name vrom argv[0]
static void help(const char *name) {
    (void) fprintf(stderr,
        R"(Usage:

    %s --manager-address=<address> --server-address=<address> [--help]

where

      --manager-address=<address>
      gives the address manager will bind to, where <address> can be
        <ipv4-hostname/address>:<port>
        <ipv6-hostname/address>:<port>
        unix:<path>

    --server-address=<server-address> or [<server-address>]
      passed to the spawned remote cartesi machine
      default: localhost:0

    --help
      prints this message and exits

)",
        name);
}

/// \brief Checks if string matches prefix and captures remaninder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remaninder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    size_t len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        *val = str + len;
        return true;
    }
    return false;
}

static void cleanup_child_handler(int signal) {
    (void) signal;
    while (waitpid(static_cast<pid_t>(-1), nullptr, WNOHANG) > 0) {
    }
}

int main(int argc, char *argv[]) try {

    static_assert(std::tuple_size<hash_type>::value == KECCAK_SIZE, "hash size mismatch");

    const char *manager_address = nullptr;
    const char *server_address = "localhost:0";

    if (argc < 1) { // NOLINT: of course it could be < 1...
        std::cerr << "missing argv[0]\n";
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        if (stringval("--manager-address=", argv[i], &manager_address)) {
            ;
        } else if (stringval("--server-address=", argv[i], &server_address)) {
            ;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            exit(0);
        } else {
            server_address = argv[i];
        }
    }

    if (!manager_address) {
        std::cerr << "missing manager-address\n";
        exit(1);
    }

    handler_context hctx{};

    hctx.remote_cartesi_machine_path = boost::dll::program_location().replace_filename("remote-cartesi-machine");
    hctx.manager_address = manager_address;
    hctx.server_address = server_address;

    std::cerr << "manager version is " << manager_version_major << "." << manager_version_minor << "."
              << manager_version_patch << "\n";

    auto manager = build_manager(manager_address, hctx);
    if (!manager) {
        std::cerr << "manager server creation failed\n";
        exit(1);
    }

    struct sigaction sa {};
    sa.sa_handler = cleanup_child_handler; // NOLINT(cppcoreguidelines-pro-type-union-access)
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, nullptr);

    // Start accepting requests for all RPCs
    new_GetVersion_handler(hctx);       // NOLINT: cannot leak (pointer is in completion queue)
    new_StartSession_handler(hctx);     // NOLINT: cannot leak (pointer is in completion queue)
    new_AdvanceState_handler(hctx);     // NOLINT: cannot leak (pointer is in completion queue)
    new_GetStatus_handler(hctx);        // NOLINT: cannot leak (pointer is in completion queue)
    new_GetSessionStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_GetEpochStatus_handler(hctx);   // NOLINT: cannot leak (pointer is in completion queue)
    new_InspectState_handler(hctx);     // NOLINT: cannot leak (pointer is in completion queue)
    new_FinishEpoch_handler(hctx);      // NOLINT: cannot leak (pointer is in completion queue)
    new_EndSession_handler(hctx);       // NOLINT: cannot leak (pointer is in completion queue)
    new_Checkin_handler(hctx);          // NOLINT: cannot leak (pointer is in completion queue)

    // Dispatch loop
    for (;;) {
        // Obtain the next active handler
        handler_type::pull_type *h = nullptr; // NOLINT: cannot leak (drain_completion_queue kills remaining)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (!hctx.completion_queue->Next(reinterpret_cast<void **>(&h), &hctx.ok)) {
            goto shutdown; // NOLINT(cppcoreguidelines-avoid-goto)
        }
        // If the handler is finished, simply delete it
        // This can't really happen here, because the handler ALWAYS yields
        // after arranging for the completion queue to return it, rather than
        // finishing.
        if (finished(h)) {
            delete h;
        } else {
            // Otherwise, resume it
            (*h)();
            // If it is now finished after being resumed, simply delete it
            if (finished(h)) {
                delete h;
            } else {
                // Otherwise, if requested a shutdown, delete this handler and
                // shutdown. The other pending handlers will be deleted when
                // we drain the completion queue.
                if (h->get() == side_effect::shutdown) {
                    delete h;
                    goto shutdown; // NOLINT(cppcoreguidelines-avoid-goto)
                }
            }
        }
    }

shutdown:
    // Shutdown server before completion queue
    manager->Shutdown();
    drain_completion_queue(hctx.completion_queue.get());
    // Kill all machine servers
    for (auto &session_pair : hctx.sessions) {
        session_pair.second.server_process_group.terminate();
    }
    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
