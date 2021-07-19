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

#include <new>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <map>
#include <deque>
#include <array>
#include <variant>
#include <optional>
#include <algorithm>
#include <chrono>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <boost/coroutine2/coroutine.hpp>
#include <boost/process.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/iostreams/stream.hpp>
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#include "cartesi-machine-checkin.grpc.pb.h"
#include "rollup-machine-manager.grpc.pb.h"
#pragma GCC diagnostic pop

static constexpr uint32_t manager_version_major = 0;
static constexpr uint32_t manager_version_minor = 0;
static constexpr uint32_t manager_version_patch = 0;
static constexpr const char *manager_version_pre_release = "";
static constexpr const char *manager_version_build = "";

static constexpr uint32_t machine_version_major = 0;
static constexpr uint32_t machine_version_minor = 4;

using namespace CartesiRollupMachineManager;
using namespace CartesiMachine;
using namespace Versioning;

#ifndef NDEBUG
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define THROW(e) \
    do { \
        std::cerr << "Throwing from " << __FILE__ << ":" << __LINE__ << " at " << __PRETTY_FUNCTION__ << '\n'; \
        throw (e); \
    } while (0);
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define THROW(e) \
    do { \
        throw (e); \
    } while (0);
#endif

/// \brief Debug output, prefixed by session-id and request-id gRPC metadata,
/// and terminated by endline
class dout {
public:
    dout(const grpc::ServerContext &context) {
#ifndef NDEBUG
        static const std::array keys = {"request-id", "test-id"};
        for (const auto &key: keys) {
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
};

template <class T>
dout &operator<<(dout &&os, const T& x) {
    dout::out() << x;
    return os;
}

template <class T>
dout &operator<<(dout &os, const T& x) {
    dout::out() << x;
    return os;
}


#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "complete-merkle-tree.h"
#include "grpc-util.h"
#include "strict-aliasing.h"
#include "htif.h"

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

/// \brief Address type for Merkle tree nodes
using address_type = uint64_t;

/// \brief Merkle tree proof type
using proof_type = cartesi::merkle_tree_proof<hash_type, address_type>;

/// \brief Description of payload and metadata drive pair
struct payload_and_metadata_type {
    uint64_t metadata_flash_drive_index{};
    FlashDriveConfig metadata_flash_drive_config{};
    uint64_t payload_flash_drive_index{};
    FlashDriveConfig payload_flash_drive_config{};
};

/// \brief Description of payload and metadata array drive pair
struct payload_and_metadata_array_type {
    payload_and_metadata_type drive_pair{};
    uint64_t entry_count{};
    uint64_t payload_entry_length{};
    uint64_t metadata_flash_drive_address{};
    uint64_t metadata_flash_drive_log2_size{};
};

constexpr const int LOG2_ROOT_SIZE = 37;
constexpr const int LOG2_KECCAK_SIZE = 5;
constexpr const uint64_t KECCAK_SIZE = UINT64_C(1) << LOG2_KECCAK_SIZE;
constexpr const uint64_t INPUT_METADATA_LENGTH = 128;
constexpr const uint64_t OUTPUT_PAYLOAD_ADDRESS_LENGTH = 32;
constexpr const uint64_t OUTPUT_PAYLOAD_OFFSET_LENGTH = 32;
constexpr const uint64_t OUTPUT_PAYLOAD_LENGTH_LENGTH = 32;
constexpr const uint64_t OUTPUT_PAYLOAD_MINIMUM_LENGTH = OUTPUT_PAYLOAD_ADDRESS_LENGTH+OUTPUT_PAYLOAD_OFFSET_LENGTH+OUTPUT_PAYLOAD_LENGTH_LENGTH;
constexpr const uint64_t MESSAGE_PAYLOAD_OFFSET_LENGTH = 32;
constexpr const uint64_t MESSAGE_PAYLOAD_LENGTH_LENGTH = 32;
constexpr const uint64_t MESSAGE_PAYLOAD_MINIMUM_LENGTH = MESSAGE_PAYLOAD_OFFSET_LENGTH+MESSAGE_PAYLOAD_LENGTH_LENGTH;

/// \brief Type holding an input for processing
struct input_type {
    input_type(const std::string &input_metadata, const std::string &input_payload) {
        std::copy(input_metadata.begin(), input_metadata.end(),
            metadata.begin());
        payload.insert(payload.end(), input_payload.begin(),
            input_payload.end());
    }
    std::vector<uint8_t> payload;
    std::array<uint8_t, INPUT_METADATA_LENGTH> metadata{};
};

/// \brief Type holding an output generated by a processed input
struct output_type {
    hash_type keccak;
    hash_type address;
    std::string payload;
    proof_type keccak_in_output_metadata_flash_drive;
};

/// \brief Type holding a message generated by a processed input
struct message_type {
    hash_type keccak;
    std::string payload;
    proof_type keccak_in_message_metadata_flash_drive;
};

/// \brief Reason why an input might have been skipped
enum class input_skip_reason {
    cycle_limit_exceeded,
    requested_by_machine,
    machine_halted,
    time_limit_exceeded
};

/// \brief Type holding an input that was successfully processed
struct input_result_type {
    proof_type outputs_metadata_flash_drive_in_machine;
    proof_type outputs_metadata_flash_drive_in_epoch;
    std::vector<output_type> outputs;
    proof_type messages_metadata_flash_drive_in_machine;
    proof_type messages_metadata_flash_drive_in_epoch;
    std::vector<message_type> messages;
};

/// \brief Type holding a processed input
struct processed_input_type {
    uint64_t input_index; ///< Index of input in epoch
    hash_type machine_hash_after; ///< Hash of machine after processing input
    std::variant<input_result_type, input_skip_reason> processed; ///< Input results of reason it was skipped
};

/// \brief State of epoch
enum class epoch_state {
    active,
    finished
};

/// \brief Type of session ids
using id_type = std::string;

/// \brief Type holding an epoch;
struct epoch_type {
    uint64_t epoch_index{};
    epoch_state state{epoch_state::active};
    cartesi::complete_merkle_tree outputs_tree{
        LOG2_ROOT_SIZE,
        LOG2_KECCAK_SIZE,
        LOG2_KECCAK_SIZE
    };
    cartesi::complete_merkle_tree messages_tree{
        LOG2_ROOT_SIZE,
        LOG2_KECCAK_SIZE,
        LOG2_KECCAK_SIZE
    };
    std::vector<processed_input_type> processed_inputs;
    std::deque<input_type> pending_inputs;
};

/// \brief Type holding the deadlines for server operations
struct deadline_config_type {
    uint64_t check_in;
    uint64_t update_merkle_tree;
    uint64_t run_input;
    uint64_t run_input_chunk;
    uint64_t machine;
    uint64_t store;
    uint64_t fast;
};

/// \brief Type holding a session;
struct session_type {
    id_type id{}; ///< Session id
    bool session_lock{}; ///< Session lock
    bool processing_lock{}; ///< Lock for handler processing inputs
    bool tainted{}; ///< Taint flag
    grpc::Status taint_status{}; ///< Status explaining why taint flag is set
    std::unique_ptr<Machine::Stub> server_stub{}; ///< Connection to machine server
    uint64_t current_mcycle{}; ///< Current mcycle for machine in server
    uint64_t active_epoch_index{}; ///< Index of active epoch
    uint64_t max_cycles_per_input{}; ///< Maximum number of cycles allowed when processing inputs
    uint64_t cycles_per_input_chunk{}; ///< Inputs are processed in smaller chunks, each with a number of cycles
    uint64_t max_input_payload_length{}; ///< Maximum length of an input payload
    payload_and_metadata_type input_description{};
    payload_and_metadata_array_type outputs_description{};
    payload_and_metadata_array_type messages_description{};
    std::map<uint64_t, epoch_type> epochs{}; ///< Map of cached epochs
    deadline_config_type server_deadline{}; ///< Deadlines for interactions with server
    boost::process::child server_process{}; ///< cartesi-machine-server process
};

/// \brief Automatically unlocks a session when out of scope
class auto_lock final {
public:
    /// \brief Constructor acquires locks
    /// \param lock Reference to lock to be acquired
    auto_lock(bool &lock): m_lock{lock} {
        acquire();
    }

    /// \brief Acquire lock if it is not already locked
    void acquire(void) {
        if (m_lock) {
            THROW((std::runtime_error{"already locked"}));
        } else {
            m_lock = true;
        }
    }

    /// \brief Release lock if it is acquired
    void release(void) {
        if (!m_lock) {
            THROW((std::runtime_error{"not locked"}));
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
};

/// \brief Desired side effect when a handler yields
enum class side_effect {
    none, ///< do nothing
    shutdown ///< shutdown server
};

/// \brief A handler is simply a coroutine that returns a side_effect
using handler_type = boost::coroutines2::coroutine<side_effect>;

/// \brief Context shared by all handlers
struct handler_context {
    std::string manager_address; ///< Address to which manager is bound
    std::string server_address;    ///< Address to which machine servers are bound
    std::unordered_map<id_type, session_type> sessions; ///< Known sessions
    RollupMachineManager::AsyncService manager_async_service; ///< Assynchronous manager service
    MachineCheckIn::AsyncService checkin_async_service; ///< Assynchronous checkin service
    std::unique_ptr<grpc::ServerCompletionQueue> completion_queue; ///< Completion queue where all handlers arrive
    boost::process::group server_group; ///< Process group to which all machine servers belong
    bool ok; ///< gRPC status of requests arriving in queue
};

/// \brief Context for internal functions that need to perform async operations
struct async_context {
    session_type &session;
    const grpc::ServerContext &request_context;
    grpc::ServerCompletionQueue *completion_queue;
    handler_type::pull_type *self;
    handler_type::push_type &yield;
};

/// \brief Checks if integer is a power of 2
/// \param value Integer to test
/// \return True if integer is power of 2, false otherwise
static inline bool is_power_of_two(uint64_t value) {
    return value > 0 && (value & (value-1)) == 0;
}

/// \brief Computes to Log<sub>2</sub> of an integer
/// \param v Integer from which to compute Log<sub>2</sub>
/// \detail The return value is undefined if v == 0
/// This works on gcc and clang and uses the lzcnt instruction
static inline uint64_t ilog2(uint64_t v) {
    return 63 - __builtin_clzll(v);
}

/// \brief Base class for exceptions holding a grpc::Status
class handler_exception: public std::exception {
public:
    explicit handler_exception(const grpc::Status &status): m_status{status} { }
    handler_exception(grpc::StatusCode code, const std::string &message): m_status{code, message} { }
    const grpc::Status &status(void) const { return m_status; }
private:
    grpc::Status m_status;
};

/// \brief Exception thrown when RPC reached an error after it was restarted
class finish_error_yield_none: public handler_exception {
public:
    using handler_exception::handler_exception;
};

/// \brief Exception thrown when RPC reached an error before it was restarted
class restart_handler_finish_error_yield_none: public handler_exception {
public:
    using handler_exception::handler_exception;
};

/// \brief Exception thrown when an error condition prevents further interactions with the session
class taint_session: public std::exception {
public:
    taint_session(session_type &tainted, const grpc::Status &status): m_session{tainted}, m_status{status} { }
    taint_session(session_type &tainted, grpc::StatusCode code, const std::string &message): m_session{tainted}, m_status{code, message} { }
    const grpc::Status &status(void) const { return m_status; }
    session_type &session(void) const { return m_session; }
private:
    session_type &m_session;
    grpc::Status m_status;
};

/// \brief Creates a new handler for the GetVersion RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetVersion_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
        }
    };
    return self;
}

/// \brief Creates a new handler for the GetStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetStatus_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
            for (const auto & [session_id, session]: hctx.sessions) {
dout{request_context} << "  " <<  session_id;
                response.add_session_id(session_id);
            }
            writer.Finish(response, grpc::Status::OK, self); // NOLINT: Unknown. Maybe linter bug?
            yield(side_effect::none);
        }
    };
    return self;
}

/// \brief Sets a deadline for the request in a ClientContext
/// \param deadline Deadline in milliseconds
static inline void set_deadline(grpc::ClientContext &client_context, uint64_t deadline) {
    client_context.set_deadline(std::chrono::system_clock::now() +
        std::chrono::milliseconds(deadline));
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
        THROW((finish_error_yield_none{status}));
    }
}

/// \brief Marks epoch finished and update all proofs now that all leaves are present
/// \param e Associated epoch
static void finish_epoch(epoch_type &e) {
    e.state = epoch_state::finished;
    for (auto &i: e.processed_inputs) {
        if (std::holds_alternative<input_result_type>(i.processed)) {
            auto &r = std::get<input_result_type>(i.processed);
            r.outputs_metadata_flash_drive_in_epoch = e.outputs_tree.get_proof(i.input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            r.messages_metadata_flash_drive_in_epoch = e.messages_tree.get_proof(i.input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
        }
    }
}

/// \brief Start a new epoch in session
/// \param session Associated session
static void start_new_epoch(session_type &session) {
    session.active_epoch_index++;
    epoch_type e;
    e.epoch_index = session.active_epoch_index;
    e.state = epoch_state::active;
    session.epochs[e.epoch_index] = std::move(e);
}

/// \brief Creates a new handler for the FinishEpoch RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_FinishEpoch_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
dout{request_context} << "Received FinishEpoch for id " << id << " epoch " << epoch_index;
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
                if (session.session_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::ABORTED, "concurrent call in session"}));
                }
                // Lock session so other rpcs to the same session are rejected
                auto_lock session_lock(session.session_lock);
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
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "incorrect processed input count (expected " +
                        std::to_string(e.processed_inputs.size()) + ", got " + std::to_string(request.processed_input_count()) + ")"}));
                }
                // Try to store session before we change anything
                if (!request.storage_directory().empty()) {
dout{request_context} << "  Storing into " << request.storage_directory();
                    async_context actx{session, request_context, hctx.completion_queue.get(), self, yield};
                    store(actx, request.storage_directory());
                }
                finish_epoch(e);
                start_new_epoch(session);
                writer.Finish(response, grpc::Status::OK, self);
                yield(side_effect::none);
            } catch (finish_error_yield_none &e) {
                dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
                writer.FinishWithError(e.status(), self);
                yield(side_effect::none);
            } catch (std::exception &e) {
                dout{request_context} << "Caught unexpected exception " << e.what();
                writer.FinishWithError(grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
                yield(side_effect::none);
            }
        }
    };
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
        THROW((finish_error_yield_none{status}));
    }
}

/// \brief Creates a new handler for the EndSession RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_EndSession_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
dout{request_context} << "Received EndSession for id " << id;
                // If a session is unknown, a bail out
                if (sessions.find(id) == sessions.end()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found"}));
                }
                // Otherwise, get session and lock until we exit handler
                auto &session = sessions[id];
                // If session is already locked, bail out
                if (session.session_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::ABORTED, "concurrent call in session"}));
                }
                // Lock session so other rpcs to the same session are rejected
                auto_lock session_lock(session.session_lock);
                async_context actx{session, request_context, cq, self, yield};
                // If the session is tainted, nothing is going on with it, so we can erase it
                if (!session.tainted) {
                    // If the session is not tainted, we will only delete it if the active epoch is pristine
                    auto &epochs = session.epochs;
                    auto &e = epochs[session.active_epoch_index];
                    if (!e.pending_inputs.empty()) {
                        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "active epoch has pending inputs"}));
                    }
                    if (!e.processed_inputs.empty()) {
                        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "active epoch has processed inputs"}));
                    }
                }
                // This is just for peace of mind, there no way this branch can enter
                if (session.processing_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL, "session is processing inputs!"}));
                }
                shutdown_server(actx);
                if (session.tainted) {
dout{request_context} << "Session " << id << " is tainted. Terminating cartesi-machine-server process: " << session.server_process.id();
                    session.server_process.terminate();
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
                writer.FinishWithError(grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
                yield(side_effect::none);
            }
        }
    };
    return self;
}

/// \brief Creates a new handler for the GetSessionStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetSessionStatus_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
            Status status;
            GetSessionStatusResponse response;
            auto &sessions = hctx.sessions;
            const auto &id = request.session_id();
dout{request_context} << "Received GetSessionStatus for id " << id;
            try {
                // If a session is unknown, a bail out
                if (sessions.find(id) == sessions.end()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found!"}));
                }
                // Otherwise, get session and lock until we exit handler
                auto &session = sessions[id];
                // If session is already locked, bail out
                if (session.session_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::ABORTED, "concurrent call in session"}));
                }
                // Lock session so other rpcs to the same session are rejected
                auto_lock session_lock(session.session_lock);
                response.set_session_id(id);
                response.set_active_epoch_index(session.active_epoch_index);
                for (const auto & [index, epoch]: session.epochs) {
dout{request_context} << "  " <<  index;
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
                writer.FinishWithError(grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
                yield(side_effect::none);
            }
        }
    };
    return self;
}

/// \brief Fills out Output message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_output(const output_type &o, Output *proto_o) {
    cartesi::set_proto_hash(o.keccak, proto_o->mutable_keccak());
    cartesi::set_proto_hash(o.address, proto_o->mutable_address());
    proto_o->set_payload(o.payload);
    cartesi::set_proto_proof(o.keccak_in_output_metadata_flash_drive,
        proto_o->mutable_keccak_in_output_metadata_flash_drive());
}

/// \brief Fills out Message message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_message(const message_type &m, Message *proto_m) {
    cartesi::set_proto_hash(m.keccak, proto_m->mutable_keccak());
    proto_m->set_payload(m.payload);
    cartesi::set_proto_proof(m.keccak_in_message_metadata_flash_drive,
        proto_m->mutable_keccak_in_message_metadata_flash_drive());
}

/// \brief Fills out ProcessedInput message from structure
/// \param i Structure
/// \param proto_i Pointer to message receiving structure contents
static void set_proto_processed_input(const processed_input_type &i,
    ProcessedInput *proto_i) {
    proto_i->set_input_index(i.input_index);
    cartesi::set_proto_hash(i.machine_hash_after, proto_i->mutable_machine_hash_after());
    if (std::holds_alternative<input_result_type>(i.processed)) {
        const auto &r = std::get<input_result_type>(i.processed);
        auto *result_p = proto_i->mutable_result();
        cartesi::set_proto_proof(r.outputs_metadata_flash_drive_in_machine,
            result_p->mutable_outputs_metadata_flash_drive_in_machine());
        cartesi::set_proto_proof(r.outputs_metadata_flash_drive_in_epoch,
            result_p->mutable_outputs_metadata_flash_drive_in_epoch());
        for (const auto &o: r.outputs) {
            set_proto_output(o, result_p->add_outputs());
        }
        cartesi::set_proto_proof(r.messages_metadata_flash_drive_in_machine,
            result_p->mutable_messages_metadata_flash_drive_in_machine());
        cartesi::set_proto_proof(r.messages_metadata_flash_drive_in_epoch,
            result_p->mutable_messages_metadata_flash_drive_in_epoch());
        for (const auto &m: r.messages) {
            set_proto_message(m, result_p->add_messages());
        }
    } else {
        switch (std::get<input_skip_reason>(i.processed)) {
            case input_skip_reason::cycle_limit_exceeded:
                proto_i->set_skip_reason(InputSkipReason::CYCLE_LIMIT_EXCEEDED);
                break;
            case input_skip_reason::requested_by_machine:
                proto_i->set_skip_reason(InputSkipReason::REQUESTED_BY_MACHINE);
                break;
            case input_skip_reason::machine_halted:
                proto_i->set_skip_reason(InputSkipReason::MACHINE_HALTED);
                break;
            case input_skip_reason::time_limit_exceeded:
                proto_i->set_skip_reason(InputSkipReason::TIME_LIMIT_EXCEEDED);
                break;
        }
    }
}

/// \brief Creates a new handler for the GetEpochStatus RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_GetEpochStatus_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
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
dout{request_context} << "Received GetEpochStatus for id " << id << " epoch " << epoch_index;
                // If a session is unknown, a bail out
                if (sessions.find(id) == sessions.end()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "session id not found"}));
                }
                // Otherwise, get session and lock until we exit handler
                auto &session = sessions[id];
                // If session is already locked, bail out
                if (session.session_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::ABORTED, "concurrent call in session"}));
                }
                // Lock session so other rpcs to the same session are rejected
                auto_lock session_lock(session.session_lock);
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
                for (const auto &i: e.processed_inputs) {
                    set_proto_processed_input(i,
                        response.add_processed_inputs());
                }
                response.set_pending_input_count(e.pending_inputs.size());
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
                writer.FinishWithError(grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
                yield(side_effect::none);
            }
        }
    };
    return self;
}

/// \brief Initializes new payload and metadata structure from request
/// \param proto_p Corresponding PayloadAndMetadata
static auto get_proto_payload_and_metadata(const PayloadAndMetadata &proto_p) {
    payload_and_metadata_type p;
    p.metadata_flash_drive_index = proto_p.metadata_flash_drive_index();
    p.payload_flash_drive_index = proto_p.payload_flash_drive_index();
    return p;
}

/// \brief Initializes new payload and metadata array structure from request
/// \param proto_p Corresponding PayloadAndMetadataArray
static auto get_proto_payload_and_metadata_array(const PayloadAndMetadataArray &proto_p) {
    payload_and_metadata_array_type p;
    p.drive_pair = get_proto_payload_and_metadata(proto_p.drive_pair());
    p.entry_count = proto_p.entry_count();
    p.payload_entry_length = proto_p.payload_entry_length();
    return p;
}

/// \brief Initializes new deadline config structure from request
/// \param proto_p Corresponding DeadlineConfig
static auto get_proto_deadline_config(const DeadlineConfig &proto_p) {
    deadline_config_type d{};
    d.check_in = proto_p.check_in();
    d.update_merkle_tree = proto_p.update_merkle_tree();
    d.run_input = proto_p.run_input();
    d.run_input_chunk = proto_p.run_input_chunk();
    d.machine = proto_p.machine();
    d.store = proto_p.store();
    d.fast = proto_p.fast();
    return d;
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
    session.max_cycles_per_input = request.max_cycles_per_input();
    session.cycles_per_input_chunk = request.cycles_per_input_chunk();
    epoch_type e;
    e.epoch_index = session.active_epoch_index;
    e.state = epoch_state::active;
    session.epochs[e.epoch_index] = std::move(e);
    session.input_description = get_proto_payload_and_metadata(request.input_description());
    session.outputs_description = get_proto_payload_and_metadata_array(request.outputs_description());
    session.messages_description = get_proto_payload_and_metadata_array(request.messages_description());
    session.server_deadline = get_proto_deadline_config(request.server_deadline());
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
        THROW((finish_error_yield_none{status}));
    }
    // If version is incompatible, bail out
    if (response.version().major() != machine_version_major || response.version().minor() != machine_version_minor) {
        THROW((finish_error_yield_none{grpc::StatusCode::FAILED_PRECONDITION, "manager is incompatible with machine server"}));
    }
}

/// \brief Asynchronously starts a machine in the server
/// \param actx Context for async operations
/// \param request Machine request received from StartSession RPC
static void check_server_machine(async_context &actx, const MachineRequest &request) {
dout{actx.request_context} << "  Instantiating machine";
    Void response;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.machine);
    auto reader = actx.session.server_stub->AsyncMachine(&client_context, request, actx.completion_queue);
    grpc::Status status;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{status}));
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
        THROW((finish_error_yield_none{status}));
    }
    return response.config();
}

/// \brief Checks that a payload and metadata configuration is valid for a given machine
/// \param request_context ServerContext used by handler
/// \param drive_pair Payload and metadata configuration
/// \param name Name of pair
/// \param config MachineConfig returned by server
static void check_payload_and_metadata_config(grpc::ServerContext &request_context, payload_and_metadata_type &drive_pair, const std::string &name,
    const MachineConfig &config) {
dout{request_context} << "  Checking " << name << " payload and metadata description with config";
    uint64_t flash_drive_size = static_cast<uint64_t>(config.flash_drive_size());
    if (drive_pair.metadata_flash_drive_index >= flash_drive_size) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " metadata flash drive index too large (expected less than " +
            std::to_string(flash_drive_size) + ", got " + std::to_string(drive_pair.metadata_flash_drive_index) + ")"}));
    }
    drive_pair.metadata_flash_drive_config = config.flash_drive(drive_pair.metadata_flash_drive_index);
    drive_pair.metadata_flash_drive_config.set_shared(false);
    drive_pair.metadata_flash_drive_config.clear_image_filename();
    if (drive_pair.payload_flash_drive_index >= flash_drive_size) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " payload flash drive index too large (expected less than " +
            std::to_string(flash_drive_size) + ", got " + std::to_string(drive_pair.payload_flash_drive_index) + ")"}));
    }
    drive_pair.payload_flash_drive_config = config.flash_drive(drive_pair.payload_flash_drive_index);
    drive_pair.payload_flash_drive_config.set_shared(false);
    drive_pair.payload_flash_drive_config.clear_image_filename();
}

/// \brief Checks that a payload and metadata array configuration is valid for a
/// given machine
/// \param request_context ServerContext used by handler
/// \param array Array configuration
/// \param name Name of array
/// \param config MachineConfig returned by server
static void check_payload_and_metadata_array_config(grpc::ServerContext &request_context, payload_and_metadata_array_type &array,
    const std::string &name, const MachineConfig &config) {
    check_payload_and_metadata_config(request_context, array.drive_pair, name, config);
    auto metadata_drive_length = array.drive_pair.metadata_flash_drive_config.length();
    if (metadata_drive_length != array.entry_count*KECCAK_SIZE) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " metadata flash drive size mismatch (expected " +
            std::to_string(array.entry_count) + "*" + std::to_string(KECCAK_SIZE) + " bytes, got " + std::to_string(metadata_drive_length) + ")"}));
    }
    auto payload_drive_length = array.drive_pair.payload_flash_drive_config.length();
    if (payload_drive_length != array.entry_count*array.payload_entry_length) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " payload flash drive size mismatch (expected " +
            std::to_string(array.entry_count) + "*" + std::to_string(array.payload_entry_length) + " bytes, got " + std::to_string(payload_drive_length) + ")"}));
    }
    if (!is_power_of_two(metadata_drive_length)) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " metadata flash drive length not a power of two (" +
            std::to_string(metadata_drive_length) + ")"}));
    }
    array.metadata_flash_drive_address = array.drive_pair.metadata_flash_drive_config.start();
    array.metadata_flash_drive_log2_size = ilog2(metadata_drive_length);
    auto aligned_address = (array.metadata_flash_drive_address >> array.metadata_flash_drive_log2_size) << array.metadata_flash_drive_log2_size;
    if ((array.metadata_flash_drive_address != aligned_address)) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, name + " metadata flash start not aligned to its power of two size"}));
    }
}

/// \brief Checks that input, outputs and message drive pairs all point to
//  distinct drives
/// \param session Associated session
static void check_distinct_drives(const session_type &session) {
    std::array<uint64_t, 6> drives = {
        session.input_description.metadata_flash_drive_index,
        session.input_description.payload_flash_drive_index,
        session.outputs_description.drive_pair.metadata_flash_drive_index,
        session.outputs_description.drive_pair.payload_flash_drive_index,
        session.messages_description.drive_pair.metadata_flash_drive_index,
        session.messages_description.drive_pair.payload_flash_drive_index,
    };
    std::sort(drives.begin(), drives.end());
    if (std::adjacent_find(drives.begin(), drives.end()) != drives.end()) {
        THROW((restart_handler_finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "repeated flash drive indices"}));
    }
}

/// \brief Checks HTIF device configuration is valid for rollups
/// \param htif HTIFConfig returned by server
static void check_htif_config(const HTIFConfig &htif) {
    if (!htif.yield_rollup()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "yield rollup must be enabled"}));
    }
    if (htif.yield_progress()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "yield progress must be disabled"}));
    }
    if (htif.console_getchar()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "console getchar must be disabled"}));
    }
}

/// \brief Start and checks the server stub
/// \param session Associated session
/// \param address Server address
static void check_server_stub(session_type &session, const std::string &address) {
    // Instantiate client connection
    session.server_stub = Machine::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    // If unable to create stub, bail out
    if (!session.server_stub) {
        THROW((finish_error_yield_none{grpc::StatusCode::RESOURCE_EXHAUSTED, "unable to create machine stub for session"}));
    }
}

/// \brief Checks that outputs payload entry length is enought to hold
/// mandatory address and payload length fields
/// \param session Associated session
static void check_outputs_payload_entry_length(const session_type &session) {
    if (session.outputs_description.payload_entry_length < OUTPUT_PAYLOAD_MINIMUM_LENGTH) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "output payload entry length must be longer than " +
            std::to_string(OUTPUT_PAYLOAD_MINIMUM_LENGTH) + "bytes"}));
    }
}

/// \brief Checks that messages payload entry length is enought to hold
/// mandatory payload length field
/// \param session Associated session
static void check_messages_payload_entry_length(const session_type &session) {
    if (session.messages_description.payload_entry_length < MESSAGE_PAYLOAD_MINIMUM_LENGTH) {
        THROW((finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "message payload entry length must be longer than " +
            std::to_string(MESSAGE_PAYLOAD_MINIMUM_LENGTH) + "bytes"}));
    }
}

/// \brief Asynchronously update Merkle tree when starting a new session
/// \param actx Context for async operations
static void initial_update_merkle_tree(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.update_merkle_tree);
    auto reader = actx.session.server_stub->AsyncUpdateMerkleTree(&client_context, request, actx.completion_queue);
    grpc::Status status;
    UpdateMerkleTreeResponse response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((finish_error_yield_none{status}));
    }
    if (!response.success()) {
        THROW((finish_error_yield_none{grpc::StatusCode::INTERNAL,
            "failed updating merkle tree"}));
    }
}

/// \brief Creates a new handler for the StartSession RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type* new_StartSession_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
            using namespace grpc;
            ServerContext request_context;
            StartSessionRequest start_session_request;
            ServerAsyncResponseWriter<Void> start_session_writer(&request_context);
            auto *cq = hctx.completion_queue.get();
            // Wait for a StartSession RPC
            hctx.manager_async_service.RequestStartSession(&request_context, &start_session_request, &start_session_writer, cq, cq, self);
            yield(side_effect::none);
            // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
            if (!hctx.ok) {
                new_StartSession_handler(hctx);
                return;
            }
            handler_type::pull_type* restarted = nullptr;
            try {
                // We now received a StartSession RPC, and we are not waiting for additional StartSession rpcs yet.
                auto &sessions = hctx.sessions;
                const auto &id = start_session_request.session_id();
dout{request_context} << "Received StartSession request for id " << id;
                // Empty id is invalid, so a bail out
                if (id.empty()) {
                    new_StartSession_handler(hctx);
                    start_session_writer.FinishWithError(grpc::Status{StatusCode::INVALID_ARGUMENT, "session id is empty"}, self);
                    yield(side_effect::none);
                    return;
                }
                // If a session with this id already exists, a bail out
                if (sessions.find(id) != sessions.end()) {
                    new_StartSession_handler(hctx);
                    start_session_writer.FinishWithError(grpc::Status{StatusCode::ALREADY_EXISTS, "session id is taken"}, self);
                    yield(side_effect::none);
                    return;
                }
                // Allocate a new session with data from request
                auto &session = (sessions[id] = get_proto_session(start_session_request));
                // Lock session so other rpcs to the same session are rejected
                auto_lock lock(session.session_lock);
                check_distinct_drives(session);
                // If no machine config, bail out
                if (start_session_request.machine().machine_oneof_case() == MachineRequest::MACHINE_ONEOF_NOT_SET) {
                    THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "missing initial machine config"}));
                }
                // If active_epoch_index is too large, bail
                if (session.active_epoch_index == UINT64_MAX) {
                    THROW((restart_handler_finish_error_yield_none{grpc::StatusCode::OUT_OF_RANGE, "active epoch index will overflow"}));
                }
                // If no deadline config, bail out
                if (!start_session_request.has_server_deadline()) {
                    THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "missing server deadline config"}));
                }
                // If run_input deadline is less than run_input_chunk, bail out
                if (session.server_deadline.run_input < session.server_deadline.run_input_chunk) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "run_input deadline is less than run_input_chunk"}));
                }
                // If inputs have no cycles to complete, bail out
                if (session.max_cycles_per_input == 0 || session.cycles_per_input_chunk == 0) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "max cycles per input or cycles per input chunk is zero"}));
                }
                // If max cycles per input is less than cycle per input chunk, bail out
                if (session.max_cycles_per_input < session.cycles_per_input_chunk) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "max cycles per input is less than cycles per input chunk"}));
                }
                // If output payload entry lengths too small for required data, bail out
                if (session.outputs_description.payload_entry_length < OUTPUT_PAYLOAD_MINIMUM_LENGTH) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "output payload entry length to small"}));
                }
                // If message payload entry lengths too small for required data, bail out
                if (session.messages_description.payload_entry_length < MESSAGE_PAYLOAD_MINIMUM_LENGTH) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INVALID_ARGUMENT, "message payload entry length to small"}));
                }
                // Start accepting CheckIn rpcs. At this point we are not accepting other StartSession rpcs.
                // In other words, the handshake is "atomic"
                ServerContext checkin_context;
                CheckInRequest checkin_request;
                ServerAsyncResponseWriter<Void> checkin_writer(&checkin_context);
                // Start expecting check-in rpcs
                hctx.checkin_async_service.RequestCheckIn(&checkin_context, &checkin_request, &checkin_writer, cq, cq, self);
                // Spawn a new server and ask it to check-in
                auto cmdline = "./cartesi-machine-server --session-id=" + id + " --checkin-address=" + hctx.manager_address +
                    " --server-address=" + hctx.server_address;
dout{request_context} << "  Spawning " << cmdline;
                try {
                    session.server_process = boost::process::child(cmdline);
                    session.server_process.detach();
                } catch (boost::process::process_error &e) {
                   THROW((restart_handler_finish_error_yield_none{StatusCode::INTERNAL, "failed spawning cartesi-machine-server with command-line '" +
                           cmdline + "' (" + e.what() + ")"}));
                }
dout{request_context} << "  Waiting check-in";
                // Wait for CheckIn
                yield(side_effect::none);
                // If check-in is for the wrong session, bail out
                if (checkin_request.session_id() != id) {
                    auto err_msg = "check-in with wrong id (expected " + id + ", got " + checkin_request.session_id() + ")";
                    checkin_writer.FinishWithError(Status{StatusCode::INVALID_ARGUMENT, err_msg}, self);
                    yield(side_effect::none);
                    THROW((restart_handler_finish_error_yield_none{StatusCode::INTERNAL, err_msg}));
                };
                // Acknowledge check-in
                Void checkin_response;
                checkin_writer.Finish(checkin_response, grpc::Status::OK, self);
                yield(side_effect::none);
dout{request_context} << "  Check-in for session " << id << " passed with address " << checkin_request.address();
                // At this point, we can safely start processing additional StartSession rpcs
                // and we are not accepting CheckIn rpcs
                restarted = new_StartSession_handler(hctx);
                check_server_stub(session, checkin_request.address());
                try {
                    async_context actx{session, request_context, cq, self, yield};
                    check_server_version(actx);
                    check_server_machine(actx, start_session_request.machine());
                    auto config = get_initial_config(actx);
                    check_htif_config(config.htif());
                    // Machine may have started at mcycle != 0, so we save it for
                    // when we need to run an input for at most max_cycles_per_input
                    session.current_mcycle = config.processor().mcycle();
                    check_payload_and_metadata_config(request_context, session.input_description, "input", config);
                    check_payload_and_metadata_array_config(request_context, session.outputs_description, "outputs", config);
                    check_payload_and_metadata_array_config(request_context, session.messages_description, "messages", config);
                    check_outputs_payload_entry_length(session);
                    check_messages_payload_entry_length(session);
                    initial_update_merkle_tree(actx);
                } catch (...) {
                    // If there is any error here, we try to shutdown the machine server
                    grpc::ClientContext client_context;
                    set_deadline(client_context, session.server_deadline.fast);
                    Void request;
                    Void response;
                    auto status = session.server_stub->Shutdown(&client_context, request, &response);
                    throw; // rethrow so it is caught outside and we report the error
                }
                // StartSession Passed!
                Void start_session_response;
                start_session_writer.Finish(start_session_response, grpc::Status::OK, self);
                yield(side_effect::none);
            } catch (finish_error_yield_none &e) {
                dout{request_context} << "Caught finish_error_yield_none " << e.status().error_message();
                hctx.sessions.erase(start_session_request.session_id());
                start_session_writer.FinishWithError(e.status(), self);
                yield(side_effect::none);
            } catch (restart_handler_finish_error_yield_none &e) {
                dout{request_context} << "Caught restart_handler_finish_error_yield_none " << e.status().error_message();
                hctx.sessions.erase(start_session_request.session_id());
                new_StartSession_handler(hctx);
                start_session_writer.FinishWithError(e.status(), self);
                yield(side_effect::none);
            } catch (std::exception &e) {
                dout{request_context} << "Caught unexpected exception " << e.what();
                hctx.sessions.erase(start_session_request.session_id());
                if (!restarted) {
                    new_StartSession_handler(hctx);
                }
                start_session_writer.FinishWithError(grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()}, self);
                yield(side_effect::none);
            }
        }
    };
    return self;
}

/// \brief Asynchronously clears the input, outputs, and messages drive pairs
/// \param actx Context for async operations
static void clear_flash_drives(async_context &actx) {
    std::array<std::pair<FlashDriveConfig *, const char *>, 6> drive_configs = {
        std::make_pair(&actx.session.input_description.payload_flash_drive_config, "input payload flash drive"),
        std::make_pair(&actx.session.input_description.metadata_flash_drive_config, "input metadata flash drive"),
        std::make_pair(&actx.session.outputs_description.drive_pair.payload_flash_drive_config, "outputs payload flash drive"),
        std::make_pair(&actx.session.outputs_description.drive_pair.metadata_flash_drive_config, "outputs metadata flash drive"),
        std::make_pair(&actx.session.messages_description.drive_pair.payload_flash_drive_config, "messages payload flash drive"),
        std::make_pair(&actx.session.messages_description.drive_pair.metadata_flash_drive_config, "messages metadata flash drive")
    };
    for (auto config: drive_configs) {
dout{actx.request_context} << "      clearing " << config.second;
        ReplaceFlashDriveRequest replace_request;
        replace_request.set_allocated_config(config.first);
        Void replace_response;
        grpc::ClientContext client_context;
        set_deadline(client_context, actx.session.server_deadline.fast);
        auto reader = actx.session.server_stub->AsyncReplaceFlashDrive(&client_context, replace_request, actx.completion_queue);
        grpc::Status replace_status;
        reader->Finish(&replace_response, &replace_status, actx.self);
        actx.yield(side_effect::none);
        replace_request.release_config();
        if (!replace_status.ok()) {
            THROW((taint_session{actx.session, replace_status}));
        }
    }
}

/// \brief Asynchronously writes data to a flash drive
/// \param actx Context for async operations
/// \param begin First byte to write
/// \param end One past last byte to write
/// \param drive FlashDriveConfig describing drive
template <typename IT>
static void write_flash_drive(async_context &actx, IT begin, IT end, const FlashDriveConfig &drive) {
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
        THROW((taint_session{actx.session, write_status}));
    }
}

/// \brief Asynchronously runs machine server up to given max cycle
/// \param actx Context for async operations
/// \param curr_mcycle current mcycle
/// \param max_mcycle mcycle limit
/// \return RunResponse returned by machine server, or nothing if deadline expired
static std::optional<RunResponse> run_input(async_context &actx, uint64_t curr_mcycle, uint64_t max_mcycle) {
    // We will run in chunks of cycles_per_input_chunk. The assumption is that
    // these chunks will be executed faster than the run_input_chunk deadline by
    // the emulator. After each chunk, if the machine has not yielded or
    // halted or we haven't reached max_mcycle, we check the total time elapsed
    // since we started. If it exceeds the deadline, we will return nothing.  This
    // indicates the run_input deadline has been expired before the machine was done, but
    // the server is still responsive. If the request for a single chunk does not return by the
    // run_input_chunk deadline, we will assume the machine is not responsive and we will taint
    // the session.
    auto start = std::chrono::system_clock::now();
    auto limit = std::min(curr_mcycle+actx.session.cycles_per_input_chunk, max_mcycle);
    int i = 0;
    for (; ;) {
dout{actx.request_context} << "  Running input chunk " << i++;
        RunRequest run_request;
        run_request.set_limit(limit);
        grpc::ClientContext client_context;
        set_deadline(client_context, std::max(actx.session.server_deadline.run_input_chunk, UINT64_C(0)));
        auto reader = actx.session.server_stub->AsyncRun(&client_context, run_request, actx.completion_queue);
        grpc::Status run_status;
        RunResponse run_response;
        reader->Finish(&run_response, &run_status, actx.self);
        actx.yield(side_effect::none);
        if (!run_status.ok()) {
            THROW((taint_session{actx.session, run_status}));
        }
        // Check if yielded or halted or reached max_mcycle and return
        if (run_response.iflags_y() || run_response.iflags_h() || run_response.mcycle() >= max_mcycle) {
            return run_response;
        }
        // Check if run_input deadline has expired.
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start).count();
        if (elapsed > static_cast<decltype(elapsed)>(actx.session.server_deadline.run_input)) {
            return {};
        }
        // Move on to next chunk
        limit = std::min(limit+actx.session.cycles_per_input_chunk, max_mcycle);
    }
}

/// \brief Asynchronously reads the contents of a flash drive
/// \param actx Context for async operations
/// \param drive FlashDriveConfig describing drive
/// \return String with drive contents
static std::string read_flash_drive(async_context &actx, const FlashDriveConfig &drive) {
    ReadMemoryRequest read_request;
    read_request.set_address(drive.start());
    read_request.set_length(drive.length());
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, read_status}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we
    // want to move out
    auto *data = read_response.release_data();
    return data? std::move(*data): std::string{};
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
static uint64_t count_null_terminated_entries(const std::string &data, uint64_t entry_length) {
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
/// \param begin Start of large big-endian number
/// \param end one-past-end of large big-endian number
/// \return Converted hash
template <typename IT>
static inline hash_type get_hash(session_type &session, IT begin, IT end) {
    hash_type hash;
    if (end-begin != hash.size()) {
        THROW((taint_session{session, grpc::StatusCode::OUT_OF_RANGE, "invalid hash length"}));
    }
    std::copy(begin, end, hash.begin());
    return hash;
}

/// \brief Converts a payload length from large big-endian to a native 64-bit integer
/// \param session Session to taint in case of error
/// \param begin Start of large big-endian number
/// \param end one-past-end of large big-endian number
/// \return Converted 64-bit native integer
template <typename IT>
static inline uint64_t get_payload_length(session_type &session, IT begin, IT end) {
    if (!is_null(begin, end-sizeof(uint64_t))) {
        THROW((taint_session{session, grpc::StatusCode::OUT_OF_RANGE, "payload length too large"}));
    }
    uint64_t length = 0;
    IT byte_iterator = end - 1;
    for (unsigned i = 0; i < sizeof(uint64_t) && byte_iterator != begin; ++i) {
        length += static_cast<uint8_t>(*byte_iterator) << 8*i;
        --byte_iterator;
    }
    return length;
}

/// \brief Asynchronously reads an output address and payload data length from the outputs payload drive
/// \param actx Context for async operations
/// \param entry_index Index of output entry to read
/// \param payload_data_length Receives payload data length for entry
/// \return Address for entry at index
static hash_type read_output_address_and_payload_data_length(async_context &actx, uint64_t entry_index, uint64_t *payload_data_length) {
    ReadMemoryRequest read_request;
    const FlashDriveConfig &drive = actx.session.outputs_description.drive_pair.payload_flash_drive_config;
    auto entry_start = entry_index*actx.session.outputs_description.payload_entry_length;
    read_request.set_address(drive.start()+entry_start);
    read_request.set_length(OUTPUT_PAYLOAD_MINIMUM_LENGTH);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, read_status}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    auto payload_data_length_begin = read_response.data().begin()+OUTPUT_PAYLOAD_ADDRESS_LENGTH+OUTPUT_PAYLOAD_OFFSET_LENGTH;
    auto payload_data_length_end = payload_data_length_begin+OUTPUT_PAYLOAD_LENGTH_LENGTH;
    *payload_data_length = get_payload_length(actx.session, payload_data_length_begin, payload_data_length_end);
    auto address_begin = read_response.data().begin();
    auto address_end = address_begin+OUTPUT_PAYLOAD_ADDRESS_LENGTH;
    return get_hash(actx.session, address_begin, address_end);
}

/// \brief Asynchronously reads an output payload data from the outputs payload drive
/// \param actx Context for async operations
/// \param entry_index Index of output entry to read
/// \param payload_data_length Length of payload data in entry
/// \return Contents of output payload data
static std::string read_output_payload_data(async_context &actx, uint64_t entry_index, uint64_t payload_data_length) {
    auto payload_data_offset = OUTPUT_PAYLOAD_MINIMUM_LENGTH;
    const FlashDriveConfig &drive = actx.session.outputs_description.drive_pair.payload_flash_drive_config;
    if (payload_data_length > actx.session.outputs_description.payload_entry_length-payload_data_offset) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "output payload length is out of bounds"}));
    }
    auto entry_start = entry_index*actx.session.outputs_description.payload_entry_length;
    ReadMemoryRequest read_request;
    read_request.set_address(drive.start()+entry_start+payload_data_offset);
    read_request.set_length(payload_data_length);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, read_status}));
    }
    if (read_response.data().size() != payload_data_length) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we want to move out
    auto *data = read_response.release_data();
    return data? std::move(*data): std::string{};
}

/// \brief Asynchronously reads a message payload data length from the messages payload drive
/// \param actx Context for async operations
/// \param entry_index Index of message entry to read
/// \return Payload data length for entry at index
static uint64_t read_message_payload_data_length(async_context &actx, uint64_t entry_index) {
    ReadMemoryRequest read_request;
    const FlashDriveConfig &drive = actx.session.messages_description.drive_pair.payload_flash_drive_config;
    auto entry_start = entry_index*actx.session.messages_description.payload_entry_length;
    read_request.set_address(drive.start()+entry_start);
    read_request.set_length(MESSAGE_PAYLOAD_MINIMUM_LENGTH);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, read_status}));
    }
    if (read_response.data().size() != read_request.length()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    auto payload_data_length_begin = read_response.data().begin()+MESSAGE_PAYLOAD_OFFSET_LENGTH;
    auto payload_data_length_end = payload_data_length_begin+MESSAGE_PAYLOAD_LENGTH_LENGTH;
    return get_payload_length(actx.session, payload_data_length_begin, payload_data_length_end);
}

/// \brief Asynchronously reads a message payload data from the messages payload drive
/// \param actx Context for async operations
/// \param entry_index Index of message entry to read
/// \param payload_data_length Length of payload data in entry
/// \return Contents of message payload data
static std::string read_message_payload_data(async_context &actx, uint64_t entry_index, uint64_t payload_data_length) {
    auto payload_data_offset = MESSAGE_PAYLOAD_MINIMUM_LENGTH;
    const FlashDriveConfig &drive = actx.session.messages_description.drive_pair.payload_flash_drive_config;
    if (payload_data_length > actx.session.messages_description.payload_entry_length-payload_data_offset) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "message payload length is out of bounds"}));
    }
    auto entry_start = entry_index*actx.session.messages_description.payload_entry_length;
    ReadMemoryRequest read_request;
    read_request.set_address(drive.start()+entry_start+payload_data_offset);
    read_request.set_length(payload_data_length);
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncReadMemory(&client_context, read_request, actx.completion_queue);
    grpc::Status read_status;
    ReadMemoryResponse read_response;
    reader->Finish(&read_response, &read_status, actx.self);
    actx.yield(side_effect::none);
    if (!read_status.ok()) {
        THROW((taint_session{actx.session, read_status}));
    }
    if (read_response.data().size() != payload_data_length) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "read returned wrong number of bytes!"}));
    }
    // Here we can't use copy elision because read_response holds the string we want to move out
    auto *data = read_response.release_data();
    return data? std::move(*data): std::string{};
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
        THROW((taint_session{actx.session, proof_status}));
    }
    return cartesi::get_proto_proof(proof_response.proof());
}

/// \brief Asynchronously reads an output from the outputs payload drive
/// \param actx Context for async operations
/// \param output_metadata Contents of entire output metadata drive
/// \param entry_index Index of output entry to read
/// \return Output at entry_index
static output_type read_output(async_context &actx, const std::string &output_metadata, uint64_t entry_index) {
    if ((entry_index+1)*KECCAK_SIZE > output_metadata.size()) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "too few hashes in metadata"}));
    }
    auto keccak = get_hash(actx.session, &output_metadata[entry_index*KECCAK_SIZE], &output_metadata[(entry_index+1)*KECCAK_SIZE]);
dout{actx.request_context} << "      Getting proof of keccak in output metadata flash drive";
    auto keccak_in_output_metadata_flash_drive = get_proof(actx, actx.session.outputs_description.metadata_flash_drive_address+entry_index*KECCAK_SIZE,
        LOG2_KECCAK_SIZE).slice(hasher_type{}, actx.session.outputs_description.metadata_flash_drive_log2_size, LOG2_KECCAK_SIZE);
    uint64_t payload_data_length = 0;
dout{actx.request_context} << "      Reading output address and length";
    auto address = read_output_address_and_payload_data_length(actx, entry_index, &payload_data_length);
dout{actx.request_context} << "      Reading output payload at " << entry_index << " of length " << payload_data_length;
    auto payload_data = read_output_payload_data(actx, entry_index, payload_data_length);
    return { std::move(keccak), std::move(address), std::move(payload_data), std::move(keccak_in_output_metadata_flash_drive) };
}

/// \brief Asynchronously reads a message from the messages payload drive
/// \param actx Context for async operations
/// \param message_metadata Contents of entire message metadata drive
/// \param entry_index Index of message entry to read
/// \return Message at entry_index
static message_type read_message(async_context &actx, const std::string &message_metadata, uint64_t entry_index) {
    if ((entry_index+1)*KECCAK_SIZE > message_metadata.size()) {
        THROW((taint_session{actx.session, grpc::StatusCode::OUT_OF_RANGE, "too few hashes in metadata"}));
    }
    auto keccak = get_hash(actx.session, &message_metadata[entry_index*KECCAK_SIZE], &message_metadata[(entry_index+1)*KECCAK_SIZE]);
dout{actx.request_context} << "      Getting proof of keccak in message metadata flash drive";
    auto keccak_in_message_metadata_flash_drive = get_proof(actx, actx.session.messages_description.metadata_flash_drive_address+entry_index*KECCAK_SIZE,
        LOG2_KECCAK_SIZE).slice(hasher_type{}, actx.session.messages_description.metadata_flash_drive_log2_size, LOG2_KECCAK_SIZE);
dout{actx.request_context} << "      Reading message length";
    auto payload_data_length = read_message_payload_data_length(actx, entry_index);
dout{actx.request_context} << "      Reading message payload at " << entry_index << " of length " << payload_data_length;
    auto payload_data = read_message_payload_data(actx, entry_index, payload_data_length);
    return { std::move(keccak), std::move(payload_data), std::move(keccak_in_message_metadata_flash_drive) };
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
        THROW((taint_session{actx.session, status}));
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
        THROW((taint_session{actx.session, status}));
    }
}

/// \brief Asynchronously resets the iflags.y flag after a machine has yielded
/// \param actx Context for async operations
static void reset_iflags_y(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.fast);
    auto reader = actx.session.server_stub->AsyncResetIflagsY(&client_context,
        request, actx.completion_queue);
    grpc::Status status;
    Void response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, status}));
    }
}

/// \brief Decides if the machine has properly yielded the result of processing an input
/// \param response Result of Run RPC to machine server
/// \return True if machine yielded the result of processing an input, false otherwise
static bool is_yield_rollup(const RunResponse &response) {
    if (!response.iflags_y()) {
        return false;
    }
    auto tohost = response.tohost();
    uint64_t dev = cartesi::HTIF_DEV_FIELD(tohost);
    uint64_t cmd = cartesi::HTIF_CMD_FIELD(tohost);
    uint64_t payload = cartesi::HTIF_DATA_FIELD(tohost);
    return (dev == cartesi::HTIF_DEVICE_YIELD) &&
           (cmd == cartesi::HTIF_YIELD_ROLLUP) &&
           (payload == 0);
}

/// \brief Decides if the machine requested for an input to be skipped
/// \param response Result of Run RPC to machine server
/// \return True if machine requested skip, false otherwise
static bool is_machine_requested_skip(const RunResponse &response) {
    return response.iflags_y() && !is_yield_rollup(response);
}

/// \brief Asynchronously updates machine server Merkle tree
/// \param actx Context for async operations
static void update_merkle_tree(async_context &actx) {
    Void request;
    grpc::ClientContext client_context;
    set_deadline(client_context, actx.session.server_deadline.update_merkle_tree);
    auto reader = actx.session.server_stub->AsyncUpdateMerkleTree(&client_context, request, actx.completion_queue);
    grpc::Status status;
    UpdateMerkleTreeResponse response;
    reader->Finish(&response, &status, actx.self);
    actx.yield(side_effect::none);
    if (!status.ok()) {
        THROW((taint_session{actx.session, status}));
    }
    if (!response.success()) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "failed updating merkle tree"}));
    }
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
        THROW((taint_session{actx.session, status}));
    }
    return cartesi::get_proto_hash(response.hash());
}

/// \brief Loops processing all pending inputs
/// \param actx Context for async operations
/// \param e Associated epoch
static void process_pending_inputs(async_context &actx, epoch_type &e) {
    // This is just for peace of mind: there is no way two concurrent calls can happen
    // (See discussion where process_pending_inputs is called.)
    if (actx.session.processing_lock) {
        THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "concurrent input processing detected in session"}));
    }
    auto_lock processing_lock(actx.session.processing_lock);
    while (!e.pending_inputs.empty()) {
        auto input_index = e.processed_inputs.size();
dout{actx.request_context} << "  Processing input " << input_index;
dout{actx.request_context} << "    Creating Snapshot";
        snapshot(actx);
dout{actx.request_context} << "    Clearing flash drives";
        clear_flash_drives(actx);
        const auto &i = e.pending_inputs.front();
dout{actx.request_context} << "    Writing input payload flash drive";
        write_flash_drive(actx, i.payload.begin(), i.payload.end(), actx.session.input_description.payload_flash_drive_config);
dout{actx.request_context} << "    Writing input metadata flash drive";
        write_flash_drive(actx, i.metadata.begin(), i.metadata.end(), actx.session.input_description.metadata_flash_drive_config);
        auto max_mcycle = actx.session.current_mcycle+actx.session.max_cycles_per_input;
        auto run_response = run_input(actx, actx.session.current_mcycle, max_mcycle);
        // If machine has yielded, we read back the input result
        if (run_response.has_value() && is_yield_rollup(run_response.value())) {
            // Update merkle tree so we can gather our proofs
dout{actx.request_context} << "    Updating Merkle tree";
            update_merkle_tree(actx);
            // Read proof of output metadata flash drive in machine
dout{actx.request_context} << "    Getting output metadata flash drive proof";
            auto outputs_metadata_flash_drive_in_machine = get_proof(actx, actx.session.outputs_description.metadata_flash_drive_address,
                actx.session.outputs_description.metadata_flash_drive_log2_size);
            // Get proof of output metadata flash drive in epoch
            if (e.outputs_tree.size() != input_index) {
                THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "inconsistent number of entries in epoch'session outputs Merkle tree"}));
            }
            e.outputs_tree.push_back(outputs_metadata_flash_drive_in_machine.get_target_hash());
            auto outputs_metadata_flash_drive_in_epoch = e.outputs_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Read outputs metadata drive and count the number of outputs
dout{actx.request_context} << "    Reading outputs metadata flash drive";
            auto output_metadata = read_flash_drive(actx, actx.session.outputs_description.drive_pair.metadata_flash_drive_config);
            uint64_t output_count = count_null_terminated_entries(output_metadata, KECCAK_SIZE);
dout{actx.request_context} << "    Output count " << output_count;
            std::vector<output_type> outputs;
            // Read each output payload
            for (uint64_t output_index = 0; output_index < output_count; ++output_index) {
dout{actx.request_context} << "    Reading output " << output_index;
                outputs.push_back(read_output(actx, output_metadata, output_index));
            }

            // Read proof of message metadata flash drive in machine
dout{actx.request_context} << "    Getting message metadata flash drive proof";
            auto messages_metadata_flash_drive_in_machine = get_proof(actx, actx.session.messages_description.metadata_flash_drive_address,
                actx.session.messages_description.metadata_flash_drive_log2_size);
            // Get proof of message metadata flash drive in epoch
            if (e.messages_tree.size() != input_index) {
                THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "inconsistent number of entries in epoch'session messages Merkle tree"}));
            }
            e.messages_tree.push_back(messages_metadata_flash_drive_in_machine.get_target_hash());
            auto messages_metadata_flash_drive_in_epoch = e.messages_tree.get_proof(input_index << LOG2_KECCAK_SIZE, LOG2_KECCAK_SIZE);
            // Read messages metadata drive and count the number of messages
dout{actx.request_context} << "    Reading messages metadata flash drive";
            auto message_metadata = read_flash_drive(actx, actx.session.messages_description.drive_pair.metadata_flash_drive_config);
            uint64_t message_count = count_null_terminated_entries(message_metadata, KECCAK_SIZE);
dout{actx.request_context} << "    Message count " << message_count;
            std::vector<message_type> messages;
            // Read each message payload
            for (uint64_t message_index = 0; message_index < message_count; ++message_index) {
dout{actx.request_context} << "    Reading message " << message_index;
                messages.push_back(read_message(actx, message_metadata, message_index));
            }
            // Make sure we are not forever stuck in a yielded status
            reset_iflags_y(actx);
            // Add results of processed input
            e.processed_inputs.push_back(
                processed_input_type{
                    input_index,
                    get_root_hash(actx),
                    input_result_type{
                        std::move(outputs_metadata_flash_drive_in_machine),
                        std::move(outputs_metadata_flash_drive_in_epoch),
                        std::move(outputs),
                        std::move(messages_metadata_flash_drive_in_machine),
                        std::move(messages_metadata_flash_drive_in_epoch),
                        std::move(messages),
                    }
                }
            );
            // Advance session.current_mcycle
            actx.session.current_mcycle = run_response.value().mcycle();
dout{actx.request_context} << "  Done processing input " << input_index;
        // Otherwise, we skip the input
        } else {
dout{actx.request_context} << "  Skipped input " << input_index;
dout{actx.request_context} << "    Rolling back";
            rollback(actx);
            input_skip_reason reason;
            if (!run_response.has_value()) {
dout{actx.request_context} << "    Input skipped because time limit was exceeded";
                reason = input_skip_reason::time_limit_exceeded;
            } else if (is_machine_requested_skip(run_response.value())) {
dout{actx.request_context} << "    Input skipped because machine requested";
                reason = input_skip_reason::requested_by_machine;
            } else if (run_response.value().iflags_h()) {
dout{actx.request_context} << "    Input skipped because machine is halted";
                reason = input_skip_reason::machine_halted;
            } else if (run_response.value().mcycle() >= max_mcycle) {
dout{actx.request_context} << "    Input skipped because cycle limit was exceeded";
                reason = input_skip_reason::cycle_limit_exceeded;
            } else {
                THROW((taint_session{actx.session, grpc::StatusCode::INTERNAL, "failed running input"}));
            }
            // Add skipped input
            e.processed_inputs.push_back(
                processed_input_type{
                    input_index,
                    get_root_hash(actx),
                    reason
                }
            );
            // Add null hashes to the epoch Merkle trees
            hash_type zero;
            std::fill_n(zero.begin(), zero.size(), 0);
            e.outputs_tree.push_back(zero);
            e.messages_tree.push_back(zero);
            // Leave session.current_mcycle alone
        }
        // Finally remove pending
        e.pending_inputs.pop_front();
    }
}

/// \brief Creates a new handler for the EnqueueInput RPC and starts accepting requests
/// \param hctx Handler context shared between all handlers
static handler_type::pull_type *new_EnqueueInput_handler(handler_context &hctx) {
    auto* self = static_cast<handler_type::pull_type *>(operator new(sizeof(handler_type::pull_type)));
    new (self) handler_type::pull_type {
        [self, &hctx](handler_type::push_type &yield) {
            using namespace grpc;
            ServerContext request_context;
            EnqueueInputRequest enqueue_input_request;
            ServerAsyncResponseWriter<Void> enqueue_input_writer(&request_context);
            auto *cq = hctx.completion_queue.get();
            // Wait for a EnqueueInput RPC
            hctx.manager_async_service.RequestEnqueueInput(&request_context, &enqueue_input_request, &enqueue_input_writer, cq, cq, self);
            yield(side_effect::none);
            // We now received a EnqueueInput
            // We will handle other EnqueueInput rpcs if we yield
            new_EnqueueInput_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
            // Not sure if we can receive an RPC with ok set to false. To be safe, we will ignore those.
            if (!hctx.ok) {
                return;
            }
            try {
                // Check if session id exists
                auto &sessions = hctx.sessions; // NOLINT: Unknown. Maybe linter bug?
                const auto &id = enqueue_input_request.session_id();
dout{request_context} << "Received EnqueueInput for id " << id << " epoch " << enqueue_input_request.active_epoch_index();
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
                if (session.session_lock) {
                    THROW((finish_error_yield_none{grpc::StatusCode::ABORTED, "concurrent call in session"}));
                }
                // Lock session so other rpcs to the same session are rejected
                auto_lock session_lock(session.session_lock);
                // If session is tainted, report potential data loss
                if (session.tainted) {
                    THROW((finish_error_yield_none{grpc::StatusCode::DATA_LOSS, "session is tainted"}));
                }
                // If active epoch does not match expected, bail out
                if (session.active_epoch_index != enqueue_input_request.active_epoch_index()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "incorrect active epoch index (expected " +
                        std::to_string(session.active_epoch_index) + ", got " + std::to_string(enqueue_input_request.active_epoch_index()) + ")"}));
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
                auto current_input_index = e.pending_inputs.size()+e.processed_inputs.size();
                if (current_input_index != enqueue_input_request.current_input_index()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "incorrect current input index (expected " +
                        std::to_string(current_input_index) + ", got " + std::to_string(enqueue_input_request.current_input_index()) + ")"}));
                }
                // Check size of input metadata
                const auto input_metadata_size = enqueue_input_request.input_metadata().size();
                if (input_metadata_size != INPUT_METADATA_LENGTH) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "input metadata wrong size (expected " +
                        std::to_string(INPUT_METADATA_LENGTH) + " bytes, got " + std::to_string(input_metadata_size) + " bytes)"}));
                }
                // Check size of input payload
                const auto input_payload_size = enqueue_input_request.input_payload().size();
                if (input_payload_size >= session.input_description.payload_flash_drive_config.length()) {
                    THROW((finish_error_yield_none{grpc::StatusCode::INVALID_ARGUMENT, "input payload too long for machine (expected " +
                        std::to_string(session.input_description.payload_flash_drive_config.length()) + " bytes max, got " + std::to_string(input_payload_size) +
                            " bytes)"}));
                }
                // Enqueue input
                e.pending_inputs.emplace_back(enqueue_input_request.input_metadata(), enqueue_input_request.input_payload());
                // Tell caller RPC succeeded
                Void enqueue_input_response;
                enqueue_input_writer.Finish(enqueue_input_response, grpc::Status::OK, self);
                yield(side_effect::none); // Here the session is still locked, so no concurrent calls are possible
                // Release the lock so other RPCs can enqueue additional inputs to the same session/epoch
                session_lock.release();
                // Between unlocking the session and the check here, there is no
                // yield, and so no other EnqueueInput RPC can be in flight for
                // the same session. This means that the handler entering the
                // branch will be exactly the handler that enqueued the input that
                // caused the pending_inputs queue to not be empty anymore. While
                // working on this single input, the handler can yield (because
                // it talks to the machine server asynchronously) and allow
                // other EnqueueInput RPCs to grow the pending_inputs queue further.
                // However, those other RPCs will not enter the branch, because
                // process_pending_inputs only removes items from the queue when
                // it is completely done with it. Between removing the pending
                // input and checking if there are other pending inputs, the
                // handler does not yield. Therefore, it will process all
                // pending inputs that have been enqueue while it is working.
                //?? Victor and Diego both think this logic is sound but is too complicated.
                //?? Any better ideas?
                if (e.pending_inputs.size() == 1) {
                    async_context actx{session, request_context, hctx.completion_queue.get(), self, yield};
                    process_pending_inputs(actx, e);
                }
            } catch (finish_error_yield_none &e) {
                dout{request_context} << "Caught finish_error_yield_none '" << e.status().error_message() << '\'';
                enqueue_input_writer.FinishWithError(e.status(), self);
                yield(side_effect::none);
            } catch (taint_session &e) {
                dout{request_context} << "Caught taint_status " << e.status().error_message();
                auto &session = e.session();
                session.tainted = true;
                session.taint_status = e.status();
            } catch (std::exception &e) {
                dout{request_context} << "Caught unexpected exception " << e.what();
                const auto &id = enqueue_input_request.session_id();
                if (hctx.sessions.find(id) != hctx.sessions.end()) {
                    auto &session = hctx.sessions[id];
                    session.tainted = true;
                    session.taint_status = grpc::Status{grpc::StatusCode::INTERNAL, std::string{"unexpected exception "} + e.what()};
                }
            }
        }
    };
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
    builder.AddListeningPort(manager_address, grpc::InsecureServerCredentials(),
        &manager_port);
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
	fprintf(stderr,
R"(Usage:

	%s --manager-address=<address> --server-address=<address> [--help]

where

      --manager-address=<address>
      gives the address manager will bind to, where <address> can be
        <ipv4-hostname/address>:<port>
        <ipv6-hostname/address>:<port>
        unix:<path>

    --server-address=<server-address> or [<server-address>]
      passed to spawned Cartesi Machine Servers
      default: localhost:0

    --help
      prints this message and exits

)", name);

}

/// \brief Checks if string matches prefix and captures remaninder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remaninder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    int len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        *val = str + len;
        return true;
    }
    return false;
}

static void cleanup_child_handler(int signal) {
    (void) signal;
    while (waitpid(static_cast<pid_t>(-1), 0, WNOHANG) > 0) {}
}

int main(int argc, char *argv[]) try {

    static_assert(std::tuple_size<hash_type>::value == KECCAK_SIZE, "hash size mismatch");

    const char *manager_address = nullptr;
    const char *server_address = "localhost:0";

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

    hctx.manager_address = manager_address;
    hctx.server_address = server_address;

    std::cerr << "manager version is " <<
        manager_version_major << "." <<
        manager_version_minor << "." <<
        manager_version_patch << "\n";

    auto manager = build_manager(manager_address, hctx);
    if (!manager) {
        std::cerr << "manager server creation failed\n";
        exit(1);
    }

    struct sigaction sa{};
    sa.sa_handler = cleanup_child_handler;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);

    // Start accepting requests for all RPCs
    new_GetVersion_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_StartSession_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_EnqueueInput_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_GetStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_GetSessionStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_GetEpochStatus_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_FinishEpoch_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)
    new_EndSession_handler(hctx); // NOLINT: cannot leak (pointer is in completion queue)

    // Dispatch loop
    for ( ;; ) {
        // Obtain the next active handler
        handler_type::pull_type *h = nullptr; // NOLINT: cannot leak (drain_completion_queue kills remaining)
        if (!hctx.completion_queue->Next(reinterpret_cast<void **>(&h), &hctx.ok)) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
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
    hctx.server_group.terminate();
    hctx.server_group.wait();
    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}

