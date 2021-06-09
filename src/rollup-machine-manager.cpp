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
#include <deque>
#include <array>
#include <variant>
#include <optional>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <boost/coroutine2/coroutine.hpp>
#include <boost/process.hpp>
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#include "cartesi-machine-checkin.grpc.pb.h"
#include "rollup-machine-manager.grpc.pb.h"
#pragma GCC diagnostic pop

#define MANAGER_VERSION_MAJOR UINT32_C(0)
#define MANAGER_VERSION_MINOR UINT32_C(0)
#define MANAGER_VERSION_PATCH UINT32_C(0)
#define MANAGER_VERSION_PRE_RELEASE ""
#define MANAGER_VERSION_BUILD ""

#define MACHINE_VERSION_MAJOR UINT32_C(0)
#define MACHINE_VERSION_MINOR UINT32_C(3)
#define MACHINE_VERSION_PATCH UINT32_C(0)
#define MACHINE_VERSION_PRE_RELEASE ""
#define MACHINE_VERSION_BUILD ""

using namespace CartesiRollupMachineManager;
using namespace CartesiMachine;
using namespace Versioning;

#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "complete-merkle-tree.h"
#include "grpc-util.h"

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
// for a given <rpc-name> by calling service->Request<rpc-name>() method, and
// passing the server context, a request message to receive the request, the
// writer object for the response, the completion queue, and a tag.
// 2) Once a request for <rpc-name> arrives, the completion queue will return
// the corresponding tag
// 3) After performing the requested task, we fill out a response message, and
// ask the writer object to send the response, using writer->Finish(), passing
// the response message, a status object, and a tag
// 4) Once the response has been acknowledged, the completion queue will return
// the tag
//
// PS: To allow for overlapped processing of multiple calls to <rpc-name>, we
// can call service->Request<rpc-name>() with a new tag as soon as the
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
// <rpc-name> by calling stub->Async<rpc-name>(), passing the client context,
// the request message, and the completion queue. This method returns the reader
// object.
// 2) We then call reader->Finish() passing the response object to be filled,
// the status object to be filled, and a tag
// 3) Once the response is received, the completion queue will return the tag.
//
// In the case of a proxy, the typical situation is that the proxy receives a
// server call that it can only complete after it performed a client call.
// The idea is as follows:
// 1) Completion queue returns tag-1 identifying an <rpc-name> server call
// 2) Processing of tag-1 starts the appropriate client call
// using stub->Async<rpc-name>() and reader->Finish(), and specifes tag-2 for completion
// 4) Completion queue returns tag-2 identifying the client call is complete
// 5) Processing of tag-2 passes result back using write->Finish(), and specifies tag-3 for completion
// 6) Completion queue returns tag-3 identifying results were received
// 7) Processing of tag-3 calls service->Request<rpc-name>() to specify a new
// tag to handle the next <rpc-name> server call
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

using hasher_type = cartesi::keccak_256_hasher;

using hash_type = hasher_type::hash_type;

using address_type = uint64_t;

using proof_type = cartesi::merkle_tree_proof<hash_type, address_type>;

struct payload_and_metadata {
    uint64_t metadata_flash_drive_index;
    uint64_t payload_flash_drive_index;
};

struct payload_and_metadata_array {
    payload_and_metadata drive_pair;
    uint64_t entry_count;
    uint64_t payload_entry_length;
};

#define INPUT_METADATA_LENGTH 128

struct input {
    std::vector<uint8_t> payload;
    std::array<uint8_t, INPUT_METADATA_LENGTH> metadata;
};

struct output {
    hash_type keccak;
    hash_type address;
    std::vector<uint8_t> payload;
    proof_type keccak_in_output_metadata_flash_drive;
};

struct message {
    hash_type keccak;
    std::vector<uint8_t> payload;
    proof_type keccak_in_message_metadata_flash_drive;
};

struct input_result {
    proof_type output_metadata_flash_drive_in_machine;
    proof_type output_metadata_flash_drive_in_epoch;
    std::vector<output> outputs;
    proof_type message_metadata_flash_drive_in_machine;
    proof_type message_metadata_flash_drive_in_epoch;
    std::vector<message> messages;
};

enum class epoch_status {
    active,
    finished
};

using session_id = std::string;

constexpr const int LOG2_ROOT_SIZE = 37;
constexpr const int LOG2_LEAF_SIZE = 5;
constexpr const int LOG2_WORD_SIZE = 5;

struct epoch {
    uint64_t epoch_index{0};
    epoch_status status{epoch_status::active};
    cartesi::complete_merkle_tree outputs_tree{
        LOG2_ROOT_SIZE,
        LOG2_LEAF_SIZE,
        LOG2_WORD_SIZE
    };
    cartesi::complete_merkle_tree messages_tree{
        LOG2_ROOT_SIZE,
        LOG2_LEAF_SIZE,
        LOG2_WORD_SIZE
    };
    std::vector<input_result> procesed_input_results;
    std::deque<input> pending_inputs;
};

struct machine_request {
    std::variant<cartesi::machine_config, std::string> config_or_directory;
    cartesi::machine_runtime_config runtime;
};

struct session {
    session_id id;
    std::optional<machine_request> initial_config;
    std::unique_ptr<Machine::Stub> server_stub;
    uint64_t active_epoch_index;
    uint64_t current_input_index;
    uint64_t max_cycles_per_input;
    payload_and_metadata input_description;
    payload_and_metadata_array outputs_description;
    payload_and_metadata_array messages_description;
    std::unordered_map<uint64_t, epoch> epochs;
};

struct handler_context {
    std::string manager_address, server_address;
    std::unordered_map<session_id, session> sessions;
    RollupMachineManager::AsyncService manager_async_service;
    MachineCheckIn::AsyncService checkin_async_service;
    std::unique_ptr<grpc::ServerCompletionQueue> completion_queue;
    boost::process::group server_group;
    bool ok;
};

enum class side_effect {
    none,
    shutdown
};

using handler = boost::coroutines2::coroutine<side_effect>;

static void new_GetVersion_handler(handler_context &hctx) {
    using REQ_TYPE = Void;
    using RESP_TYPE = GetVersionResponse;
    handler::pull_type* self = reinterpret_cast<handler::pull_type *>(operator new(sizeof(handler::pull_type)));
    new (self) handler::pull_type {
        [self, &hctx](handler::push_type &yield) {
            using namespace grpc;
            ServerContext server_context;
            REQ_TYPE request;
            ServerAsyncResponseWriter<RESP_TYPE> writer(&server_context);
            auto cq = hctx.completion_queue.get();
            hctx.manager_async_service.RequestGetVersion(&server_context,
                &request, &writer, cq, cq, self);
            yield(side_effect::none);
            Status status;
            RESP_TYPE response;
            auto version = response.mutable_version();
            version->set_major(MANAGER_VERSION_MAJOR);
            version->set_minor(MANAGER_VERSION_MINOR);
            version->set_patch(MANAGER_VERSION_PATCH);
            version->set_pre_release(MANAGER_VERSION_PRE_RELEASE);
            version->set_build(MANAGER_VERSION_BUILD);
            writer.Finish(response, grpc::Status::OK, self);
            yield(side_effect::none);
            new_GetVersion_handler(hctx);
        }
    };
}

static payload_and_metadata get_proto_payload_and_metadata(
    const PayloadAndMetadata &proto_p) {
    payload_and_metadata p;
    p.metadata_flash_drive_index = proto_p.metadata_flash_drive_index();
    p.payload_flash_drive_index = proto_p.payload_flash_drive_index();
    return p;
}

static payload_and_metadata_array get_proto_payload_and_metadata_array(
    const PayloadAndMetadataArray &proto_p) {
    payload_and_metadata_array p;
    p.drive_pair = get_proto_payload_and_metadata(proto_p.drive_pair());
    p.entry_count = proto_p.entry_count();
    p.payload_entry_length = proto_p.payload_entry_length();
    return p;
}

static std::optional<machine_request> get_proto_machine_request(const
    MachineRequest &proto_m) {
    machine_request m;
    m.runtime = cartesi::get_proto_machine_runtime_config(proto_m.runtime());
    switch (proto_m.machine_oneof_case()) {
        case MachineRequest::kConfig:
            m.config_or_directory = cartesi::get_proto_machine_config(
                proto_m.config());
            return m;
        case MachineRequest::kDirectory:
            m.config_or_directory = proto_m.directory();
            return m;
        default:
            return {};
    }
}

static session get_proto_session(const StartSessionRequest &req) {
    session s;
    s.id = req.session_id();
    s.initial_config = get_proto_machine_request(req.machine());
    s.active_epoch_index = req.active_epoch_index();
    s.current_input_index = req.current_input_index();
    s.max_cycles_per_input = req.max_cycles_per_input();
    s.input_description = get_proto_payload_and_metadata(req.
        input_description());
    s.outputs_description = get_proto_payload_and_metadata_array(req.
        outputs_description());
    s.messages_description = get_proto_payload_and_metadata_array(req.
        messages_description());
    return s;
}

static void new_StartSession_handler(handler_context &hctx) {
    handler::pull_type* self = reinterpret_cast<handler::pull_type *>(operator new(sizeof(handler::pull_type)));
    new (self) handler::pull_type {
        [self, &hctx](handler::push_type &yield) {
            using namespace grpc;
            ServerContext start_session_context;
            StartSessionRequest start_session_request;
            ServerAsyncResponseWriter<Void> start_session_writer(
                &start_session_context);
            auto cq = hctx.completion_queue.get();
            // Wait for a StartSession rpc
            hctx.manager_async_service.RequestStartSession(
                &start_session_context, &start_session_request,
                &start_session_writer, cq, cq, self);
            yield(side_effect::none);
            // If session with same id already exists
            auto &sessions = hctx.sessions;
            auto id = start_session_request.session_id();
            // If this is not a new session, bail out
            if (sessions.find(id) != sessions.end()) {
                // Start handling the next StartSession rpc
                new_StartSession_handler(hctx);
                // Return error for this rpc and we are done
                start_session_writer.FinishWithError(
                    Status{StatusCode::ALREADY_EXISTS,
                    "session id is taken"}, self);
                yield(side_effect::none);
                return;
            }
            // Otherwise, add entry for session
            auto &s = (sessions[id] = get_proto_session(start_session_request));
            // If no machine specification, bail out
            if (!s.initial_config.has_value()) {
                // Unreserve session id
                sessions.erase(id);
                // Start handling the next StartSession rpc
                new_StartSession_handler(hctx);
                // Return error for this rpc and we are done
                start_session_writer.FinishWithError(
                    Status{StatusCode::INVALID_ARGUMENT,
                    "missing initial machine config"}, self);
                yield(side_effect::none);
                return;
            }
            // Spawn a new server
            auto cmdline = "./cartesi-machine-server --session-id='" +
                id + "' --checkin-address=" + hctx.manager_address +  " --server-address=" + hctx.server_address;
            boost::process::spawn(cmdline, hctx.server_group);
            // Wait for a CheckIn rpc
            ServerContext checkin_context;
            CheckInRequest checkin_request;
            ServerAsyncResponseWriter<Void> checkin_writer(&checkin_context);
            hctx.checkin_async_service.RequestCheckIn(&checkin_context,
                &checkin_request, &checkin_writer, cq, cq, self);
            yield(side_effect::none);
            // Acknowledge check-in
            Void checkin_response;
            checkin_writer.Finish(checkin_response, grpc::Status::OK, self);
            yield(side_effect::none);
            // At this point, we can safely start processing
            // new StartSession rpcs
            new_StartSession_handler(hctx);
            // Instantiate client connection
            s.server_stub = Machine::NewStub(
                grpc::CreateChannel(checkin_request.address(),
                    grpc::InsecureChannelCredentials()));
            // If unable to create stub, bail out
            if (!s.server_stub) {
                // Return error for this rpc and we are done
                start_session_writer.FinishWithError(
                    Status{StatusCode::RESOURCE_EXHAUSTED,
                    "unable to create machine stub for session"}, self);
                yield(side_effect::none);
                return;
            }
            // Try to get version from client
            Void version_request;
            GetVersionResponse version_response;
            grpc::ClientContext client_context;
            auto version_status = s.server_stub->GetVersion(&client_context,
                version_request, &version_response);
            // If getversion failed on the server, bail out
            if (!version_status.ok()) {
                // Return error for this rpc and we are done
                start_session_writer.FinishWithError(version_status, self);
                yield(side_effect::none);
                return;
            }
            // If version is incompatible, bail out
            if (version_response.version().major() != MACHINE_VERSION_MAJOR ||
                version_response.version().minor() != MACHINE_VERSION_MINOR) {
                // Return error for this rpc and we are done
                start_session_writer.FinishWithError(
                    Status{StatusCode::FAILED_PRECONDITION,
                    "manager is incompatible with machine server"}, self);
                yield(side_effect::none);
                return;
            }

            // Still need to instantiate the machine in the server
            // Still need to get the initial config returned by the instance
            // and see if our descriptions are compatible with it

            Void start_session_response;
            start_session_writer.Finish(start_session_response,
                grpc::Status::OK, self);
            yield(side_effect::none);
        }
    };
}

static std::string replace_port(const std::string &address, int port) {
    // Unix address?
    if (address.find("unix:") == 0) {
        return address;
    }
    auto pos = address.find_last_of(':');
    // If already has a port, replace
    if (pos != address.npos) {
        return address.substr(0, pos) + ":" + std::to_string(port);
    // Otherwise, concatenate
    } else {
        return address + ":" + std::to_string(port);
    }
}

static auto build_manager(const char *manager_address, handler_context &hctx) {
    grpc::ServerBuilder builder;
    int manager_port = 0;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(manager_address, grpc::InsecureServerCredentials(),
        &manager_port);
    hctx.manager_address = replace_port(manager_address, manager_port);
    builder.RegisterService(&hctx.manager_async_service);
    builder.RegisterService(&hctx.checkin_async_service);
    hctx.completion_queue = builder.AddCompletionQueue();
    return builder.BuildAndStart();
}

static void drain_completion_queue(grpc::ServerCompletionQueue *completion_queue) {
    completion_queue->Shutdown();
    bool ok = false;
    handler::pull_type *h = nullptr;
    while (completion_queue->Next(reinterpret_cast<void **>(&h), &ok)) {
        if (h) {
            delete h;
        }
    }
}

static bool finished(handler::pull_type *c) {
    return !(*c);
}

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
      passed spawned Cartesi Machine Servers
      default: localhost:0

    --help
      prints this message and exits

)", name);

};

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

int main(int argc, char *argv[]) {

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
        MANAGER_VERSION_MAJOR << "." <<
        MANAGER_VERSION_MINOR << "." <<
        MANAGER_VERSION_PATCH << "\n";

    auto manager = build_manager(manager_address, hctx);
    if (!manager) {
        std::cerr << "manager server creation failed\n";
        exit(1);
    }

    new_GetVersion_handler(hctx);
    new_StartSession_handler(hctx);

    for ( ;; ) {
        // Obtain the next active handler coroutine
        handler::pull_type *h = nullptr;
        if (!hctx.completion_queue->Next(reinterpret_cast<void **>(&h), &hctx.ok)) {
            goto shutdown;
        }
        // If the coroutine is finished, simply delete it
        // This can't really happen here, because the coroutine ALWAYS yields
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
                // Otherwise, if requested a shutdown, delete this coroutine and
                // shutdown. The other pending coroutines will be deleted when
                // we drain the completion queue.
                if (h->get() == side_effect::shutdown) {
                    delete h;
                    goto shutdown;
                }
            }
        }
    }

shutdown:
    // Shutdown server before completion queue
    manager->Shutdown();
    drain_completion_queue(hctx.completion_queue.get());
    hctx.server_group.terminate();
    hctx.server_group.wait();
    return 0;
}

