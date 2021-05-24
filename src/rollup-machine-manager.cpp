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
#include <boost/coroutine2/coroutine.hpp>
#include <unordered_map>
#include <deque>
#include <array>

#define MANAGER_VERSION_MAJOR UINT32_C(0)
#define MANAGER_VERSION_MINOR UINT32_C(0)
#define MANAGER_VERSION_PATCH UINT32_C(0)
#define MANAGER_VERSION_PRE_RELEASE ""
#define MANAGER_VERSION_BUILD ""

#define SERVER_VERSION_MAJOR UINT32_C(0)
#define SERVER_VERSION_MINOR UINT32_C(3)
#define SERVER_VERSION_PATCH UINT32_C(0)
#define SERVER_VERSION_PRE_RELEASE ""
#define SERVER_VERSION_BUILD ""

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#include "rollup-machine-manager.grpc.pb.h"
#pragma GCC diagnostic pop

using namespace CartesiRollupMachineManager;
using namespace CartesiMachine;
using namespace Versioning;

#include "keccak-256-hasher.h"
#include "merkle-tree-proof.h"
#include "complete-merkle-tree.h"

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

struct session {
    session_id id;
    std::unique_ptr<Machine::Stub> stub;
    uint64_t active_epoch_index;
    uint64_t max_mcycle_per_input;
    payload_and_metadata input_description;
    payload_and_metadata_array outputs_description;
    payload_and_metadata_array messages_description;
    std::unordered_map<uint64_t, epoch> epochs;
};

struct handler_context {
    std::unordered_map<session_id, session> sessions;
    RollupMachineManager::AsyncService async_service;
    std::unique_ptr<grpc::ServerCompletionQueue> completion_queue;
    bool ok;
};

enum class side_effect {
    none,
    shutdown
};

using handler = boost::coroutines2::coroutine<side_effect>;

#if 0

template <typename RESP>
static void writer_finish(grpc::ServerAsyncResponseWriter<RESP> &writer, const RESP &response, const grpc::Status &status, handler::pull_type *self) {
    if (status.ok()) {
        writer.Finish(response, grpc::Status::OK, self);
    } else {
        writer.FinishWithError(status, self);
    }
}

template <
    typename REQ_TYPE,  // <rpc-name> request message type
    typename RESP_TYPE, // <rpc-name> response message type
    typename SRV_REQ,   // functor that invokes Request<rpc-name>
    typename CLNT_REQ   // functor that invokes Async<rpc-name>
>
static handler::pull_type *new_handler(const std::string &rpc_name,
    SRV_REQ start_server_request, CLNT_REQ start_client_request, side_effect last_effect = side_effect::none) {
    // Here we had a fun conundrum to solve.  We want to allocate a new
    // handler::pull_type object and initialize it with a lambda function that
    // contains the coroutine implementation.  However, we want to give this lambda
    // access to the value of the pointer holding the new handler::pull_type object.
    // This is because it needs to use this this pointer in gRPC calls that will
    // return it in the completion queue.  If we used the normal new operator, the
    // lambda would be constructed before the value was returned by the operator, and
    // therefore would capture an uninitialized value. So we break the
    // construction into an allocation with operator new and construction with
    // placement new.
    handler::pull_type* self = reinterpret_cast<handler::pull_type *>(operator new(sizeof(handler::pull_type)));
    new (self) handler::pull_type {
        [self, rpc_name, start_server_request, start_client_request, last_effect](handler::push_type &yield) {
            using namespace grpc;
            ServerContext server_context;
            REQ_TYPE request;
            ServerAsyncResponseWriter<RESP_TYPE> writer(&server_context);
            // Advertise we are ready to process requests
            start_server_request(server_context, request, writer, self);
            // Yield until a request arrives, we are returned in the completion
            // queue, and the dispatcher resumes us
            yield(side_effect::none);
            ClientContext client_context;
            Status status;
            // Start a client request
            auto reader = start_client_request(client_context, request);
            RESP_TYPE response;
            // Advertise we are waiting for the response
            reader->Finish(&response, &status, self);
            // Yield until the response arrives, we are returned in the
            // completion queue, and the dispatcher resumes us
            yield(side_effect::none);
            // Start client response
            writer_finish(writer, response, status, self);
            // Yield until done sending response, we are returned in the
            // completion queue, and the dispatcher resumes us
            yield(last_effect);
            // Create a new handler for the same <rpc-name>
            new_handler<REQ_TYPE, RESP_TYPE>(rpc_name, start_server_request, start_client_request);
            // Allow the coroutine to finish. The dispatcher loop will
            // immediately delete it.
        }
    };
    return self;
}
#endif

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
            hctx.async_service.RequestGetVersion(&server_context, &request,
                &writer, cq, cq, self);
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

static auto build_server(const std::string &address, handler_context &hctx) {
    grpc::ServerBuilder builder;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&hctx.async_service);
    hctx.completion_queue = builder.AddCompletionQueue();
    return builder.BuildAndStart();
}

static bool test_machine_server(const std::string &address) {
    auto stub = Machine::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    if (!stub) {
        return false;
    }
    Void request;
    GetVersionResponse response;
    grpc::ClientContext context;
    auto status = stub->GetVersion(&context, request, &response);
    if (!status.ok()) {
        return false;
    }
    std::cerr << "connected to server: version is " <<
        response.version().major() << "." <<
        response.version().minor() << "." <<
        response.version().patch() << "\n";

    if (response.version().major() != SERVER_VERSION_MAJOR ||
        response.version().minor() != SERVER_VERSION_MINOR) {
        std::cerr << "machine manager is incompatible with server\n";
        return false;
    }

    return true;
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

int main(int argc, char *argv[]) {

    if (argc < 3) {
        std::cerr << "Usage:\n";
        std::cerr << "  " << argv[0] << " <proxy-address> <remote-address>\n";
        std::cerr << "where <address> can be\n";
        std::cerr << "  <ipv4-hostname/address>:<port>\n";
        std::cerr << "  <ipv6-hostname/address>:<port>\n";
        std::cerr << "  unix:<path>\n";
        exit(1);
    }

    handler_context hctx{};

    std::cerr << "proxy version is " <<
        MANAGER_VERSION_MAJOR << "." <<
        MANAGER_VERSION_MINOR << "." <<
        MANAGER_VERSION_PATCH << "\n";

    if (!test_machine_server(argv[2])) {
        std::cerr << "machine server connection failed\n";
        exit(1);
    }

    auto server = build_server(argv[1], hctx);
    if (!server) {
        std::cerr << "server creation failed\n";
        exit(1);
    }

    new_GetVersion_handler(hctx);

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
    server->Shutdown();
    drain_completion_queue(hctx.completion_queue.get());
    // Make sure we don't leave a snapshot burried
    return 0;
}

