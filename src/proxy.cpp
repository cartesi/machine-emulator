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
#include <string>
#include <boost/coroutine2/coroutine.hpp>

#define PROXY_VERSION_MAJOR UINT32_C(0)
#define PROXY_VERSION_MINOR UINT32_C(4)
#define PROXY_VERSION_PATCH UINT32_C(0)
#define PROXY_VERSION_PRE_RELEASE ""
#define PROXY_VERSION_BUILD ""

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

using namespace CartesiMachine;
using namespace Versioning;

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
struct handler_context {
    Machine::AsyncService async_service;
    std::unique_ptr<Machine::Stub> stub;
    std::unique_ptr<grpc::ServerCompletionQueue> completion_queue;
    bool ok;
};

enum class side_effect {
    none,
    shutdown
};

using handler = boost::coroutines2::coroutine<side_effect>;

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

static auto new_GetVersion_handler(handler_context &hctx) {
    return new_handler<Void, GetVersionResponse>("GetVersion",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetVersion(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetVersion(&client_context, request, cq);
        }
    );
}

static auto new_Machine_handler(handler_context &hctx) {
    return new_handler<MachineRequest, Void>("Machine",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestMachine(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncMachine(&client_context, request, cq);
        }
    );
}

static auto new_Run_handler(handler_context &hctx) {
    return new_handler<RunRequest, RunResponse>("Run",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestRun(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncRun(&client_context, request, cq);
        }
    );
}

static auto new_Store_handler(handler_context &hctx) {
    return new_handler<StoreRequest, Void>("Store",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestStore(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncStore(&client_context, request, cq);
        }
    );
}

static auto new_Destroy_handler(handler_context &hctx) {
    return new_handler<Void, Void>("Destroy",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestDestroy(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncDestroy(&client_context, request, cq);
        }
    );
}

static auto new_Snapshot_handler(handler_context &hctx) {
    return new_handler<Void, Void>("Snapshot",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestSnapshot(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncSnapshot(&client_context, request, cq);
        }
    );
}

static auto new_Rollback_handler(handler_context &hctx) {
    return new_handler<Void, Void>("Rollback",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestRollback(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncRollback(&client_context, request, cq);
        }
    );
}

static auto new_Shutdown_handler(handler_context &hctx) {
    return new_handler<Void, Void>("Shutdown",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestShutdown(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncShutdown(&client_context, request, cq);
        },
        side_effect::shutdown
    );
}

static auto new_Step_handler(handler_context &hctx) {
    return new_handler<StepRequest, StepResponse>("Step",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestStep(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncStep(&client_context, request, cq);
        }
    );
}

static auto new_ReadMemory_handler(handler_context &hctx) {
    return new_handler<ReadMemoryRequest, ReadMemoryResponse>("ReadMemory",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReadMemory(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReadMemory(&client_context, request, cq);
        }
    );
}

static auto new_WriteMemory_handler(handler_context &hctx) {
    return new_handler<WriteMemoryRequest, Void>("WriteMemory",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestWriteMemory(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncWriteMemory(&client_context, request, cq);
        }
    );
}

static auto new_ReadWord_handler(handler_context &hctx) {
    return new_handler<ReadWordRequest, ReadWordResponse>("ReadWord",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReadWord(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReadWord(&client_context, request, cq);
        }
    );
}

static auto new_GetRootHash_handler(handler_context &hctx) {
    return new_handler<Void, GetRootHashResponse>("GetRootHash",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetRootHash(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetRootHash(&client_context, request, cq);
        }
    );
}

static auto new_GetProof_handler(handler_context &hctx) {
    return new_handler<GetProofRequest, GetProofResponse>("GetProof",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetProof(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetProof(&client_context, request, cq);
        }
    );
}

static auto new_ReplaceFlashDrive_handler(handler_context &hctx) {
    return new_handler<ReplaceFlashDriveRequest, Void>("ReplaceFlashDrive",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReplaceFlashDrive(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReplaceFlashDrive(&client_context, request, cq);
        }
    );
}

static auto new_GetXAddress_handler(handler_context &hctx) {
    return new_handler<GetXAddressRequest, GetXAddressResponse>("GetXAddress",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetXAddress(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetXAddress(&client_context, request, cq);
        }
    );
}

static auto new_ReadX_handler(handler_context &hctx) {
    return new_handler<ReadXRequest, ReadXResponse>("ReadX",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReadX(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReadX(&client_context, request, cq);
        }
    );
}

static auto new_WriteX_handler(handler_context &hctx) {
    return new_handler<WriteXRequest, Void>("WriteX",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestWriteX(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncWriteX(&client_context, request, cq);
        }
    );
}

static auto new_ResetIflagsY_handler(handler_context &hctx) {
    return new_handler<Void, Void>("ResetIflagsY",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestResetIflagsY(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncResetIflagsY(&client_context, request, cq);
        }
    );
}

static auto new_GetDhdHAddress_handler(handler_context &hctx) {
    return new_handler<GetDhdHAddressRequest, GetDhdHAddressResponse>("GetDhdHAddress",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetDhdHAddress(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetDhdHAddress(&client_context, request, cq);
        }
    );
}

static auto new_ReadDhdH_handler(handler_context &hctx) {
    return new_handler<ReadDhdHRequest, ReadDhdHResponse>("ReadDhdH",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReadDhdH(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReadDhdH(&client_context, request, cq);
        }
    );
}

static auto new_WriteDhdH_handler(handler_context &hctx) {
    return new_handler<WriteDhdHRequest, Void>("WriteDhdH",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestWriteDhdH(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncWriteDhdH(&client_context, request, cq);
        }
    );
}

static auto new_GetCsrAddress_handler(handler_context &hctx) {
    return new_handler<GetCsrAddressRequest, GetCsrAddressResponse>("GetCsrAddress",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetCsrAddress(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetCsrAddress(&client_context, request, cq);
        }
    );
}

static auto new_ReadCsr_handler(handler_context &hctx) {
    return new_handler<ReadCsrRequest, ReadCsrResponse>("ReadCsr",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestReadCsr(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncReadCsr(&client_context, request, cq);
        }
    );
}

static auto new_WriteCsr_handler(handler_context &hctx) {
    return new_handler<WriteCsrRequest, Void>("WriteCsr",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestWriteCsr(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncWriteCsr(&client_context, request, cq);
        }
    );
}

static auto new_GetInitialConfig_handler(handler_context &hctx) {
    return new_handler<Void, GetInitialConfigResponse>("GetInitialConfig",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetInitialConfig(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetInitialConfig(&client_context, request, cq);
        }
    );
}

static auto new_VerifyMerkleTree_handler(handler_context &hctx) {
    return new_handler<Void, VerifyMerkleTreeResponse>("VerifyMerkleTree",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestVerifyMerkleTree(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncVerifyMerkleTree(&client_context, request, cq);
        }
    );
}

static auto new_UpdateMerkleTree_handler(handler_context &hctx) {
    return new_handler<Void, UpdateMerkleTreeResponse>("UpdateMerkleTree",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestUpdateMerkleTree(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncUpdateMerkleTree(&client_context, request, cq);
        }
    );
}

static auto new_VerifyDirtyPageMaps_handler(handler_context &hctx) {
    return new_handler<Void, VerifyDirtyPageMapsResponse>("VerifyDirtyPageMaps",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestVerifyDirtyPageMaps(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncVerifyDirtyPageMaps(&client_context, request, cq);
        }
    );
}

static auto new_DumpPmas_handler(handler_context &hctx) {
    return new_handler<Void, Void>("DumpPmas",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestDumpPmas(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncDumpPmas(&client_context, request, cq);
        }
    );
}

static auto new_GetDefaultConfig_handler(handler_context &hctx) {
    return new_handler<Void, GetDefaultConfigResponse>("GetDefaultConfig",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestGetDefaultConfig(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncGetDefaultConfig(&client_context, request, cq);
        }
    );
}

static auto new_VerifyAccessLog_handler(handler_context &hctx) {
    return new_handler<VerifyAccessLogRequest, Void>("VerifyAccessLog",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestVerifyAccessLog(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncVerifyAccessLog(&client_context, request, cq);
        }
    );
}

static auto new_VerifyStateTransition_handler(handler_context &hctx) {
    return new_handler<VerifyStateTransitionRequest, Void>("VerifyStateTransition",
        [&hctx](auto &server_context, auto &request, auto &writer, auto self) {
            auto cq = hctx.completion_queue.get();
            hctx.async_service.RequestVerifyStateTransition(&server_context, &request, &writer, cq, cq, self);
        },
        [&hctx](auto &client_context, auto &request) {
            auto cq = hctx.completion_queue.get();
            return hctx.stub->AsyncVerifyStateTransition(&client_context, request, cq);
        }
    );
}

static auto build_server(const std::string &address, handler_context &hctx) {
    grpc::ServerBuilder builder;
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&hctx.async_service);
    hctx.completion_queue = builder.AddCompletionQueue();
    return builder.BuildAndStart();
}

static bool build_client(const std::string &address, handler_context &hctx) {
    hctx.stub = Machine::NewStub(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    if (!hctx.stub) {
        return false;
    }
    Void request;
    GetVersionResponse response;
    grpc::ClientContext context;
    auto status = hctx.stub->GetVersion(&context, request, &response);
    if (!status.ok()) {
        return false;
    }
    std::cerr << "connected to server: version is " <<
        response.version().major() << "." <<
        response.version().minor() << "." <<
        response.version().patch() << "\n";

    if (response.version().major() != PROXY_VERSION_MAJOR ||
        response.version().minor() != PROXY_VERSION_MINOR) {
        std::cerr << "proxy is incompatible with server\n";
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
        PROXY_VERSION_MAJOR << "." <<
        PROXY_VERSION_MINOR << "." <<
        PROXY_VERSION_PATCH << "\n";

    if (!build_client(argv[2], hctx)) {
        std::cerr << "client creation failed\n";
        exit(1);
    }

    auto server = build_server(argv[1], hctx);
    if (!server) {
        std::cerr << "server creation failed\n";
        exit(1);
    }

    new_GetVersion_handler(hctx);
    new_Machine_handler(hctx);
    new_Run_handler(hctx);
    new_Store_handler(hctx);
    new_Destroy_handler(hctx);
    new_Snapshot_handler(hctx);
    new_Rollback_handler(hctx);
    new_Shutdown_handler(hctx);
    new_Step_handler(hctx);
    new_ReadMemory_handler(hctx);
    new_WriteMemory_handler(hctx);
    new_ReadWord_handler(hctx);
    new_GetRootHash_handler(hctx);
    new_GetProof_handler(hctx);
    new_ReplaceFlashDrive_handler(hctx);
    new_GetXAddress_handler(hctx);
    new_ReadX_handler(hctx);
    new_WriteX_handler(hctx);
    new_ResetIflagsY_handler(hctx);
    new_GetDhdHAddress_handler(hctx);
    new_ReadDhdH_handler(hctx);
    new_WriteDhdH_handler(hctx);
    new_GetCsrAddress_handler(hctx);
    new_ReadCsr_handler(hctx);
    new_WriteCsr_handler(hctx);
    new_GetInitialConfig_handler(hctx);
    new_VerifyMerkleTree_handler(hctx);
    new_UpdateMerkleTree_handler(hctx);
    new_VerifyDirtyPageMaps_handler(hctx);
    new_DumpPmas_handler(hctx);
    new_GetDefaultConfig_handler(hctx);
    new_VerifyAccessLog_handler(hctx);
    new_VerifyStateTransition_handler(hctx);

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

