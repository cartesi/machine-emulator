// Copyright 2019 Cartesi Pte. Ltd.
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
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <chrono>
#include <cstdint>

#define SERVER_VERSION_MAJOR UINT32_C(0)
#define SERVER_VERSION_MINOR UINT32_C(2)
#define SERVER_VERSION_PATCH UINT32_C(0)
#define SERVER_VERSION_PRE_RELEASE ""
#define SERVER_VERSION_BUILD ""

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

#include "grpc-util.h"
#include "manager-client.h"

#include <chrono>
#include <thread>
#include <mutex>
#include <exception>

#include "machine.h"
#include "access-log.h"
#include "keccak-256-hasher.h"
#include "pma.h"
#include "unique-c-ptr.h"
#include "shadow.h"

#include <boost/program_options.hpp>

namespace po = boost::program_options;

using namespace cartesi;
using hash_type = keccak_256_hasher::hash_type;
using namespace CartesiMachine;
using namespace Versioning;
using grpc::Status;
using grpc::ServerContext;
using grpc::StatusCode;
using grpc::Server;

#define dbg(...) syslog(LOG_DEBUG, __VA_ARGS__)

struct Context {
    int value;
    std::string address;
    std::string manager_address;
    std::string session_id;
    bool auto_port;
    bool report_to_manager;
    bool forked;
    std::unique_ptr<cartesi::machine> machine;
};

// Move this to static member function of MachingServiceImpl?
static void shutdown_server(grpc::Server *s) {
    if (s) s->Shutdown();
}

static void squash_parent(Context &context) {
    // If we are a forked child, we have a parent waiting.
    // We want to take its place before exiting.
    // Wake parent up by signaling ourselves to stop.
    // Parent will wake us back up and then exit.
    if (context.forked) {
        raise(SIGSTOP);
        // When we wake up, we took the parent's place, so we are not "forked" anymore
        context.forked = false;
    }
}


enum class BreakReason {
    error,
    snapshot,
    rollback,
    shutdown
};

// Logic and data behind the server's behavior.
class MachineServiceImpl final: public CartesiMachine::Machine::Service {

    std::mutex barrier_;
    std::thread breaker_;
    grpc::Server *server_;
    Context &context_;
    BreakReason reason_;

    Status error_no_machine(void) const {
        dbg("No machine");
        return Status(StatusCode::FAILED_PRECONDITION, "no machine");
    }

    Status error_exception(const std::exception& e) const {
        dbg("Caught exception %s", e.what());
        return Status(StatusCode::ABORTED, e.what());
    }

    void Break(BreakReason reason) {
        // Here we have exclusie access to everything
        // because the Break method is only called after the
        // barrier_ has been acquired
        reason_ = reason;
        // If the breaker_ thread is joinable, it means we
        // it is already trying to shutdown the server.
        if (!breaker_.joinable())
           breaker_ = std::thread(shutdown_server, server_);
    }

    Status Machine(ServerContext *, const MachineRequest * request, Void *)
        override {
        std::lock_guard<std::mutex> lock(barrier_);
        // If machine already exists, abort
        if (context_.machine) {
            dbg("Machine already exists");
            return Status(StatusCode::FAILED_PRECONDITION,
                "machine already exists");
        }
        // Otherwise, try to create a new one
        try {
            switch (request->machine_oneof_case()) {
                case MachineRequest::kConfig:
                    context_.machine = std::make_unique<cartesi::machine>(
                        get_proto_machine_config(request->config()));
                    return Status::OK;
                case MachineRequest::kDirectory:
                    context_.machine = std::make_unique<cartesi::machine>(
                        request->directory());
                    return Status::OK;
                default:
                    return Status(StatusCode::INVALID_ARGUMENT,
                        "invalid machine specification");
            }
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status GetVersion(ServerContext *, const Void *,
        GetVersionResponse *response) override {
        auto version = response->mutable_version();
        version->set_major(SERVER_VERSION_MAJOR);
        version->set_minor(SERVER_VERSION_MINOR);
        version->set_patch(SERVER_VERSION_PATCH);
        version->set_pre_release(SERVER_VERSION_PRE_RELEASE);
        version->set_build(SERVER_VERSION_BUILD);
        return Status::OK;
    }

    Status Store(ServerContext *, const StoreRequest *request, Void *)
        override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            dbg("Saving machine");
            context_.machine->store(request->directory());
            dbg("Save finished");
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status Run(ServerContext *, const RunRequest *request,
        RunResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        uint64_t limit = (uint64_t) request->limit();
        // Limit can't be in the past
        if (limit < context_.machine->read_mcycle()) {
            dbg("Requested mcycle limit is already past");
            return Status(StatusCode::INVALID_ARGUMENT, "mcycle in past");
        }
        // If it is not in the past, try running running towards it
        try {
            dbg("Run started");
            context_.machine->run(limit);
            response->set_mcycle(context_.machine->read_mcycle());
            response->set_tohost(context_.machine->read_htif_tohost());
            response->set_iflags_h(context_.machine->read_iflags_H());
            response->set_iflags_y(context_.machine->read_iflags_Y());
            dbg("Run finished");
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status GetProof(ServerContext *, const GetProofRequest *request,
        GetProofResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            dbg("GetProof started");
            uint64_t address = request->address();
            int log2_size = static_cast<int>(request->log2_size());
            merkle_tree::proof_type p{};
            if (!context_.machine->update_merkle_tree()) {
                throw std::runtime_error{"Merkle tree update failed"};
            }
            context_.machine->get_proof(address, log2_size, p);
            set_proto_proof(p, response->mutable_proof());
            dbg("GetProof finished");
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status Step(ServerContext *, const StepRequest *request,
        StepResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);

        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            AccessLog proto_log;
            set_proto_access_log(context_.machine->step(
                get_proto_log_type(request->log_type()), request->one_based()),
                    response->mutable_log());
            dbg("Step executed");
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status GetRootHash(ServerContext *, const Void *,
        GetRootHashResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            context_.machine->update_merkle_tree();
            merkle_tree::hash_type rh;
            context_.machine->get_root_hash(rh);
            set_proto_hash(rh, response->mutable_hash());
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status ReadMemory(ServerContext *, const ReadMemoryRequest *request,
        ReadMemoryResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            uint64_t address = request->address();
            uint64_t length = request->length();
            auto data = cartesi::unique_calloc<unsigned char>(length);
            context_.machine->read_memory(address, data.get(), length);
            response->set_data(data.get(), length);
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status WriteMemory(ServerContext *, const WriteMemoryRequest *request,
        Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            uint64_t address = request->address();
            const auto &data = request->data();
            context_.machine->write_memory(address,
                reinterpret_cast<const unsigned char *>(data.data()),
                data.size());
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status ReplaceFlashDrive(ServerContext *,
        const ReplaceFlashDriveRequest *request, Void *)
        override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            context_.machine->replace_flash_drive(get_proto_flash_drive_config(
                request->config()));
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status GetXAddress(ServerContext*, const GetXAddressRequest *request, GetXAddressResponse *response) override {
        auto index = request->index();
        if (index >= X_REG_COUNT)
            throw std::invalid_argument{"Invalid register index"};
        response->set_address(cartesi::machine::get_x_address(index));
        return Status::OK;
    }

    Status ReadX(ServerContext*, const ReadXRequest *request, ReadXResponse *response) override {
        auto index = request->index();
        if (index >= X_REG_COUNT)
            throw std::invalid_argument{"Invalid register index"};
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_value(context_.machine->read_x(index));
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status WriteX(ServerContext*, const WriteXRequest *request, Void*)  override {
        auto index = request->index();
        if (index >= X_REG_COUNT || index <= 0) // x0 is read-only
            throw std::invalid_argument{"Invalid register index"};
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            context_.machine->write_x(index, request->value());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status GetDhdHAddress(ServerContext *,
        const GetDhdHAddressRequest *request,
        GetDhdHAddressResponse *response) override {
        auto index = request->index();
        if (index >= DHD_H_REG_COUNT)
            throw std::invalid_argument{"Invalid register index"};
        response->set_address(cartesi::machine::get_dhd_h_address(index));
        return Status::OK;
    }

    Status ReadDhdH(ServerContext*, const ReadDhdHRequest *request, ReadDhdHResponse *response) override {
        auto index = request->index();
        if (index >= DHD_H_REG_COUNT)
            throw std::invalid_argument{"Invalid register index"};
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_value(context_.machine->read_dhd_h(index));
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status WriteDhdH(ServerContext*, const WriteDhdHRequest *request, Void*)  override {
        auto index = request->index();
        if (index >= DHD_H_REG_COUNT)
            throw std::invalid_argument{"Invalid register index"};
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            context_.machine->write_dhd_h(index, request->value());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status GetCsrAddress(ServerContext*, const GetCsrAddressRequest *request, GetCsrAddressResponse *response) override {
        if (!CartesiMachine::Csr_IsValid(request->csr()))
            throw std::invalid_argument{"Invalid CSR"};
        auto csr = static_cast<cartesi::machine::csr>(request->csr());
        response->set_address(cartesi::machine::get_csr_address(csr));
        return Status::OK;
    }

    Status ReadCsr(ServerContext*, const ReadCsrRequest *request, ReadCsrResponse *response) override {
        if (!CartesiMachine::Csr_IsValid(request->csr()))
            throw std::invalid_argument{"Invalid CSR"};
        auto csr = static_cast<cartesi::machine::csr>(request->csr());
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_value(context_.machine->read_csr(csr));
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status WriteCsr(ServerContext*, const WriteCsrRequest *request, Void*) override {
        if (!CartesiMachine::Csr_IsValid(request->csr()))
            throw std::invalid_argument{"Invalid CSR"};
        auto csr = static_cast<cartesi::machine::csr>(request->csr());
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            context_.machine->write_csr(csr, request->value());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status Snapshot(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        Break(BreakReason::snapshot);
        return Status::OK;
    }

    Status Rollback(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (context_.forked) {
            Break(BreakReason::rollback);
            return Status::OK;
        } else {
            return Status(StatusCode::FAILED_PRECONDITION, "no snapshot");
        }
    }

    Status Destroy(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        squash_parent(context_);
        // Destruct current machine if there's one
        if (context_.machine)
            context_.machine.reset();
        return Status::OK;
    }

    Status Shutdown(ServerContext *, const Void *, Void *) override {
        // No lock here, Shutdown should always be available
        Break(BreakReason::shutdown);
        return Status::OK;
    }

    Status GetInitialConfig(ServerContext *, const Void*, GetInitialConfigResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            set_proto_machine_config(
                context_.machine->get_initial_config(),
                response->mutable_config());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status GetDefaultConfig(ServerContext *, const Void*, GetDefaultConfigResponse *response) override {
        try {
            set_proto_machine_config(
                machine::get_default_config(),
                response->mutable_config());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status DumpPmas(ServerContext *, const Void*, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            context_.machine->dump_pmas();
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
        return Status::OK;
    }

    Status VerifyAccessLog(ServerContext *,
        const VerifyAccessLogRequest *request, Void *) override {
        try {
            machine::verify_access_log(
                get_proto_access_log(request->log()),
                get_proto_machine_runtime_config(request->runtime()),
                request->one_based());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status VerifyStateTransition(ServerContext *,
        const VerifyStateTransitionRequest *request, Void *) override {
        try {
            machine::verify_state_transition(
                get_proto_hash(request->root_hash_before()),
                get_proto_access_log(request->log()),
                get_proto_hash(request->root_hash_after()),
                get_proto_machine_runtime_config(request->runtime()),
                request->one_based());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
    }

    Status VerifyMerkleTree(ServerContext *, const Void*, VerifyMerkleTreeResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_success(context_.machine->verify_merkle_tree());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
        return Status::OK;
    }

    Status UpdateMerkleTree(ServerContext *, const Void*, UpdateMerkleTreeResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_success(context_.machine->update_merkle_tree());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
        return Status::OK;
    }

    Status VerifyDirtyPageMaps(ServerContext *, const Void*, VerifyDirtyPageMapsResponse *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine)
            return error_no_machine();
        try {
            response->set_success(context_.machine->verify_dirty_page_maps());
            return Status::OK;
        } catch (std::exception& e) {
            return error_exception(e);
        }
        return Status::OK;
    }

public:

    MachineServiceImpl(Context &context):
        server_(nullptr),
        context_(context),
        reason_(BreakReason::error) {
        ;
    }

    ~MachineServiceImpl() {
        // If the service is being deleted, it was either
        // never started, or server->Wait returned because
        // we shut it down.
        // In that case, there is a joinable breaker_ thread,
        // and we join before the thread is destroyed.
        if (breaker_.joinable())
            breaker_.join();
    }

    void set_server(Server *s) {
        server_ = s;
    }

    BreakReason reason(void) const {
        return reason_;
    }

};

static void report_to_manager_server(Context &context) {
    dbg("Reporting address to manager\n");
    std::unique_ptr<cartesi::manager_client> mc = std::make_unique<cartesi::manager_client>();
    mc->register_on_manager(context.session_id, context.address, context.manager_address);
    dbg("Address reported to manager\n");

}

static BreakReason server_loop(Context &context) {
    using grpc::ServerBuilder;
    using grpc::Server;
    ServerBuilder builder;
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::NUM_CQS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MAX_POLLERS, 1);
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    int bound_port;
    builder.AddListeningPort(context.address, grpc::InsecureServerCredentials(), &bound_port);
    MachineServiceImpl service(context);
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (!server)
        return BreakReason::error;

    service.set_server(server.get());

    if (context.auto_port) {
        dbg("Auto port\n");
        context.address = "localhost:";
        context.address += std::to_string(bound_port);
    }
    dbg("Server %d listening to %s", getpid(), context.address.c_str());
    if (context.report_to_manager) {
        report_to_manager_server(context);
    }

    server->Wait();
    return service.reason();
}

static void snapshot(Context &context) {
    pid_t childid = 0;
    squash_parent(context);
    // Now actually fork
    if ((childid = fork()) == 0) {
        // Child simply goes on with next loop iteration.
        context.forked = true;
    } else {
        // Parent waits on child.
        int wstatus;
        waitpid(childid, &wstatus, WUNTRACED);
        if (WIFSTOPPED(wstatus)) {
            // Here the child wants to take our place.
            // Wake child and exit.
            kill(childid, SIGCONT);
            exit(0);
        } else {
            // Here the child exited.
            // We take its place, but are not "forked" anymore.
            // We go on with next loop iteration.
            context.forked = false;
        }
    }
}

static void rollback(Context &context) {
    if (context.forked) {
        // Here, we are a child and forked.
        // We simply exit so parent can take our place.
        exit(0);
    } else {
        dbg("Should not have broken away from server loop.");
    }
}

static void shutdown(Context &context) {
    squash_parent(context);
    // Now exit
    exit(0);
}

// Turn process into a daemon (from APUE book)
static void daemonize(void) {
    pid_t pid;
    // Clear file creation mask
    umask(0);
    // Become session leader to lose controlling TTY
    if ((pid = fork()) < 0) {
        std::cerr << "Can't fork.\n";
        exit(1);
    } else if (pid != 0) {
        exit(0);
    }
    setsid();
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        std::cerr << "Can't ignore SIGHUP.\n";
        exit(1);
    }
    // Stop being a session leader so we will never
    // inadvertently open a file and regain a controlling TTY
    if ((pid = fork()) < 0) {
        std::cerr << "Can't fork.\n";
        exit(1);
    } else if (pid != 0) {
        exit(0);
    }
    // Change to / so we don't keep a lock on the working directory
    if (chdir("/")) { ; }
    // Close stdin/stdout/stderr and reopen as /dev/null to prevent
    // us getting locked when some library function writes
    // to them behind our back
    close(0);
    close(1);
    close(2);
    int fd0 = open("/dev/null", O_RDWR);
    //int fd1 = dup(0); //Use this not to throw away stdout output to /dev/null
    int fd1 = open("/tmp/cartesi_emu.log", O_WRONLY | O_CREAT, 0644); //Use this for debugging purposes
    int fd2 = dup(0);
    if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
        syslog(LOG_ERR, "unexpected file descriptors %d %d %d", fd0, fd1, fd2);
        exit(1);
    }
}

static void check_conflicting_options(const po::variables_map & vm,
    const std::string & opt1, const std::string & opt2) {
    if (vm.count(opt1) && !vm[opt1].defaulted() &&
        vm.count(opt2) && !vm[opt2].defaulted()) {
        std::cout << std::string("Conflicting options '") +
                               opt1 + "' and '" + opt2 + "'.\n";
        exit(1);
    }
}

static std::string get_unix_socket_filename() {
    char tmp[] = "/tmp/cartesi-unix-socket-XXXXXX";
    if(!mkdtemp(tmp)) {
        dbg("Error creating tmp directory");
        exit(1);
    }
    return std::string{tmp} + "/grpc-unix-socket";
}

static void set_context_with_cli_arguments(Context &context, int &argc, 
    char** &argv) {
    //Defining cli options
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "exhibits help message with usage")
        ("socket-type,t", po::value<std::string>(), "socket type to listen to, options are tcp and unix, mutually exclusive with address option")
        ("address,a", po::value<std::string>(), "unix path or ip:port to listen to, mutually exclusive with socket-type option")
        ("session-id,s", po::value<std::string>(), "session id of this instance, triggers reporting address to core-manager server")
        ("manager-address,m", po::value<std::string>(), "unix path or ip:port of the core-manager server, only used when providing a session-id");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
    } catch (boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<boost::program_options::invalid_command_line_syntax>> &ex) {
        std::cout << ex.what() << '\n';
        exit(1);
    } catch (boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<boost::program_options::unknown_option>> &ex) {
        std::cout << ex.what() << '\n';
        exit(1);
    }

    check_conflicting_options(vm, "socket-type", "address");
    po::notify(vm);

    //Help
    if (vm.count("help") || argc==1) {
        std::cout << desc << "\n";
        exit(0);
    }

    //Checking if both socket type and address weren't defined
    if (!vm.count("address") && !vm.count("socket-type")) {
        std::cout << "Must provide address or socket-type, but not both\n";
        exit(1);
    }

    //If manager address or session if were provided, they must both be provided
    if (vm.count("manager-address") || vm.count("session-id")) {
        if (!(vm.count("session-id") && vm.count("manager-address"))) {
            std::cout << "Must provide both session-id and setting manager-address when desired to report session-id to core-manager server\n";
            exit(1);
        }
        //They were, setting manager-address and session-id
        context.manager_address = vm["manager-address"].as<std::string>();
        context.report_to_manager = true;
        context.session_id = vm["session-id"].as<std::string>();
    }

    //Setting address to the given one or an auto-generated
    if (vm.count("address")) {
        //Setting to listen on provided address
        context.address = vm["address"].as<std::string>();
    }
    if (vm.count("socket-type")) {
        auto socket_type = vm["socket-type"].as<std::string>();
        if (socket_type == "unix") {
            //Using unix socket on a dynamically generated filename
            context.address = "unix:";
            context.address += get_unix_socket_filename();
            dbg("%s", context.address.c_str());
        } else if (socket_type == "tcp") {
            //System allocated port
            context.auto_port = true;
            context.address = "localhost:0";
        } else {
            std::cout << "Invalid option, provide either unix or tcp as socket-type\n";
            exit(1);
        }
    }
}

int main(int argc, char** argv) {
    Context context{};

    set_context_with_cli_arguments(context, argc, argv);

    daemonize();
    openlog("cartesi-grpc", LOG_PID, LOG_USER);

    //??D I am nervous about using a multi-threaded GRPC
    //    server here. The combination of fork with threads is
    //    problematic because, after a fork, we can only call
    //    async-signal-safe functions until we call exec (which
    //    we don't).  I try to make sure there is only a single
    //    thread running whenever I call fork by completely
    //    destroying the server before returning from
    //    server_loop. Forking *should* be safe in this
    //    scenario. I would be happiest if the server was
    //    single-threaded.
    while (1) {
        auto break_reason = server_loop(context);
        switch (break_reason) {
            case BreakReason::snapshot:
                dbg("Break due to snapshot.");
                snapshot(context);
                break;
            case BreakReason::rollback:
                dbg("Break due to rollback.");
                rollback(context);
                break;
            case BreakReason::shutdown:
                dbg("Shutting down.");
                shutdown(context);
                break;
            case BreakReason::error:
                dbg("Server creation failed.");
                shutdown(context);
                break;
        }
    }
    return 0;
}

