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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <grpc++/grpc++.h>
#include <grpc++/resource_quota.h>
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

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

#include <boost/program_options.hpp>

namespace po = boost::program_options;

using cartesi::word_access;
using cartesi::merkle_tree;
using cartesi::access_type;
using cartesi::bracket_type;
using cartesi::access_log;
using cartesi::machine_config;
using cartesi::processor_config;
using cartesi::flash_config;
using cartesi::rom_config;
using cartesi::ram_config;
using cartesi::htif_config;
using cartesi::clint_config;
using cartesi::machine_config;
using cartesi::keccak_256_hasher;
using cartesi::bracket_note;
using hash_type = keccak_256_hasher::hash_type;

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

enum class BreakReason {
    error,
    snapshot,
    rollback,
    shutdown
};

// Logic and data behind the server's behavior.
class MachineServiceImpl final: public CartesiMachine::Machine::Service {

    using Void = CartesiMachine::Void;
    using Status = grpc::Status;
    using StatusCode = grpc::StatusCode;
    using ServerContext = grpc::ServerContext;
    using Server = grpc::Server;
    using MachineRequest = CartesiMachine::MachineRequest;
    using StoreRequest = CartesiMachine::StoreRequest;
    using RunRequest = CartesiMachine::RunRequest;
    using RunResponse = CartesiMachine::RunResponse;
    using GetProofRequest = CartesiMachine::GetProofRequest;
    using ReadMemoryRequest = CartesiMachine::ReadMemoryRequest;
    using ReadMemoryResponse = CartesiMachine::ReadMemoryResponse;
    using WriteMemoryRequest = CartesiMachine::WriteMemoryRequest;
    using MachineConfig = CartesiMachine::MachineConfig;
    using ProcessorConfig = CartesiMachine::ProcessorConfig;
    using ROMConfig = CartesiMachine::ROMConfig;
    using RAMConfig = CartesiMachine::RAMConfig;
    using FlashConfig = CartesiMachine::FlashConfig;
    using HTIFConfig = CartesiMachine::HTIFConfig;
    using CLINTConfig = CartesiMachine::CLINTConfig;
    using AccessLog = CartesiMachine::AccessLog;
    using BracketNote = CartesiMachine::BracketNote;
    using Access = CartesiMachine::Access;
    using Proof = CartesiMachine::Proof;
    using Hash = CartesiMachine::Hash;
    using Word = CartesiMachine::Word;

    std::mutex barrier_;
    std::thread breaker_;
    grpc::Server *server_;
    Context &context_;
    BreakReason reason_;

    Status error_no_machine(void) const {
        dbg("No machine");
        return Status(StatusCode::FAILED_PRECONDITION, "No machine");
    }

    Status error_exception(const std::exception& e) const {
        dbg("Caught exception %s", e.what());
        return Status(StatusCode::ABORTED, e.what());
    }

    void set_proto_proof(const merkle_tree::proof_type &p, Proof *proto_p)
        const {
        proto_p->set_address(p.address);
        proto_p->set_log2_size(p.log2_size);

        //Building target hash
        proto_p->mutable_target_hash()->set_content(p.target_hash.data(),
            p.target_hash.size());

        //Building root hash
        proto_p->mutable_root_hash()->set_content(p.root_hash.data(),
            p.root_hash.size());

        //Setting all sibling hashes
        for (int log2_size = merkle_tree::get_log2_tree_size()-1;
            log2_size >= p.log2_size; --log2_size) {
            const auto &h = merkle_tree::get_sibling_hash(p.sibling_hashes,
                log2_size);
            Hash *sh = proto_p->add_sibling_hashes();
            sh->set_content(h.data(), h.size());
        }
    }

    void set_proto_access_log(const access_log &al, AccessLog *proto_al) const {
        //Building word access grpc objects with equivalent content
        for (const auto &wa: al.get_accesses()) {
            Access *a = proto_al->add_accesses();
            //Setting type
            switch (wa.type) {
                case access_type::read:
                    a->set_operation(CartesiMachine::AccessOperation::READ);
                    break;
                case access_type::write:
                    a->set_operation(CartesiMachine::AccessOperation::WRITE);
                    break;
                default:
                    throw std::invalid_argument{"Invalid AccessOperation"};
                    break;
            }

            //Setting read, and written fields
            a->mutable_read()->set_content(&wa.read, sizeof(wa.read));
            a->mutable_written()->set_content(&wa.written, sizeof(wa.written));

            //Building proof object
            set_proto_proof(wa.proof, a->mutable_proof());
        }

        //Building bracket note grpc objects with equivalent content
        for (const auto &bni: al.get_brackets()) {
            BracketNote *bn = proto_al->add_brackets();
            //Setting type
            switch (bni.type) {
                case bracket_type::begin:
                    bn->set_type(CartesiMachine::BracketNote_BracketNoteType_BEGIN);
                    break;
                case bracket_type::end:
                    bn->set_type(CartesiMachine::BracketNote_BracketNoteType_END);
                    break;
                default:
                    throw std::invalid_argument{"Invalid BracketNoteType"};
                    break;
            }
            //Setting where and text
            bn->set_where(bni.where);
            bn->set_text(bni.text);
        }

        //Building notes
        for (const auto &ni: al.get_notes()) {
            proto_al->add_notes()->assign(ni);
        }
    }

    processor_config get_proto_processor_config(const ProcessorConfig &ps)
        const {
        processor_config p;
        if (ps.x1_oneof_case() == ProcessorConfig::kX1) {
            p.x[1] = ps.x1();
        }
        if (ps.x2_oneof_case() == ProcessorConfig::kX2) {
            p.x[2] = ps.x2();
        }
        if (ps.x3_oneof_case() == ProcessorConfig::kX3) {
            p.x[3] = ps.x3();
        }
        if (ps.x4_oneof_case() == ProcessorConfig::kX4) {
            p.x[4] = ps.x4();
        }
        if (ps.x5_oneof_case() == ProcessorConfig::kX5) {
            p.x[5] = ps.x5();
        }
        if (ps.x6_oneof_case() == ProcessorConfig::kX6) {
            p.x[6] = ps.x6();
        }
        if (ps.x7_oneof_case() == ProcessorConfig::kX7) {
            p.x[7] = ps.x7();
        }
        if (ps.x8_oneof_case() == ProcessorConfig::kX8) {
            p.x[8] = ps.x8();
        }
        if (ps.x9_oneof_case() == ProcessorConfig::kX9) {
            p.x[9] = ps.x9();
        }
        if (ps.x10_oneof_case() == ProcessorConfig::kX10) {
            p.x[10] = ps.x10();
        }
        if (ps.x11_oneof_case() == ProcessorConfig::kX11) {
            p.x[11] = ps.x11();
        }
        if (ps.x12_oneof_case() == ProcessorConfig::kX12) {
            p.x[12] = ps.x12();
        }
        if (ps.x13_oneof_case() == ProcessorConfig::kX13) {
            p.x[13] = ps.x13();
        }
        if (ps.x14_oneof_case() == ProcessorConfig::kX14) {
            p.x[14] = ps.x14();
        }
        if (ps.x15_oneof_case() == ProcessorConfig::kX15) {
            p.x[15] = ps.x15();
        }
        if (ps.x16_oneof_case() == ProcessorConfig::kX16) {
            p.x[16] = ps.x16();
        }
        if (ps.x17_oneof_case() == ProcessorConfig::kX17) {
            p.x[17] = ps.x17();
        }
        if (ps.x18_oneof_case() == ProcessorConfig::kX18) {
            p.x[18] = ps.x18();
        }
        if (ps.x19_oneof_case() == ProcessorConfig::kX19) {
            p.x[19] = ps.x19();
        }
        if (ps.x20_oneof_case() == ProcessorConfig::kX20) {
            p.x[20] = ps.x20();
        }
        if (ps.x21_oneof_case() == ProcessorConfig::kX21) {
            p.x[21] = ps.x21();
        }
        if (ps.x22_oneof_case() == ProcessorConfig::kX22) {
            p.x[22] = ps.x22();
        }
        if (ps.x23_oneof_case() == ProcessorConfig::kX23) {
            p.x[23] = ps.x23();
        }
        if (ps.x24_oneof_case() == ProcessorConfig::kX24) {
            p.x[24] = ps.x24();
        }
        if (ps.x25_oneof_case() == ProcessorConfig::kX25) {
            p.x[25] = ps.x25();
        }
        if (ps.x26_oneof_case() == ProcessorConfig::kX26) {
            p.x[26] = ps.x26();
        }
        if (ps.x27_oneof_case() == ProcessorConfig::kX27) {
            p.x[27] = ps.x27();
        }
        if (ps.x28_oneof_case() == ProcessorConfig::kX28) {
            p.x[28] = ps.x28();
        }
        if (ps.x29_oneof_case() == ProcessorConfig::kX29) {
            p.x[29] = ps.x29();
        }
        if (ps.x30_oneof_case() == ProcessorConfig::kX30) {
            p.x[30] = ps.x30();
        }
        if (ps.x31_oneof_case() == ProcessorConfig::kX31) {
            p.x[31] = ps.x31();
        }
        if (ps.pc_oneof_case() == ProcessorConfig::kPc) {
            p.pc = ps.pc();
        }
        if (ps.mvendorid_oneof_case() == ProcessorConfig::kMvendorid) {
            p.mvendorid = ps.mvendorid();
        }
        if (ps.marchid_oneof_case() == ProcessorConfig::kMarchid) {
            p.marchid = ps.marchid();
        }
        if (ps.mimpid_oneof_case() == ProcessorConfig::kMimpid) {
            p.mimpid = ps.mimpid();
        }
        if (ps.mcycle_oneof_case() == ProcessorConfig::kMcycle) {
            p.mcycle = ps.mcycle();
        }
        if (ps.minstret_oneof_case() == ProcessorConfig::kMinstret) {
            p.minstret = ps.minstret();
        }
        if (ps.mstatus_oneof_case() == ProcessorConfig::kMstatus) {
            p.mstatus = ps.mstatus();
        }
        if (ps.mtvec_oneof_case() == ProcessorConfig::kMtvec) {
            p.mtvec = ps.mtvec();
        }
        if (ps.mscratch_oneof_case() == ProcessorConfig::kMscratch) {
            p.mscratch = ps.mscratch();
        }
        if (ps.mepc_oneof_case() == ProcessorConfig::kMepc) {
            p.mepc = ps.mepc();
        }
        if (ps.mcause_oneof_case() == ProcessorConfig::kMcause) {
            p.mcause = ps.mcause();
        }
        if (ps.mtval_oneof_case() == ProcessorConfig::kMtval) {
            p.mtval = ps.mtval();
        }
        if (ps.misa_oneof_case() == ProcessorConfig::kMisa) {
            p.misa = ps.misa();
        }
        if (ps.mie_oneof_case() == ProcessorConfig::kMie) {
            p.mie = ps.mie();
        }
        if (ps.mip_oneof_case() == ProcessorConfig::kMip) {
            p.mip = ps.mip();
        }
        if (ps.medeleg_oneof_case() == ProcessorConfig::kMedeleg) {
            p.medeleg = ps.medeleg();
        }
        if (ps.mideleg_oneof_case() == ProcessorConfig::kMideleg) {
            p.mideleg = ps.mideleg();
        }
        if (ps.mcounteren_oneof_case() == ProcessorConfig::kMcounteren) {
            p.mcounteren = ps.mcounteren();
        }
        if (ps.stvec_oneof_case() == ProcessorConfig::kStvec) {
            p.stvec = ps.stvec();
        }
        if (ps.sscratch_oneof_case() == ProcessorConfig::kSscratch) {
            p.sscratch = ps.sscratch();
        }
        if (ps.sepc_oneof_case() == ProcessorConfig::kSepc) {
            p.sepc = ps.sepc();
        }
        if (ps.scause_oneof_case() == ProcessorConfig::kScause) {
            p.scause = ps.scause();
        }
        if (ps.stval_oneof_case() == ProcessorConfig::kStval) {
            p.stval = ps.stval();
        }
        if (ps.satp_oneof_case() == ProcessorConfig::kSatp) {
            p.satp = ps.satp();
        }
        if (ps.scounteren_oneof_case() == ProcessorConfig::kScounteren) {
            p.scounteren = ps.scounteren();
        }
        if (ps.ilrsc_oneof_case() == ProcessorConfig::kIlrsc) {
            p.ilrsc = ps.ilrsc();
        }
        if (ps.iflags_oneof_case() == ProcessorConfig::kIflags) {
            p.iflags = ps.iflags();
        }
        return p;
    }

    machine_config get_proto_machine_config(const MachineConfig &ms) {
        machine_config c;

        //Checking if custom processor values were set on request parameters
        if (ms.has_processor()) {
            c.processor = get_proto_processor_config(ms.processor());
        }

        //Setting ROM configs
        if (ms.has_rom()) {
            c.rom.bootargs = ms.rom().bootargs();
            c.rom.image_filename = ms.rom().image_filename();
            dbg("Bootargs: %s", c.rom.bootargs.c_str());
            dbg("ROM image filename: %s", c.rom.image_filename.c_str());
        }

        //Setting ram configs
        if (ms.has_ram()) {
            c.ram.length = ms.ram().length();
            c.ram.image_filename = ms.ram().image_filename();
        }

        //Setting flash configs
        for (const auto &fs: ms.flash()) {
            flash_config f{};
            f.start = fs.start();
            f.image_filename = fs.image_filename();
            f.length = fs.length();
            f.shared = fs.shared();
            c.flash.emplace_back(std::move(f));
        }

        //Setting CLINT configs
        if (ms.has_clint()) {
            const auto &clint = ms.clint();
            if (clint.mtimecmp_oneof_case() == CLINTConfig::kMtimecmp) {
                c.clint.mtimecmp = clint.mtimecmp();
            }
        }

        //Setting HTIF configs
        if (ms.has_htif()) {
            const auto &htif = ms.htif();
            if (htif.fromhost() == HTIFConfig::kFromhost) {
                c.htif.fromhost = htif.fromhost();
            }
            if (htif.tohost() == HTIFConfig::kTohost) {
                c.htif.tohost = htif.tohost();
            }
            // zero default when missing is ok
            c.htif.console_getchar = htif.console_getchar();
            // zero default when missing is ok
            c.htif.yield_progress = htif.yield_progress();
            // zero default when missing is ok
            c.htif.yield_rollup = htif.yield_rollup();
        }

        return c;
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
                "Machine already exists");
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
                        "Invalid machine specification");
            }
        } catch (std::exception& e) {
            return error_exception(e);
        }
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
            return Status(StatusCode::INVALID_ARGUMENT,
                "Requested mcycle limit is already past");
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
        Proof *proto_p) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            dbg("GetProof started");
            uint64_t address = request->address();
            int log2_size = static_cast<int>(request->log2_size());
            merkle_tree::proof_type p{};
            if (context_.machine->update_merkle_tree() &&
                context_.machine->get_proof(address, log2_size, p)) {
                set_proto_proof(p, proto_p);
            } else {
                throw std::runtime_error{"GetProof failed"};
            }
            dbg("GetProof finished");
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status Step(ServerContext *, const Void *, AccessLog *proto_al) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            access_log al{};
            context_.machine->step(al);
            set_proto_access_log(al, proto_al);
            dbg("Step executed");
            return Status::OK;
        } catch (std::exception &e) {
            return error_exception(e);
        }
    }

    Status GetRootHash(ServerContext *, const Void *, Hash *response) override {
        std::lock_guard<std::mutex> lock(barrier_);
        if (!context_.machine) {
            return error_no_machine();
        }
        try {
            context_.machine->update_merkle_tree();
            merkle_tree::hash_type rh;
            context_.machine->get_merkle_tree().get_root_hash(rh);
            response->set_content(rh.data(), rh.size());
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
            auto data = cartesi::unique_calloc<unsigned char>(1, length);
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
            return Status(StatusCode::FAILED_PRECONDITION, "No snapshot");
        }
    }

    Status Shutdown(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        Break(BreakReason::shutdown);
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
    // If we are a forked child, we have a parent waiting.
    // We want to take its place.
    // Wake parent up by signaling ourselves to stop.
    // Parent will wake us up and then exit.
    if (context.forked) {
        raise(SIGSTOP);
        // When we wake up, we took the parent's place, so we are not "forked" anymore
        context.forked = false;
    }
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
    // If we are a forked child, we have a parent waiting.
    // We want to take its place before exiting.
    // Wake parent up by signaling ourselves to stop.
    // Parent will wake us back up and then exit.
    if (context.forked) {
        raise(SIGSTOP);
        // When we wake up, we took the parent's place, so we are not "forked" anymore
        context.forked = false;
    }
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

