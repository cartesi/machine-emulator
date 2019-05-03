#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <chrono>
#include <experimental/filesystem>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/resource_quota.h>

#include "core.grpc.pb.h"
#include "core.pb.h"
#include "manager-client.h"

#include <chrono>
#include <thread>
#include <mutex>
#include <exception>

#include "machine.h"
#include "access-log.h"
#include "keccak-256-hasher.h"
#include "pma.h"

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
using cartesi::machine;
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
    std::unique_ptr<machine> cartesimachine;
    Context(void): value(0), address(), manager_address(), session_id(), auto_port(false), report_to_manager(false), forked(false), cartesimachine(nullptr) { }
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
class MachineServiceImpl final: public CartesiCore::Machine::Service {

    using Void = CartesiCore::Void;
    using Status = grpc::Status;
    using StatusCode = grpc::StatusCode;
    using ServerContext = grpc::ServerContext;
    using Server = grpc::Server;
    using MachineRequest = CartesiCore::MachineRequest;
    using RunRequest = CartesiCore::RunRequest;
    using RunResponse = CartesiCore::RunResponse;
    using Processor = CartesiCore::Processor;
    using ProcessorState = CartesiCore::ProcessorState;
    using ROM = CartesiCore::ROM;
    using RAM = CartesiCore::RAM;
    using Drive = CartesiCore::Drive;
    using HTIF = CartesiCore::HTIF;
    using HTIFState = CartesiCore::HTIFState;
    using CLINT = CartesiCore::CLINT;
    using CLINTState = CartesiCore::CLINTState;
    using AccessLog = CartesiCore::AccessLog;
    using BracketNote = CartesiCore::BracketNote;
    using Access = CartesiCore::Access;
    using Proof = CartesiCore::Proof;
    using Hash = CartesiCore::Hash;
    using Word = CartesiCore::Word;

    std::mutex barrier_;
    std::thread breaker_;
    grpc::Server *server_;
    Context &context_;
    BreakReason reason_;

    //This method is not being used, by might be useful for debugging
    std::string convert_hash_type_to_hex_string(const hash_type &h){
        std::ostringstream ss;
        ss << "0x" << std::setfill('0');
        for (unsigned int i=0; i < h.size(); ++i) {
            ss << std::setw(2) << std::hex << static_cast<int>(h[i]);
        }
        //std::cout << ss.str() << "\n"; //Debug
        return ss.str();
    }

    void set_resp_from_access_log(AccessLog *response, access_log &al) {
        //Building word access grpc objects with equivalent content
        auto accesses = al.get_accesses();
        for (std::vector<word_access>::iterator wai = accesses.begin(); wai != accesses.end(); ++wai){
            Access *a = response->add_accesses();

            //Setting type
            switch (wai->type) {
                case cartesi::access_type::read :
                    a->set_operation(CartesiCore::AccessOperation::READ);
                    break;
                case cartesi::access_type::write :
                    a->set_operation(CartesiCore::AccessOperation::WRITE);
                    break;
            }

            //Setting read, and written fields
            Word *r = a->mutable_read();
            Word *w = a->mutable_written();
            r->set_content(reinterpret_cast<char *>(&wai->read), sizeof(wai->read));
            w->set_content(reinterpret_cast<char *>(&wai->written), sizeof(wai->written));

            //Building proof object
            Proof *p = a->mutable_proof();
            p->set_address(wai->proof.address);
            p->set_log2_size(wai->proof.log2_size);

            //Building target hash
            Hash *th = p->mutable_target_hash();
            th->set_content(wai->proof.target_hash.data(), wai->proof.target_hash.size());

            //Building root hash
            Hash *rh = p->mutable_root_hash();
            rh->set_content(wai->proof.root_hash.data(), wai->proof.root_hash.size());

            //Setting all sibling hashes
            for (unsigned int i=0; i < wai->proof.sibling_hashes.size(); ++i) {
                Hash *sh = p->add_sibling_hashes();
                sh->set_content(wai->proof.sibling_hashes[i].data(), wai->proof.sibling_hashes[i].size());    
            }
        }

        //Building bracket note grpc objects with equivalent content
        auto brackets = al.get_brackets();
        for (std::vector<bracket_note>::iterator bni = brackets.begin(); bni != brackets.end(); ++bni){
            BracketNote *bn = response->add_brackets();

            //Setting type
            switch (bni->type) {
                case cartesi::bracket_type::begin :
                    bn->set_type(CartesiCore::BracketNote_BracketNoteType_BEGIN);
                    break;
                case cartesi::bracket_type::end :
                    bn->set_type(CartesiCore::BracketNote_BracketNoteType_END);
                    break;
                case cartesi::bracket_type::invalid :
                    bn->set_type(CartesiCore::BracketNote_BracketNoteType_INVALID);
                    break;
            }

            //Setting where and text
            bn->set_where(bni->where);
            bn->set_text(bni->text);
        }

        //Building notes
        auto notes = al.get_notes();
        for (std::vector<std::string>::iterator ni = notes.begin(); ni != notes.end(); ++ni){
            std::string *n = response->add_notes();
            n->assign(*ni);
        }
    }

    void set_processor_config_from_grpc(machine_config &c, ProcessorState &ps) {
		if (ps.x1_oneof_case() == ProcessorState::kX1){
            c.processor.x[1] = ps.x1();
        }
        if (ps.x2_oneof_case() == ProcessorState::kX2){
            c.processor.x[2] = ps.x2();
        }
        if (ps.x3_oneof_case() == ProcessorState::kX3){
            c.processor.x[3] = ps.x3();
        }
        if (ps.x4_oneof_case() == ProcessorState::kX4){
            c.processor.x[4] = ps.x4();
        }
        if (ps.x5_oneof_case() == ProcessorState::kX5){
            c.processor.x[5] = ps.x5();
        }
        if (ps.x6_oneof_case() == ProcessorState::kX6){
            c.processor.x[6] = ps.x6();
        }
        if (ps.x7_oneof_case() == ProcessorState::kX7){
            c.processor.x[7] = ps.x7();
        }
        if (ps.x8_oneof_case() == ProcessorState::kX8){
            c.processor.x[8] = ps.x8();
        }
        if (ps.x9_oneof_case() == ProcessorState::kX9){
            c.processor.x[9] = ps.x9();
        }
        if (ps.x10_oneof_case() == ProcessorState::kX10){
            c.processor.x[10] = ps.x10();
        }
        if (ps.x11_oneof_case() == ProcessorState::kX11){
            c.processor.x[11] = ps.x11();
        }
        if (ps.x12_oneof_case() == ProcessorState::kX12){
            c.processor.x[12] = ps.x12();
        }
        if (ps.x13_oneof_case() == ProcessorState::kX13){
            c.processor.x[13] = ps.x13();
        }
        if (ps.x14_oneof_case() == ProcessorState::kX14){
            c.processor.x[14] = ps.x14();
        }
        if (ps.x15_oneof_case() == ProcessorState::kX15){
            c.processor.x[15] = ps.x15();
        }
        if (ps.x16_oneof_case() == ProcessorState::kX16){
            c.processor.x[16] = ps.x16();
        }
        if (ps.x17_oneof_case() == ProcessorState::kX17){
            c.processor.x[17] = ps.x17();
        }
        if (ps.x18_oneof_case() == ProcessorState::kX18){
            c.processor.x[18] = ps.x18();
        }
        if (ps.x19_oneof_case() == ProcessorState::kX19){
            c.processor.x[19] = ps.x19();
        }
        if (ps.x20_oneof_case() == ProcessorState::kX20){
            c.processor.x[20] = ps.x20();
        }
        if (ps.x21_oneof_case() == ProcessorState::kX21){
            c.processor.x[21] = ps.x21();
        }
        if (ps.x22_oneof_case() == ProcessorState::kX22){
            c.processor.x[22] = ps.x22();
        }
        if (ps.x23_oneof_case() == ProcessorState::kX23){
            c.processor.x[23] = ps.x23();
        }
        if (ps.x24_oneof_case() == ProcessorState::kX24){
            c.processor.x[24] = ps.x24();
        }
        if (ps.x25_oneof_case() == ProcessorState::kX25){
            c.processor.x[25] = ps.x25();
        }
        if (ps.x26_oneof_case() == ProcessorState::kX26){
            c.processor.x[26] = ps.x26();
        }
        if (ps.x27_oneof_case() == ProcessorState::kX27){
            c.processor.x[27] = ps.x27();
        }
        if (ps.x28_oneof_case() == ProcessorState::kX28){
            c.processor.x[28] = ps.x28();
        }
        if (ps.x29_oneof_case() == ProcessorState::kX29){
            c.processor.x[29] = ps.x29();
        }
        if (ps.x30_oneof_case() == ProcessorState::kX30){
            c.processor.x[30] = ps.x30();
        }
        if (ps.x31_oneof_case() == ProcessorState::kX31){
            c.processor.x[31] = ps.x31();
        }
        if (ps.pc_oneof_case() == ProcessorState::kPc){
            c.processor.pc = ps.pc();
        }
        if (ps.mvendorid_oneof_case() == ProcessorState::kMvendorid){
            c.processor.mvendorid = ps.mvendorid();
        }
        if (ps.marchid_oneof_case() == ProcessorState::kMarchid){
            c.processor.marchid = ps.marchid();
        }
        if (ps.mimpid_oneof_case() == ProcessorState::kMimpid){
            c.processor.mimpid = ps.mimpid();
        }
        if (ps.mcycle_oneof_case() == ProcessorState::kMcycle){
            c.processor.mcycle = ps.mcycle();
        }
        if (ps.minstret_oneof_case() == ProcessorState::kMinstret){
            c.processor.minstret = ps.minstret();
        }
        if (ps.mstatus_oneof_case() == ProcessorState::kMstatus){
            c.processor.mstatus = ps.mstatus();
        }
        if (ps.mtvec_oneof_case() == ProcessorState::kMtvec){
            c.processor.mtvec = ps.mtvec();
        }
        if (ps.mscratch_oneof_case() == ProcessorState::kMscratch){
            c.processor.mscratch = ps.mscratch();
        }
        if (ps.mepc_oneof_case() == ProcessorState::kMepc){
            c.processor.mepc = ps.mepc();
        }
        if (ps.mcause_oneof_case() == ProcessorState::kMcause){
            c.processor.mcause = ps.mcause();
        }
        if (ps.mtval_oneof_case() == ProcessorState::kMtval){
            c.processor.mtval = ps.mtval();
        }
        if (ps.misa_oneof_case() == ProcessorState::kMisa){
            c.processor.misa = ps.misa();
        }
        if (ps.mie_oneof_case() == ProcessorState::kMie){
            c.processor.mie = ps.mie();
        }
        if (ps.mip_oneof_case() == ProcessorState::kMip){
            c.processor.mip = ps.mip();
        }
        if (ps.medeleg_oneof_case() == ProcessorState::kMedeleg){
            c.processor.medeleg = ps.medeleg();
        }
        if (ps.mideleg_oneof_case() == ProcessorState::kMideleg){
            c.processor.mideleg = ps.mideleg();
        }
        if (ps.mcounteren_oneof_case() == ProcessorState::kMcounteren){
            c.processor.mcounteren = ps.mcounteren();
        }
        if (ps.stvec_oneof_case() == ProcessorState::kStvec){
            c.processor.stvec = ps.stvec();
        }
        if (ps.sscratch_oneof_case() == ProcessorState::kSscratch){
            c.processor.sscratch = ps.sscratch();
        }
        if (ps.sepc_oneof_case() == ProcessorState::kSepc){
            c.processor.sepc = ps.sepc();
        }
        if (ps.scause_oneof_case() == ProcessorState::kScause){
            c.processor.scause = ps.scause();
        }
        if (ps.stval_oneof_case() == ProcessorState::kStval){
            c.processor.stval = ps.stval();
        }
        if (ps.satp_oneof_case() == ProcessorState::kSatp){
            c.processor.satp = ps.satp();
        }
        if (ps.scounteren_oneof_case() == ProcessorState::kScounteren){
            c.processor.scounteren = ps.scounteren();
        }
        if (ps.ilrsc_oneof_case() == ProcessorState::kIlrsc){
            c.processor.ilrsc = ps.ilrsc();
        }
        if (ps.iflags_oneof_case() == ProcessorState::kIflags){
            c.processor.iflags = ps.iflags();
        }
    }

    void set_config_from_req(machine_config &c, const MachineRequest *mr) {


        //Checking if custom processor values were set on request parameters
        if (mr->has_processor()){
            auto p = mr->processor();

            switch (p.processor_oneof_case()) {
                case Processor::kState: {
                        auto ps = p.state();
                        set_processor_config_from_grpc(c, ps);
                    }
                    break;
                case Processor::kBacking:
                    c.processor.backing = p.backing();
                    break;
                case Processor::PROCESSOR_ONEOF_NOT_SET:
                    dbg("No processor config set");
                    break;
            }
        }

        //Setting ROM configs
        if (mr->has_rom()){
            auto rom = mr->rom();

            switch (rom.rom_oneof_case()) {
                case ROM::kBootargs: {
                    c.rom.bootargs = rom.bootargs();
                    break;
                }
                case ROM::kBacking: {
                    c.rom.backing = rom.backing();
                    break;
                }
                case ROM::ROM_ONEOF_NOT_SET: {
                    dbg("No rom config set");
                    break;
                }
            }
        }

        //Setting ram configs
        if (mr->has_ram()){
            c.ram.length = mr->ram().length();
            c.ram.backing = mr->ram().backing();
        }

        //Setting flash configs
        for (const Drive &drive: mr->flash()){
            flash_config flash{};
            flash.start = drive.start();
            flash.backing = drive.backing();
            flash.label = drive.label();
            flash.length = drive.length();
            c.flash.push_back(std::move(flash));
        }

        //Setting CLINT configs
        if (mr->has_clint()){
            auto clint = mr->clint();

            switch (clint.clint_oneof_case()) {
                case CLINT::kState: {
                    c.clint.mtimecmp = clint.state().mtimecmp();
                    break;
                }
                case CLINT::kBacking: {
                    c.clint.backing = clint.backing();
                    break;
                }
                case CLINT::CLINT_ONEOF_NOT_SET: {
                    dbg("No clint config set");
                    break;
                }
            }
        }
        //Setting HTIF configs
        if (mr->has_htif()){
            auto htif = mr->htif();

            switch (htif.htif_oneof_case()) {
                case HTIF::kState: {
                    c.htif.fromhost = htif.state().fromhost();
                    c.htif.tohost = htif.state().tohost();
                    break;
                }
                case HTIF::kBacking: {
                    c.htif.backing = htif.backing();
                    break;
                }
                case HTIF::HTIF_ONEOF_NOT_SET: {
                    dbg("No htif config set");
                    break;
                }
            }
        }
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

    Status Machine(ServerContext *, const MachineRequest * request, Void *) override {
        //Acquiring lock
        std::lock_guard<std::mutex> lock(barrier_);

        //Checking if there is already a Cartesi machine created
        if (!context_.cartesimachine){
            //There isn't, creating a new one

            //Creating a standard machine config
            machine_config mconfig{};
            set_config_from_req(mconfig, request);

            //Creating machine
            dbg("Creating Cartesi machine");
            try {
                context_.cartesimachine = std::make_unique<machine>(mconfig);
            }
            catch (std::exception& e) {
                std::string errormsg = "An exception happened when instantiating a Cartesi machine: ";
                errormsg += e.what();
                dbg("%s", errormsg.c_str());
                return Status(StatusCode::UNKNOWN, errormsg);
            }
            dbg("Cartesi machine created");
            return Status::OK;
        }
        else {
            //There is, notifying and doing nothing
            dbg("There is already an active Cartesi machine");
            return Status(StatusCode::FAILED_PRECONDITION, "There is already a Cartesi machine");
        }
    }

    Status Run(ServerContext *, const RunRequest *request, RunResponse *response) override {
        //Acquiring lock
        std::lock_guard<std::mutex> lock(barrier_);

        //Checking if there is already a Cartesi machine created
        if (context_.cartesimachine){
            //There is

            //Debug
            dbg("Running");

            //Reading desired CPU cycles limit to execute
            uint64_t reqlimit = (uint64_t) request->limit();

            machine *cm = context_.cartesimachine.get();

            //Reading mcycle
            auto curmcycle = cm->read_mcycle();

            //Checking if provided limit is valid
            if (reqlimit < curmcycle){
                dbg("Must provide a CPU cycles limit greater than current Cartesi machine CPU cycle to issue running the machine");
                return Status(StatusCode::INVALID_ARGUMENT, "Must provide a CPU cycles limit greater than current Cartesi machine CPU cycle to issue running the machine");
            }

            try {
                cm->run(reqlimit);
            }
            catch (std::exception& e){
                std::string errormsg = "An exception happened when running the Cartesi machine: ";
                errormsg += e.what();
                dbg("%s", errormsg.c_str());
                return Status(StatusCode::UNKNOWN, errormsg);
            }

            //Setting response
            response->set_mcycle(cm->read_mcycle());
            response->set_tohost(cm->read_htif_tohost());

            dbg("Run executed");
            return Status::OK;
        }
        else {
            //There isn't, notifying and doing nothing
            dbg("There is no active Cartesi machine, create one before executing run");
            return Status(StatusCode::FAILED_PRECONDITION, "There is no active Cartesi machine, create one before executing run");
        }
    }

    Status Step(ServerContext *, const Void *, AccessLog *response) override {
        //Acquiring lock
        std::lock_guard<std::mutex> lock(barrier_);

        //Checking if there is already a Cartesi machine created
        if (context_.cartesimachine){
            //There is
            dbg("Stepping");

            //Recovering cartesi machine instance reference
            machine *cm = context_.cartesimachine.get();

            //Creating an access log instance to hold step execution information and stepping
            access_log al{};
            cm->step(al);

            //Setting response
            set_resp_from_access_log(response, al);

            dbg("Step executed");
            return Status::OK;
        }
        else {
            //There isn't, notifying and doing nothing
            dbg("There is no active Cartesi machine, create one before executing step");
            return Status(StatusCode::FAILED_PRECONDITION, "There is no active Cartesi machine, create one before executing step");
        }
    }

    Status GetRootHash(ServerContext *, const Void *, Hash *response) override {
        //Acquiring lock
        std::lock_guard<std::mutex> lock(barrier_);

        //Checking if there is already a Cartesi machine created
        if (context_.cartesimachine){
            //There is
            dbg("Getting root hash");

            //Recovering cartesi machine instance reference
            machine *cm = context_.cartesimachine.get();

            //Updating merkle tree
            cm->update_merkle_tree();

            //Creating a merkle tree hash to hold the root hash and populating it
            merkle_tree::hash_type rh;
            cm->get_merkle_tree().get_root_hash(rh);

            //Setting response
            response->set_content(rh.data(), rh.size());
            dbg("Getting root hash executed");

            return Status::OK;
        }
        else {
            //There isn't, notifying and doing nothing
            dbg("There is no active Cartesi machine, create one before executing get root hash");
            return Status(StatusCode::FAILED_PRECONDITION, "There is no active Cartesi machine, create one before executing get root hash");
        }
    }

    Status Inc(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        ++context_.value;
        dbg("%d", context_.value);
        return Status::OK;
    }

    Status Print(ServerContext *, const Void *, Void *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        dbg("%d", context_.value);
        return Status::OK;
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

void report_to_manager_server(Context &context){
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

    if (context.auto_port){
        dbg("Auto port\n");
        context.address = "localhost:";
        context.address += std::to_string(bound_port);
    }
    dbg("Server %d listening to %s", getpid(), context.address.c_str());
    if (context.report_to_manager){
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

void conflicting_options(const po::variables_map & vm,
                         const std::string & opt1, const std::string & opt2) {
    if (vm.count(opt1) && !vm[opt1].defaulted() &&
        vm.count(opt2) && !vm[opt2].defaulted())
    {
        std::cout << std::string("Conflicting options '") +
                               opt1 + "' and '" + opt2 + "'.\n";
        exit(1);
    }
}

std::string get_unix_socket_filename() {
    char tmp[] = "/tmp/cartesi-unix-socket-XXXXXX";
    if(!mkdtemp(tmp)) {
        dbg("Error creating tmp directory");
        exit(1);
    }
    return std::string{tmp} + "/grpc-unix-socket";
}

void set_context_with_cli_arguments(Context &context, int &argc, char** &argv) {
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
    } catch (boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<boost::program_options::invalid_command_line_syntax>> &ex){
        std::cout << ex.what() << '\n';
        exit(1);
    } catch (boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<boost::program_options::unknown_option>> &ex){
        std::cout << ex.what() << '\n';
        exit(1);
    }

    conflicting_options(vm, "socket-type", "address");
    po::notify(vm);

    //Help
    if (vm.count("help") || argc==1) {
        std::cout << desc << "\n";
        exit(0);
    }

    //Checking if both socket type and address weren't defined
    if (!vm.count("address") && !vm.count("socket-type")){
        std::cout << "Must provide address or socket-type, but not both\n";
        exit(1);
    }
  
    //If manager address or session if were provided, they must both be provided
    if (vm.count("manager-address") || vm.count("session-id")){
        if (!(vm.count("session-id") && vm.count("manager-address"))){
            std::cout << "Must provide both session-id and setting manager-address when desired to report session-id to core-manager server\n";
            exit(1);
        }
        //They were, setting manager-address and session-id
        context.manager_address = vm["manager-address"].as<std::string>();
        context.report_to_manager = true;
        context.session_id = vm["session-id"].as<std::string>();
    }

    //Setting address to the given one or an auto-generated
    if (vm.count("address")){
        //Setting to listen on provided address
        context.address = vm["address"].as<std::string>();
    }
    if (vm.count("socket-type")){
        auto socket_type = vm["socket-type"].as<std::string>();
        if (socket_type == "unix"){
            //Using unix socket on a dynamically generated filename
            context.address = "unix:";
            context.address += get_unix_socket_filename();
            dbg("%s", context.address.c_str());
        }
        else if (socket_type == "tcp") {
            //System allocated port
            context.auto_port = true;
            context.address = "localhost:0";
        }
        else {
            std::cout << "Invalid option, provide either unix or tcp as socket-type\n";
            exit(1);
        }        
    }
}

int main(int argc, char** argv) {
    Context context;
   
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

