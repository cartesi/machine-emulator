#include <iostream>
#include <fstream>
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

#include <chrono>
#include <thread>
#include <mutex>
#include <exception>

#include "machine.h"
#include "access-log.h"
#include "keccak-256-hasher.h"
#include "pma.h"

using cartesi::merkle_tree;
using cartesi::access_type;
using cartesi::note_type;
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

#define dbg(...) syslog(LOG_DEBUG, __VA_ARGS__)

struct Context {
    int value;
    std::string address;
    bool forked;
    std::unique_ptr<machine> cartesimachine;
    Context(void): value(0), address(), forked(false), cartesimachine(nullptr) { }
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

    std::mutex barrier_;
    std::thread breaker_;
    grpc::Server *server_;
    Context &context_;
    BreakReason reason_;

    void set_processor_config_from_grpc(machine_config &c, Processor &p) {
        if (p.x1_oneof_case() == Processor::kX1){            
            c.processor.x[0] = p.x1();
        }
        if (p.x2_oneof_case() == Processor::kX2){            
            c.processor.x[1] = p.x2();
        }
        if (p.x3_oneof_case() == Processor::kX3){            
            c.processor.x[2] = p.x3();
        }
        if (p.x4_oneof_case() == Processor::kX4){            
            c.processor.x[3] = p.x4();
        }
        if (p.x5_oneof_case() == Processor::kX5){            
            c.processor.x[4] = p.x5();
        }
        if (p.x6_oneof_case() == Processor::kX6){            
            c.processor.x[5] = p.x6();
        }
        if (p.x7_oneof_case() == Processor::kX7){            
            c.processor.x[6] = p.x7();
        }
        if (p.x8_oneof_case() == Processor::kX8){            
            c.processor.x[7] = p.x8();
        }
        if (p.x9_oneof_case() == Processor::kX9){            
            c.processor.x[8] = p.x9();
        }
        if (p.x10_oneof_case() == Processor::kX10){            
            c.processor.x[9] = p.x10();
        }
        if (p.x11_oneof_case() == Processor::kX11){            
            c.processor.x[10] = p.x11();
        }
        if (p.x12_oneof_case() == Processor::kX12){            
            c.processor.x[11] = p.x12();
        }
        if (p.x13_oneof_case() == Processor::kX13){            
            c.processor.x[12] = p.x13();
        }
        if (p.x14_oneof_case() == Processor::kX14){            
            c.processor.x[13] = p.x14();
        }
        if (p.x15_oneof_case() == Processor::kX15){            
            c.processor.x[14] = p.x15();
        }
        if (p.x16_oneof_case() == Processor::kX16){            
            c.processor.x[15] = p.x16();
        }
        if (p.x17_oneof_case() == Processor::kX17){            
            c.processor.x[16] = p.x17();
        }
        if (p.x18_oneof_case() == Processor::kX18){            
            c.processor.x[17] = p.x18();
        }
        if (p.x19_oneof_case() == Processor::kX19){            
            c.processor.x[18] = p.x19();
        }
        if (p.x20_oneof_case() == Processor::kX20){            
            c.processor.x[19] = p.x20();
        }
        if (p.x21_oneof_case() == Processor::kX21){            
            c.processor.x[20] = p.x21();
        }
        if (p.x22_oneof_case() == Processor::kX22){            
            c.processor.x[21] = p.x22();
        }
        if (p.x23_oneof_case() == Processor::kX23){            
            c.processor.x[22] = p.x23();
        }
        if (p.x24_oneof_case() == Processor::kX24){            
            c.processor.x[23] = p.x24();
        }
        if (p.x25_oneof_case() == Processor::kX25){            
            c.processor.x[24] = p.x25();
        }
        if (p.x26_oneof_case() == Processor::kX26){            
            c.processor.x[25] = p.x26();
        }
        if (p.x27_oneof_case() == Processor::kX27){            
            c.processor.x[26] = p.x27();
        }
        if (p.x28_oneof_case() == Processor::kX28){            
            c.processor.x[27] = p.x28();
        }
        if (p.x29_oneof_case() == Processor::kX29){            
            c.processor.x[28] = p.x29();
        }
        if (p.x30_oneof_case() == Processor::kX30){            
            c.processor.x[29] = p.x30();
        }
        if (p.x31_oneof_case() == Processor::kX31){            
            c.processor.x[30] = p.x31();
        }
        if (p.x32_oneof_case() == Processor::kX32){            
            c.processor.x[31] = p.x32();
        }
        if (p.pc_oneof_case() == Processor::kPc){            
            c.processor.pc = p.pc();
        }
        if (p.mvendorid_oneof_case() == Processor::kMvendorid){            
            c.processor.mvendorid = p.mvendorid();
        }
        if (p.marchid_oneof_case() == Processor::kMarchid){            
            c.processor.marchid = p.marchid();
        }
        if (p.mimpid_oneof_case() == Processor::kMimpid){            
            c.processor.mimpid = p.mimpid();
        }
        if (p.mcycle_oneof_case() == Processor::kMcycle){            
            c.processor.mcycle = p.mcycle();
        }
        if (p.minstret_oneof_case() == Processor::kMinstret){            
            c.processor.minstret = p.minstret();
        }
        if (p.mstatus_oneof_case() == Processor::kMstatus){            
            c.processor.mstatus = p.mstatus();
        }
        if (p.mtvec_oneof_case() == Processor::kMtvec){            
            c.processor.mtvec = p.mtvec();
        }
        if (p.mscratch_oneof_case() == Processor::kMscratch){            
            c.processor.mscratch = p.mscratch();
        }
        if (p.mepc_oneof_case() == Processor::kMepc){            
            c.processor.mepc = p.mepc();
        }
        if (p.mcause_oneof_case() == Processor::kMcause){            
            c.processor.mcause = p.mcause();
        }
        if (p.mtval_oneof_case() == Processor::kMtval){            
            c.processor.mtval = p.mtval();
        }
        if (p.misa_oneof_case() == Processor::kMisa){            
            c.processor.misa = p.misa();
        }
        if (p.mie_oneof_case() == Processor::kMie){            
            c.processor.mie = p.mie();
        }
        if (p.mip_oneof_case() == Processor::kMip){            
            c.processor.mip = p.mip();
        }
        if (p.medeleg_oneof_case() == Processor::kMedeleg){            
            c.processor.medeleg = p.medeleg();
        }
        if (p.mideleg_oneof_case() == Processor::kMideleg){            
            c.processor.mideleg = p.mideleg();
        }
        if (p.mcounteren_oneof_case() == Processor::kMcounteren){            
            c.processor.mcounteren = p.mcounteren();
        }
        if (p.stvec_oneof_case() == Processor::kStvec){            
            c.processor.stvec = p.stvec();
        }
        if (p.sscratch_oneof_case() == Processor::kSscratch){            
            c.processor.sscratch = p.sscratch();
        }
        if (p.sepc_oneof_case() == Processor::kSepc){            
            c.processor.sepc = p.sepc();
        }
        if (p.scause_oneof_case() == Processor::kScause){            
            c.processor.scause = p.scause();
        }
        if (p.stval_oneof_case() == Processor::kStval){            
            c.processor.stval = p.stval();
        }
        if (p.satp_oneof_case() == Processor::kSatp){            
            c.processor.satp = p.satp();
        }
        if (p.scounteren_oneof_case() == Processor::kScounteren){            
            c.processor.scounteren = p.scounteren();
        }
        if (p.ilrsc_oneof_case() == Processor::kIlrsc){            
            c.processor.ilrsc = p.ilrsc();
        }
        if (p.iflags_oneof_case() == Processor::kIflags){            
            c.processor.iflags = p.iflags();
        }
        if (p.backing_oneof_case() == Processor::kBacking){            
            c.processor.backing = p.backing();
        }

    }
    
    void set_config_from_req(machine_config &c, const MachineRequest *mr) {
        //TODO: set other alternative fields that could be desirable to customize
        //also load some arguments hardcode bellow form machine request
        c.rom.bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw";

        //Checking if custom processor values were set on request parameters
        if (mr->processor_oneof_case() == MachineRequest::kProcessor){
            dbg("Processor config set");
            if (mr->has_processor()){
                auto processor = mr->processor();
                set_processor_config_from_grpc(c, processor);
            }
        }
        else if (mr->processor_oneof_case() == MachineRequest::PROCESSOR_ONEOF_NOT_SET){
            dbg("No config set");
        }

        

        //Getting cmdline if any and appending to bootargs
        if (mr->has_rom()){
            auto rom = mr->rom();
            std::string tmp = rom.cmdline();
            if (!tmp.empty()) {
                c.rom.bootargs += " " + tmp;
            }
        }

        //Setting ram configs
        c.ram.length = 64 << 20;
        c.ram.backing = "/home/carlo/crashlabs/core/src/emulator/kernel.bin";

        //Setting flash configs
        flash_config flash{};
        flash.start = cartesi::PMA_RAM_START + c.ram.length;// 1<< 63 originally
        flash.backing = "/home/carlo/crashlabs/core/src/emulator/rootfs.ext2";
        flash.label = "root filesystem";
        flash.length = std::experimental::filesystem::file_size(flash.backing); 
        //flash.length = 46223360; //size manually checked from os terminal for test only, use above solution or other ASAP as this cannot be shipped liked this
        c.flash.push_back(std::move(flash));
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
                dbg(errormsg.c_str());
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
        //Checking if there is already a Cartesi machine created
        if (context_.cartesimachine){
            //There is

            //Debug
            std::cout << "Running\n";

            //Reading desired CPU cycles limit to execute
            uint64_t reqlimit = (uint64_t) request->limit();

            machine *cm = context_.cartesimachine.get();

            //Reading mcycle
            auto curmcycle = cm->read_mcycle();

            //Checking if provided limit is valid
            if (reqlimit){
                if (reqlimit < curmcycle){
                    dbg("Must provide a CPU cycles limit greater than current Cartesi machine CPU cycle to issue running the machine");
                    return Status(StatusCode::INVALID_ARGUMENT, "Must provide a CPU cycles limit greater than current Cartesi machine CPU cycle to issue running the machine");
                }
            }
            else {
                dbg("Must provide a CPU cycles limit to issue running the Cartesi machine");
                return Status(StatusCode::INVALID_ARGUMENT, "Must provide a CPU cycles limit to issue running the Cartesi machine");
            }

            try {
                cm->run(reqlimit);
            }
            catch (std::exception& e){
                std::string errormsg = "An exception happened when running the Cartesi machine: ";
                errormsg += e.what();
                dbg(errormsg.c_str());
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

static BreakReason server_loop(Context &context) {
    using grpc::ServerBuilder;
    using grpc::Server;
    ServerBuilder builder;
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::NUM_CQS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MAX_POLLERS, 1);
    builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    builder.AddListeningPort(context.address, grpc::InsecureServerCredentials());
    MachineServiceImpl service(context);
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (!server)
        return BreakReason::error;
    dbg("Server %d listening to %s", getpid(), context.address.c_str());
    service.set_server(server.get());
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

int main(int argc, char** argv) {
    Context context;
    if (argc != 2) {
        std::cerr << argv[0] << " <ip>:<port>\n";
        std::cerr << argv[0] << " unix:<path>\n";
        exit(0);
    }
    context.address = argv[1];
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

