#include <iostream>
#include <memory>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>

#include <grpcpp/grpcpp.h>

#include "core.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using CartesiCore::Void;
using CartesiCore::Machine;

#include <chrono>
#include <thread>
#include <mutex>

#define dbg(...) syslog(LOG_DEBUG, __VA_ARGS__)

struct Context {
    int value;
    int port;
    bool forked;
    Context(void): value(0), port(0), forked(false) { }
};

// Move this to static member function of MachingServiceImpl?
static void shutdown_server(Server *s) {
    if (s) s->Shutdown();
}

enum class BreakReason {
    none,
    snapshot,
    rollback,
    shutdown
};

// Logic and data behind the server's behavior.
class MachineServiceImpl final: public Machine::Service {
    std::mutex barrier_;
    Server *server_;
    Context &context_;
    BreakReason reason_;

    void Break(BreakReason reason) {
        reason_ = reason;
        std::thread t(shutdown_server, server_);
        t.detach();
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
        reason_(BreakReason::none) {
        ;
    }

    void set_server(Server *s) {
        server_ = s;
    }

    BreakReason reason(void) const {
        return reason_;
    }

};

static BreakReason server_loop(Context &context) {
    std::string address("0.0.0.0:");
    address += std::to_string(context.port);
    ServerBuilder builder;
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::NUM_CQS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MAX_POLLERS, 1);
    builder.AddListeningPort(address, grpc::InsecureServerCredentials(), &context.port);
    MachineServiceImpl service(context);
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    dbg("Listening on port %d", context.port);
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

static void evoke(void) {
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Can't fork.\n";
        exit(1);
    }
    if (pid) exit(0);
    // Child continues
    if (setsid() < 0) {
        std::cerr << "Can't become session leader.\n";
        exit(1);
    }
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        std::cerr << "Can't fork.\n";
        exit(1);
    }
    if (pid) exit(0);
    // Child continues;
    auto ign = chdir("/"); (void) ign;
    close(0);
    close(1);
    close(2);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);
    umask(0);
}

int main(int argc, char** argv) {
    Context context;
    if (argc > 1) {
        int end;
        if (sscanf(argv[1], "%d%n", &context.port, &end) != 1 || argv[1][end]) {
            std::cerr << "server [<port>]\n";
            exit(1);
        }
    }
    evoke();
    openlog("cartesi-grpc", LOG_PID, LOG_USER);
    while (1) {
        switch (server_loop(context)) {
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
            default:
                dbg("Should not have broken away from server loop.");
                break;
        }
    }
    closelog();
    return 0;
}
