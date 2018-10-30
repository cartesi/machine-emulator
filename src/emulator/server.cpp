#include <iostream>
#include <memory>
#include <string>

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <wait.h>

#include <grpcpp/grpcpp.h>

#include "core.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using CartesiCore::Integer;
using CartesiCore::Machine;

#include <chrono>
#include <thread>
#include <mutex>

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
class MachineServiceImpl final : public Machine::Service {
    std::mutex barrier_;
    Server *server_;
    int value_;
    BreakReason reason_;

    void Break(BreakReason reason) {
        reason_ = reason;
        std::thread t(shutdown_server, server_);
        t.detach();
    }

    Status Inc(ServerContext *, const google::protobuf::Empty *, Integer *reply) override {
        std::lock_guard<std::mutex> lock(barrier_);
        reply->set_value(++value_);
        return Status::OK;
    }

    Status Print(ServerContext *, const google::protobuf::Empty *, Integer *reply) override {
        std::lock_guard<std::mutex> lock(barrier_);
        reply->set_value(value_);
        std::cerr << value_ << std::endl;
        return Status::OK;
    }

    Status Snapshot(ServerContext *, const google::protobuf::Empty *, Integer *reply) override {
        std::lock_guard<std::mutex> lock(barrier_);
        reply->set_value(value_);
        Break(BreakReason::snapshot);
        return Status::OK;
    }

    Status Rollback(ServerContext *, const google::protobuf::Empty *, Integer *reply) override {
        std::lock_guard<std::mutex> lock(barrier_);
        reply->set_value(value_);
        Break(BreakReason::rollback);
        return Status::OK;
    }

    Status Shutdown(ServerContext *, const google::protobuf::Empty *, google::protobuf::Empty *) override {
        std::lock_guard<std::mutex> lock(barrier_);
        Break(BreakReason::shutdown);
        return Status::OK;
    }

public:

    MachineServiceImpl(int value):
        server_(nullptr),
        value_(value),
        reason_(BreakReason::none) {
        ;
    }

    void set_server(Server *s) {
        server_ = s;
    }

    Server *server(void) {
        return server_;
    }

    BreakReason reason(void) const {
        return reason_;
    }

    int value(void) const {
        return value_;
    }

};

BreakReason server_loop(int *value, int *port) {
    std::string address("0.0.0.0:");
    address += std::to_string(*port);
    MachineServiceImpl service(*value);
    ServerBuilder builder;
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::NUM_CQS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
    builder.SetSyncServerOption(ServerBuilder::SyncServerOption::MAX_POLLERS, 1);
    builder.AddListeningPort(address, grpc::InsecureServerCredentials(), port);
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on port " << *port << std::endl;
    service.set_server(server.get());
    server->Wait();
    *value = service.value();
    return service.reason();
}

int main(int argc, char** argv) {
    int value = 0;
    int port = 0;
    bool forked = false;
    if (argc > 1) {
        int end;
        if (sscanf(argv[1], "%d%n", &port, &end) != 1 || argv[1][end]) {
            std::cerr << "server [<port>]\n";
            exit(1);
        }
    }
    while (1) {
        switch (server_loop(&value, &port)) {
            case BreakReason::snapshot: {
                std::cerr << "Break due to snapshot. Re-running.\n";
                pid_t childid = 0;
				// If we are a forked child, we have a parent waiting.
                // We want to take its place.
				// Wake parent up by signaling ourselves to stop.
				// Parent will wake us up and then exit.
				if (forked) {
					raise(SIGSTOP);
					// When we wake up, we took the parent's place, so we are not "forked" anymore
					forked = false;
				}
				// Now actually fork
				if ((childid = fork()) == 0) {
					// Child simply goes on with next loop iteration.
					forked = true;
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
						forked = false;
					}
				}
                break;
            }
            case BreakReason::rollback: {
                std::cerr << "Break due to rollback. Re-running.\n";
                if (forked) {
                    // Here, we are a child and forked.
                    // We simply exit so parent can take our place.
                    exit(0);
                } else {
                    std::cerr << "Rollback ignored.\n";
                }
                break;
            }
            case BreakReason::shutdown:
                std::cerr << "Exit due to shutdown request.\n";
				// If we are a forked child, we have a parent waiting.
                // We want to take its place before exiting.
				// Wake parent up by signaling ourselves to stop.
				// Parent will wake us up and then exit.
				if (forked) {
					raise(SIGSTOP);
					// When we wake up, we took the parent's place, so we are not "forked" anymore
					forked = false;
				}
                // Now exit
                exit(0);
                break;
            default:
                std::cerr << "Should not have broken away from server loop.\n";
                break;
        }
    }
    return 0;
}
