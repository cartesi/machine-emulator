#include <iostream>
#include <memory>
#include <string>
#include <new>

#include <grpcpp/grpcpp.h>

#include "core.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using CartesiCore::Void;
using CartesiCore::Machine;

class MachineClient {

    void reconnect(void) {
        stub_ = Machine::NewStub(grpc::CreateChannel(address_,
                grpc::InsecureChannelCredentials()));
    }

    void check_status(const Status &status) {
        if (!status.ok()) {
            std::cerr << "Error " << status.error_code() <<
                ": " << status.error_message() << std::endl;
        } else {
            std::cerr << "Ok\n";
        }
    }

public:

    MachineClient(std::string address): address_(address) {
        reconnect();
    }

    void Inc(void) {
        Void request, response;
        ClientContext context;
        return check_status(stub_->Inc(&context, request, &response));
    }

    void Print(void) {
        Void request, response;
        ClientContext context;
        return check_status(stub_->Print(&context, request, &response));
    }

    void Snapshot(void) {
        Void request, response;
        ClientContext context;
        auto status = stub_->Snapshot(&context, request, &response);
        reconnect();
        return check_status(status);
    }

    void Rollback(void) {
        Void request, response;
        ClientContext context;
        auto status = stub_->Rollback(&context, request, &response);
        reconnect();
        return check_status(status);
    }

    void Shutdown(void) {
        Void request, response;
        ClientContext context;
        return check_status(stub_->Shutdown(&context, request, &response));
    }

private:
    std::string address_;
    std::unique_ptr<Machine::Stub> stub_;
};

int main(int argc, char** argv) {
    std::string address;
    if (argc != 2) {
        std::cerr << argv[0] << " <ip>:<port>\n";
        std::cerr << argv[0] << " unix:<path>\n";
        exit(0);
    }
    MachineClient machine(argv[1]);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "inc") {
            machine.Inc();
        } else if (line == "print") {
            machine.Print();
        } else if (line == "snapshot") {
            machine.Snapshot();
        } else if (line == "rollback") {
            machine.Rollback();
        } else if (line == "shutdown") {
            machine.Shutdown();
            break;
        } else if (line == "help") {
            std::cerr << "inc print snapshot rollback shutdown\n";
        } else {
            std::cerr << "invalid command '" << line << "'\n";
        }
    }
    return 0;
}
