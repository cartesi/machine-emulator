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
#include <memory>
#include <string>
#include <new>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <grpc++/grpc++.h>
#include "cartesi-machine.grpc.pb.h"
#pragma GCC diagnostic pop

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using CartesiMachine::Void;
using CartesiMachine::Machine;
using CartesiMachine::MachineRequest;

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

    void Machine(void) {
        MachineRequest request;
        Void response;
        ClientContext context;
        return check_status(stub_->Machine(&context, request, &response));
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
        if (line == "snapshot") {
            machine.Snapshot();
        } else if (line == "rollback") {
            machine.Rollback();
        } else if (line == "shutdown") {
            machine.Shutdown();
            break;
        } else if (line == "machine") {
            machine.Machine();
        } else if (line == "help") {
            std::cerr << "inc print snapshot rollback shutdown\n";
        } else {
            std::cerr << "invalid command '" << line << "'\n";
        }
    }
    return 0;
}
