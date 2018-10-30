/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>
#include <new>

#include <grpcpp/grpcpp.h>

#include "core.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using CartesiCore::Integer;
using CartesiCore::Machine;

class MachineClient {
public:
    MachineClient(std::shared_ptr<Channel> channel):
        stub_(Machine::NewStub(channel)) {}

    int Inc(void) {
        google::protobuf::Empty request;
        Integer response;
        ClientContext context;
        Status status = stub_->Inc(&context, request, &response);
        if (status.ok()) {
            return response.value();
        } else {
            std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
            return 0;
        }
    }

    int Print(void) {
        google::protobuf::Empty request;
        Integer response;
        ClientContext context;
        Status status = stub_->Print(&context, request, &response);
        if (status.ok()) {
            return response.value();
        } else {
            std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
            return 0;
        }
    }

    int Snapshot(void) {
        google::protobuf::Empty request;
        Integer response;
        ClientContext context;
        Status status = stub_->Snapshot(&context, request, &response);
        if (status.ok()) {
            return response.value();
        } else {
            std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
            return 0;
        }
    }

    int Rollback(void) {
        google::protobuf::Empty request;
        Integer response;
        ClientContext context;
        Status status = stub_->Rollback(&context, request, &response);
        if (status.ok()) {
            return response.value();
        } else {
            std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
            return 0;
        }
    }

    void Shutdown(void) {
        google::protobuf::Empty request, reply;
        ClientContext context;
        Status status = stub_->Shutdown(&context, request, &reply);
        // Act upon its status.
        if (!status.ok()) {
            std::cerr << status.error_code() << ": " << status.error_message()
                << std::endl;
        }
    }

private:
    std::unique_ptr<Machine::Stub> stub_;
};

int main(int argc, char** argv) {
    std::string address = "localhost:";
    if (argc < 1) {
        std::cerr << "client <port>\n";
        exit(1);
    }
    address += argv[1];
    MachineClient machine(
        grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "inc") {
            std::cerr << machine.Inc() << '\n';
        } else if (line == "print") {
            std::cerr << machine.Print() << '\n';
        } else if (line == "snapshot") {
            std::cerr << machine.Snapshot() << '\n';
            machine.~MachineClient();
            new (&machine) MachineClient(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        } else if (line == "rollback") {
            std::cerr << machine.Rollback() << '\n';
            machine.~MachineClient();
            new (&machine) MachineClient(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        } else if (line == "shutdown") {
            machine.Shutdown();
            machine.~MachineClient();
            new (&machine) MachineClient(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
        } else if (line == "help") {
            std::cerr << "inc print snapshot rollback shutdown\n";
        } else {
            std::cerr << "invalid command\n";
        }
    }
    return 0;
}
