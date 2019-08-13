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
#include <string>
#include <syslog.h>

#include <grpc++/grpc++.h>

#include "manager-client.h"
#include "manager-low.grpc.pb.h"
#include "manager-low.pb.h"
#include "cartesi-base.pb.h"

#define dbg(...) syslog(LOG_DEBUG, __VA_ARGS__)

namespace cartesi {

manager_client::manager_client() {}

void manager_client::register_on_manager(std::string &session_id, std::string &address, std::string &manager_address){
    CartesiManagerLow::AddressRequest request;
    CartesiCore::Void response;
    grpc::ClientContext context;

    request.set_address(address);
    request.set_session_id(session_id);
    
    dbg("Creating manager server connection stub");
    std::unique_ptr<CartesiManagerLow::MachineManagerLow::Stub> mml_stub = CartesiManagerLow::MachineManagerLow::NewStub(grpc::CreateChannel(manager_address, 
            grpc::InsecureChannelCredentials()));
    dbg("Initiated manager server connection stub");

    dbg("Communicating address to manager server");
    grpc::Status status = mml_stub->CommunicateAddress(&context, request, &response);
    dbg("Address communicated");

    if (!status.ok()){
        dbg("Error trying to communicate reference to manager\n");
    }    
}

}
