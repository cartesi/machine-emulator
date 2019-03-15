#include <iostream>
#include <string>
#include <syslog.h>

#include <grpcpp/grpcpp.h>

#include "manager-client.h"
#include "manager-low.grpc.pb.h"
#include "manager-low.pb.h"
#include "cartesi-base.pb.h"

#define dbg(...) syslog(LOG_DEBUG, __VA_ARGS__)

namespace cartesi {

std::unique_ptr<CartesiManagerLow::MachineManagerLow::Stub> stub_;

manager_client::manager_client() {
    stub_ = CartesiManagerLow::MachineManagerLow::NewStub(grpc::CreateChannel("localhost:50051", 
            grpc::InsecureChannelCredentials()));
    dbg("Initiated manager server connection");
}

void manager_client::register_on_manager(std::string &session_id, std::string &address){
    CartesiManagerLow::AddressRequest request;
    CartesiCore::Void response;
    grpc::ClientContext context;

    request.set_address(address);
    request.set_session_id(session_id);
    grpc::Status status = stub_->CommunicateAddress(&context, request, &response);

    if (!status.ok()){
        std::cout << "Error trying to communicate reference to manager\n";
    }    
}

}
