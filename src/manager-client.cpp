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
