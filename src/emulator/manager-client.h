#ifndef MANAGER_CLIENT_H
#define MANAGER_CLIENT_H

#include <string>

namespace cartesi {

class manager_client {
public:
    //Constructor
    manager_client();

    /// \brief Register the address to connect to an emulator grpc server on the core manager
    /// \param session_id Session id of the emulator grpc server
    /// \param address Address to connect to the emulator grpc server
    /// \param manager_address Address of manager to register on
    void register_on_manager(std::string &session_id, std::string &address, std::string &manager_address);

};

}

#endif
