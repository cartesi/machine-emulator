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
