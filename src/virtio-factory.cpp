// Copyright 2023 Cartesi Pte. Ltd.
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

#include "virtio-factory.h"

namespace cartesi {

pma_entry make_virtio_pma_entry(uint64_t start, uint64_t length, const std::string &description,
    const pma_driver *driver, void *context) {
    pma_entry::flags f{
        true,                  // R
        true,                  // W
        false,                 // X
        false,                 // IR
        false,                 // IW
        PMA_ISTART_DID::VIRTIO // DID
    };
    // VirtIO devices are not verifiable yet,
    // therefore peek will always fail and cause an runtime error when updating the Merkle tree.
    return make_device_pma_entry(description, start, length, pma_peek_error, driver, context).set_flags(f);
}

} // namespace cartesi
