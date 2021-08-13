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

#ifndef KECCAK_256_HASHER_H
#define KECCAK_256_HASHER_H

#include "cryptopp-keccak-256-hasher.h"

namespace cartesi {

/// \brief Class used to compute Keccak 256 hashes
using keccak_256_hasher = cryptopp_keccak_256_hasher;

} // namespace cartesi

#endif
