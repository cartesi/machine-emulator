// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

pragma solidity ^0.8.20;

/// @notice Image ID for the Cartesi RISC0 step verification guest program.
/// @dev Generated from the reproducible Docker build of the guest binary.
///      This value must match the Image ID produced by `make -C risc0 image-id`.
///      Update this constant whenever the guest program or RISC0 version changes.
///
///      Current value from RISC0 v3.0.5 with Docker reproducible build (r0.1.88.0).
library ImageID {
    bytes32 public constant CARTESI_STEP_VERIFIER_ID =
        bytes32(0xadddf33feec474903934d62f6b7e56d12029a63a4f1ded6117626d7033db5fb6);
}
