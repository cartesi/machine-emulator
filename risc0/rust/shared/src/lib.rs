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

use serde::{Deserialize, Serialize};

pub type MachineHash = [u8; 32];

/// Verified public information stored in the receipt.journal
#[derive(Debug, Serialize, Deserialize)]
pub struct Journal {
    pub root_hash_before: MachineHash,
    pub mcycle_count: u64,
    pub root_hash_after: MachineHash,
}

// todo: error types.

