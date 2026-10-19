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

use cartesi_risc0::REPLAY_STEP_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};

fn framed_input(log_size: u64, log: &[u8]) -> Vec<u8> {
    let mut input = 1u64.to_le_bytes().to_vec();
    input.extend_from_slice(&log_size.to_le_bytes());
    input.extend_from_slice(log);
    input
}

#[test]
fn test_guest_rejects_invalid_input_framing() {
    let cases = [
        (vec![0; 7], "input shorter than the cycle count prefix"),
        (vec![0; 15], "input shorter than the step log length prefix"),
        (
            framed_input(u64::from(u32::MAX) + 1, &[]),
            "step log size exceeds guest address space",
        ),
        (
            framed_input(u64::from(u32::MAX), &[]),
            "step log size exceeds guest address space",
        ),
        (
            framed_input(8, &[0; 7]),
            "input shorter than the declared step log length",
        ),
        (framed_input(0, &[]), "step log shorter than header"),
    ];
    for (input, expected) in cases {
        let env = ExecutorEnv::builder().write_slice(&input).build().unwrap();
        let err = default_executor()
            .execute(env, REPLAY_STEP_ELF)
            .expect_err("guest accepted an invalid input frame");
        let message = format!("{err:?}");
        assert!(message.contains(expected), "{message:?} lacks {expected:?}");
    }
}
