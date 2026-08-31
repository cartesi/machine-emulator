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

#![no_main]
use risc0_zkvm::guest::env;
use std::ffi::CStr;
use std::io::Read;
risc0_zkvm::guest::entry!(main);
use risc0_zkvm::sha::{Impl, Sha256};
use std::os::raw::{c_char, c_ulong, c_ulonglong};
type MachineHash = [u8; 32];

extern "C" {
    /// C++ code that replays `mcycle_count` cycles over the logged witness and returns the
    /// replay-derived roots via output params. The log buffer is mutable: the replay writes
    /// page data and re-zeroes the per-page scratch hash slots in place.
    pub fn risc0_replay_steps(
        raw_log_data: *mut u8,
        raw_log_size: c_ulonglong,
        mcycle_count: c_ulonglong,
        out_root_hash_before: *mut u8,
        out_root_hash_after: *mut u8,
    );
}

#[no_mangle]
pub extern "C" fn zk_abort_with_msg(msg: *const c_char) {
    let str = unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() };
    panic!("abort_with_msg: {}", str);
}

#[no_mangle]
pub extern "C" fn zk_putchar(c: u8) {
    print!("{}", c as char);
}

#[no_mangle]
pub extern "C" fn zk_merkle_tree_hash(
    hash_tree_target: u64,
    data: *const c_char,
    size: c_ulong,
    hash: *mut c_char,
) {
    if hash_tree_target != 1 {
        panic!("zk_merkle_tree_hash: hash_tree_target must be 1");
    }
    if size > 32 {
        // The halving recursion assumes power-of-two sizes (as every caller passes); an odd
        // size would silently drop its last byte.
        if !(size as u64).is_power_of_two() {
            panic!("zk_merkle_tree_hash: size must be a power of two");
        }
        unsafe {
            let half_size = size / 2;
            let mut left_hash = [0u8; 32];
            zk_merkle_tree_hash(
                hash_tree_target,
                data,
                half_size,
                left_hash.as_mut_ptr() as *mut c_char,
            );
            let mut right_hash = [0u8; 32];
            zk_merkle_tree_hash(
                hash_tree_target,
                data.add(half_size as usize) as *const c_char,
                half_size,
                right_hash.as_mut_ptr() as *mut c_char,
            );
            let mut conctd = [0u8; 64];
            std::ptr::copy(left_hash.as_ptr(), conctd.as_mut_ptr(), 32);
            std::ptr::copy(right_hash.as_ptr(), conctd.as_mut_ptr().add(32), 32);
            let result_bytes = Impl::hash_bytes(&conctd).as_bytes();
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }
    } else {
        let result_bytes = Impl::hash_bytes(unsafe {
            std::slice::from_raw_parts(data as *const u8, size as usize)
        })
        .as_bytes();
        unsafe {
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }
    }
}

// The guest exports only the hash primitives (zk_merkle_tree_hash, zk_concat_hash).
// Composite hashes such as the padded Merkle hash are built on these in freestanding
// C++ (replay-step-state-access.hpp).

#[no_mangle]
pub extern "C" fn zk_concat_hash(
    hash_tree_target: u64,
    left: *const c_char,
    right: *const c_char,
    result: *mut c_char,
) {
    if hash_tree_target != 1 {
        panic!("zk_concat_hash: hash_tree_target must be 1");
    }
    let mut conctd = [0u8; 64];
    unsafe {
        std::ptr::copy(left as *const u8, conctd.as_mut_ptr(), 32);
        std::ptr::copy(right as *const u8, conctd.as_mut_ptr().add(32), 32);
    }
    let result_bytes = Impl::hash_bytes(&conctd).as_bytes();
    unsafe {
        std::ptr::copy(result_bytes.as_ptr(), result as *mut u8, 32);
    }
}

fn main() {
    // Input: an 8-byte little-endian requested cycle count, then the step log bytes.
    let mut input = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input).unwrap();
    assert!(
        input.len() >= 8,
        "input shorter than the cycle count prefix"
    );
    let mcycle_count = u64::from_le_bytes(input[0..8].try_into().unwrap());
    let mut log_data = input.split_off(8);
    // step_log::decode reinterprets the buffer as structs with uint64 fields; the wire
    // layout keeps every field 8-aligned relative to the buffer start.
    assert!(
        log_data.as_ptr() as usize % 8 == 0,
        "log buffer is not 8-byte aligned"
    );

    let mut root_hash_before: MachineHash = [0; 32];
    let mut root_hash_after: MachineHash = [0; 32];

    unsafe {
        risc0_replay_steps(
            log_data.as_mut_ptr(),
            log_data.len() as c_ulonglong,
            mcycle_count,
            root_hash_before.as_mut_ptr(),
            root_hash_after.as_mut_ptr(),
        );
    }

    // ABI-encode journal as abi.encode(bytes32, uint64, bytes32) — 96 bytes
    let mut journal_bytes = Vec::with_capacity(96);
    journal_bytes.extend_from_slice(&root_hash_before);
    journal_bytes.extend_from_slice(&[0u8; 24]);
    journal_bytes.extend_from_slice(&mcycle_count.to_be_bytes());
    journal_bytes.extend_from_slice(&root_hash_after);
    env::commit_slice(&journal_bytes);
}
