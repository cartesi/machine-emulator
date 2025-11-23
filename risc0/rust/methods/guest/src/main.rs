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
use std::ffi::{CStr};
risc0_zkvm::guest::entry!(main);
use std::os::raw::{c_char, c_ulong, c_ulonglong};
use risc0_zkvm::sha::{Impl, Sha256};
use cartesi_risc0_shared::{ Journal, MachineHash};

extern "C" {
    /// this is the C++ compiled code that will be called to replay the logged step
    pub fn risc0_replay_steps(root_hash_before: *const c_char, raw_log_data: *const c_char, raw_log_size: c_ulonglong, mcycle_count: c_ulonglong, root_hash_after: *const c_char) -> c_ulonglong;
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
pub extern "C" fn zk_merkle_tree_hash(hash_tree_target: u64, data: *const c_char, size: c_ulong, hash: *mut c_char) {
    if hash_tree_target != 1 {
        panic!("zk_merkle_tree_hash: hash_tree_target must be 1");
    }
    if size > 32 {
        unsafe {
            let half_size = size / 2;
            let left_hash = [0u8; 32];
            zk_merkle_tree_hash(hash_tree_target, data, half_size, left_hash.as_ptr() as *mut c_char);
            let right_hash = [0u8; 32];
            zk_merkle_tree_hash(hash_tree_target, data.add(half_size as usize) as *const c_char, half_size, right_hash.as_ptr() as *mut c_char);
            let mut conctd = [0u8; 64];
            std::ptr::copy(left_hash.as_ptr(), conctd.as_mut_ptr(), 32);
            std::ptr::copy(right_hash.as_ptr(), conctd.as_mut_ptr().add(32), 32);
            let result_bytes = Impl::hash_bytes(&conctd).as_bytes();
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }
    } else{
        let result_bytes = Impl::hash_bytes(unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) }).as_bytes();
        unsafe {
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }       
    }
}

#[no_mangle]
pub extern "C" fn zk_concat_hash(hash_tree_target: u64, left: *const c_char, right: *const c_char, result: *mut c_char) {
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
    let mcycle_count: u64 = env::read();
    let root_hash_before : MachineHash = env::read();
    let root_hash_after : MachineHash = env::read();
    let raw_log_length : u64 = env::read();
    let mut raw_log: Vec<u8> = vec![0; raw_log_length as usize];
    for i in (0..raw_log_length).step_by(1) {
        raw_log[i as usize] = env::read();
    }
    unsafe {
        risc0_replay_steps(root_hash_before.as_ptr() as *const c_char, raw_log.as_ptr() as *const c_char, raw_log_length, mcycle_count, root_hash_after.as_ptr() as *const c_char);
    }
    // Collect the verified public information into the journal.
    let journal = Journal {
        root_hash_before: root_hash_before,
        mcycle_count: mcycle_count,
        root_hash_after: root_hash_after,
    };
    env::commit(&journal);
}
