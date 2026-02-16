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
ziskos::entrypoint!(main);

extern crate alloc;

use alloc::vec::Vec;
use ziskos::zisklib::sha256f_compress;
use ziskos::{read_input, set_output};
use core::ffi::c_char;

// SHA256 using ZisK's accelerated sha256f_compress precompile
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_small(data: &[u8]) -> [u8; 32] {
    debug_assert!(data.len() <= 55, "sha256_small: data too large, use sha256_64");
    let mut state = SHA256_IV;
    let mut block = [0u8; 64];
    block[..data.len()].copy_from_slice(data);
    block[data.len()] = 0x80;
    block[56..64].copy_from_slice(&((data.len() as u64) * 8).to_be_bytes());

    sha256f_compress(&mut state, &[block]);
    sha256_state_to_bytes(&state)
}

fn sha256_64(data: &[u8; 64]) -> [u8; 32] {
    let mut state = SHA256_IV;
    sha256f_compress(&mut state, &[*data]);
    let mut pad_block = [0u8; 64];
    pad_block[0] = 0x80;
    pad_block[56..64].copy_from_slice(&512u64.to_be_bytes());
    sha256f_compress(&mut state, &[pad_block]);

    sha256_state_to_bytes(&state)
}

fn sha256_state_to_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    result
}

extern "C" {
    pub fn zisk_replay_steps(
        step_log_image: *mut u8,
        step_log_image_size: u64,
        out_root_hash_before: *mut u8,
        out_mcycle_count: *mut u64,
        out_root_hash_after: *mut u8,
    );
}

#[no_mangle]
pub extern "C" fn zk_abort_with_msg(_msg: *const c_char) -> ! {
    panic!("C++ abort");
}

#[no_mangle]
pub extern "C" fn zk_putchar(_c: u8) {
    // no-op in zkVM
}

#[no_mangle]
pub extern "C" fn zk_merkle_tree_hash(
    hash_function: u64,
    data: *const u8,
    size: usize,
    hash: *mut u8,
) {
    if hash_function != 1 {
        panic!("only SHA256 supported");
    }

    unsafe {
        let result = if size > 32 {
            let half_size = size / 2;
            let mut left_hash = [0u8; 32];
            let mut right_hash = [0u8; 32];
            zk_merkle_tree_hash(hash_function, data, half_size, left_hash.as_mut_ptr());
            zk_merkle_tree_hash(
                hash_function,
                data.add(half_size),
                half_size,
                right_hash.as_mut_ptr(),
            );

            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left_hash);
            combined[32..].copy_from_slice(&right_hash);
            sha256_64(&combined)
        } else {
            let slice = core::slice::from_raw_parts(data, size);
            sha256_small(slice)
        };

        core::ptr::copy_nonoverlapping(result.as_ptr(), hash, 32);
    }
}

#[no_mangle]
pub extern "C" fn zk_concat_hash(
    hash_function: u64,
    left: *const u8,
    right: *const u8,
    out: *mut u8,
) {
    if hash_function != 1 {
        panic!("only SHA256 supported");
    }

    unsafe {
        let mut combined = [0u8; 64];
        core::ptr::copy_nonoverlapping(left, combined.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(right, combined.as_mut_ptr().add(32), 32);

        let result = sha256_64(&combined);
        core::ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    }
}

// Memory functions must be in Rust — compiler_builtins weak stubs infinite-loop.
// Byte loops intentional — copy_nonoverlapping can recurse back to memcpy.

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        *s.add(i) = byte;
        i += 1;
    }
    s
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

#[used]
static FORCE_MEMCPY: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 = memcpy;
#[used]
static FORCE_MEMSET: unsafe extern "C" fn(*mut u8, i32, usize) -> *mut u8 = memset;
#[used]
static FORCE_MEMMOVE: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 = memmove;

fn main() {
    let mut input: Vec<u8> = read_input();
    let mut root_hash_before = [0u8; 32];
    let mut mcycle_count: u64 = 0;
    let mut root_hash_after = [0u8; 32];

    unsafe {
        zisk_replay_steps(
            input.as_mut_ptr(),
            input.len() as u64,
            root_hash_before.as_mut_ptr(),
            &mut mcycle_count,
            root_hash_after.as_mut_ptr(),
        );
    }

    for i in 0..8 {
        let val = u32::from_be_bytes(root_hash_before[i * 4..i * 4 + 4].try_into().unwrap());
        set_output(i, val);
    }
    set_output(8, (mcycle_count >> 32) as u32);
    set_output(9, mcycle_count as u32);
    for i in 0..8 {
        let val = u32::from_be_bytes(root_hash_after[i * 4..i * 4 + 4].try_into().unwrap());
        set_output(10 + i, val);
    }
}
