#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
//#![no_std]  // std support is experimental

use risc0_zkvm::guest::env;
use std::ffi::{CStr};
risc0_zkvm::guest::entry!(main);
use std::os::raw::{c_char, c_ulong, c_ulonglong};
use tiny_keccak::{Hasher, Keccak};

#[no_mangle]
pub extern "C" fn interop_print(text: *const c_char) {
    let str = unsafe { CStr::from_ptr(text).to_string_lossy().into_owned() };
    println!("print_from_c: {}", str);
}

#[no_mangle]
pub extern "C" fn interop_merkle_tree_hash(data: *const c_char, size: c_ulong, hash: *mut c_char) {
    let mut hasher = Keccak::v256();
    if size > 32 {
        unsafe {
            let half_size = size / 2;
            let left_hash = [0u8; 32];
            interop_merkle_tree_hash(data, half_size, left_hash.as_ptr() as *mut c_char);
            let right_hash = [0u8; 32];
            interop_merkle_tree_hash(data.add(half_size as usize) as *const c_char, half_size, right_hash.as_ptr() as *mut c_char);
            hasher.update(left_hash.as_ref());
            hasher.update(right_hash.as_ref());
            let mut result_bytes = [0u8; 32];
            hasher.finalize(&mut result_bytes);
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }
    } else{
        let mut hasher = Keccak::v256();
        hasher.update(unsafe { std::slice::from_raw_parts(data as *const u8, size as usize) });
        let mut result_bytes = [0u8; 32];
        hasher.finalize(&mut result_bytes);
        unsafe {
            std::ptr::copy(result_bytes.as_ptr(), hash as *mut u8, 32);
        }       
    }
}

#[no_mangle]
pub extern "C" fn interop_concat_hash(left: *const c_char, right: *const c_char, result: *mut c_char) {
    let mut hasher = Keccak::v256();
    hasher.update(unsafe { std::slice::from_raw_parts(left as *const u8, 32) });
    hasher.update(unsafe { std::slice::from_raw_parts(right as *const u8, 32) });
    let mut result_bytes = [0u8; 32];
    hasher.finalize(&mut result_bytes);
    unsafe {
        std::ptr::copy(result_bytes.as_ptr(), result as *mut u8, 32);
    }
}

#[no_mangle]
pub extern "C" fn interop_abort_with_msg(msg: *const c_char) {
    let str = unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() };
    panic!("abort_with_msg: {}", str);
}

extern "C" {
    pub fn zkarch_replay_steps(root_hash_before: *const c_char, raw_log_data: *const c_char, raw_log_size: c_ulonglong, mcycle_count: c_ulonglong, root_hash_after: *const c_char) -> c_ulonglong;
}


fn main() {
    let mcycle_count: u64 = env::read();
    let root_hash_before : [u8; 32] = env::read();
    let root_hash_after : [u8; 32] = env::read();
    let raw_log_length : u64 = env::read();
    println!("guest: mcycle_count: {:?}", mcycle_count);
    println!("guest: root_hash_before: {:?}", root_hash_before);
    println!("guest: root_hash_after: {:?}", root_hash_after);
    println!("guest: raw_log_length: {:?}", raw_log_length);
    let mut raw_log: Vec<u8> = vec![0; raw_log_length as usize];
    for i in (0..raw_log_length).step_by(1) {
        raw_log[i as usize] = env::read();
    }
    println!("guest: before zkarch_replay_steps");
    unsafe {
        zkarch_replay_steps(root_hash_before.as_ptr() as *const c_char, raw_log.as_ptr() as *const c_char, raw_log_length, mcycle_count, root_hash_after.as_ptr() as *const c_char);
    }
    println!("guest: after zkarch_replay_steps");
    let result : bool = true; // TODO: result -> root_hash_before, mcycle_count and root_hash_after
    println!("guest: commiting");
    env::commit(&result);
    println!("guest: committed");
}
