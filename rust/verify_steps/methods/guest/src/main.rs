#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
//#![no_std]  // std support is experimental

use risc0_zkvm::guest::env;
use std::ffi::{CStr};
risc0_zkvm::guest::entry!(main);
use std::os::raw::{c_char, c_ulong, c_ulonglong};
use risc0_zkvm::sha::{Impl, Sha256};

extern "C" {
    pub fn zkarch_replay_steps(steps: c_ulonglong, data: *const c_char, size: c_ulong) -> c_ulonglong; 
}

#[no_mangle]
pub extern "C" fn print_from_c(text: *const c_char) {
    let str = unsafe { CStr::from_ptr(text).to_string_lossy().into_owned() };
    println!("print_from_c: {}", str);
}

#[no_mangle]
pub extern "C" fn abort_from_c() {
    panic!("abort called from C");
}

fn main() {
    let steps : u64 = env::read();
    let page_count : u32 = env::read();
    let data_size : u32 = page_count * (4096 + 8);
    let mut data: Vec<u8> = vec![0; data_size as usize];
    for i in (0..data_size).step_by(1) {
        data[i as usize] = env::read();
    }
    let mctcle_end: u64;
    unsafe {
        mctcle_end = zkarch_replay_steps(steps, data.as_ptr() as *const c_char, page_count);
    }
    println!("guest: mctcle_end: {:?}", mctcle_end);
    let hash = Impl::hash_bytes(&data);
    println!("guest: hash after {:?}", hash);
    env::commit(hash);
}
