#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
//#![no_std]  // std support is experimental

use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
use std::ptr;
use std::os::raw::{c_char, c_ulonglong};

#[repr(C)]
pub struct PageInfo {
    pub address: c_ulonglong,
    pub data: [c_char; 4096],
    pub next: *mut PageInfo,
}

extern "C" {
    pub fn zkarch_replay_steps(steps: c_ulonglong, pages: *mut PageInfo) -> c_ulonglong;
}

fn main() {
    // linked list of pages
    let mut _head : *mut PageInfo = ptr::null_mut();
    let mut _current : *mut PageInfo = ptr::null_mut();
    // read page count
    let _page_count : u64 = env::read();
    // stupid way of reading pages. Will improve later.
    for _ in 0.._page_count {
        let _asdress : u64 = env::read();
        let mut _page = PageInfo {
            address: _asdress,
            data: [0; 4096],
            next: ptr::null_mut(),
        };
        // even stupider way of reading page data. Will improve later.  
        for _i in (0..4096).step_by(32) {
            env::read_slice(&mut _page.data[_i..(_i + 32)]);
        }
        if _head.is_null() {
            _head = Box::into_raw(Box::new(_page));
            _current = _head;
        } else {
            let _new_page = Box::into_raw(Box::new(_page));
            unsafe {
                (*_current).next = _new_page;
                _current = _new_page;
            }
        }
    }

    let mctcle_end: u64;
    unsafe {
        mctcle_end = zkarch_replay_steps(1, _head);
    }
    
    env::commit(&_page_count);
}
